//! SVR4 Boot File System (BFS) — the simple, flat, contiguous filesystem used
//! for the `/stand` slice (kernel + boot loader).
//!
//! Rust port of the format/read path in `host_tools/fs/bfs.py`. BFS is trivial
//! compared to UFS: a 512-byte superblock, a table of fixed 64-byte inode
//! records, then a data area holding the root directory (flat 16-byte
//! name→inode entries) followed by each file's data laid out contiguously and
//! sector-aligned. There are no subdirectories, indirect blocks, or fragments.
//!
//! Only the operations the image build needs are ported: [`format`] (lay out a
//! slice with a set of root files, byte-for-byte like the Python writer) and a
//! small read side (`detect`, `list_root`, `read_file`) for verification and
//! for the disk inspector. The in-place/relocating mutation helpers from the
//! Python version are intentionally omitted — `/stand` is rebuilt wholesale.

use svr4_fs_core::codec::{put_i32, put_u16, put_u32, u16, u32};
use svr4_fs_core::consts::SECTOR_SIZE;

pub mod detector;

pub use detector::BfsDetector;

pub const BFS_MAGIC: u32 = 0x1BAD_FACE;
pub const BFS_ROOT_INODE: u16 = 2;
pub const BFS_SUPER_SIZE: usize = 512;
pub const BFS_DIRENT_SIZE: usize = 64;
pub const BFS_VATTR_SIZE: usize = 48;
pub const BFS_LDIR_SIZE: usize = 16;

// Inode (dirent) record field offsets.
const BFS_DIRENT_INO_OFFSET: usize = 0;
const BFS_DIRENT_SBLOCK_OFFSET: usize = 4;
const BFS_DIRENT_EBLOCK_OFFSET: usize = 8;
const BFS_DIRENT_EOFFSET_OFFSET: usize = 12;
const BFS_DIRENT_VATTR_OFFSET: usize = 16;

// vattr field offsets (within the dirent's vattr region).
const BFS_VATTR_TYPE_OFFSET: usize = 0;
const BFS_VATTR_MODE_OFFSET: usize = 4;
const BFS_VATTR_UID_OFFSET: usize = 8;
const BFS_VATTR_GID_OFFSET: usize = 12;
const BFS_VATTR_NLINK_OFFSET: usize = 16;
const BFS_VATTR_ATIME_OFFSET: usize = 20;
const BFS_VATTR_MTIME_OFFSET: usize = 24;
const BFS_VATTR_CTIME_OFFSET: usize = 28;

// vnode types as stored in a BFS vattr.
pub const BFS_VREG: u32 = 1;
pub const BFS_VDIR: u32 = 2;

const BFS_MAX_NAME: usize = 14;

/// A detected BFS filesystem: where it lives plus its parsed superblock.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Bfs {
    /// Byte offset of the BFS superblock within the backing image.
    pub start_offset: u64,
    /// First byte of the data area (`fs_start`-relative).
    pub data_start: u64,
    /// Last valid byte of the filesystem (`fs_start`-relative).
    pub data_end: u64,
}

/// One root-directory entry, resolved to its inode extent.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct BfsEntry {
    pub name: String,
    pub inode: u16,
    pub size: u64,
}

fn round_up(value: usize, alignment: usize) -> usize {
    value.div_ceil(alignment) * alignment
}

fn put_vattr(buf: &mut [u8], at: usize, file_type: u32, mode: u32, nlink: u32, timestamp: i32) {
    put_u32(buf, at + BFS_VATTR_TYPE_OFFSET, file_type);
    put_u32(buf, at + BFS_VATTR_MODE_OFFSET, mode);
    put_u32(buf, at + BFS_VATTR_UID_OFFSET, 0);
    put_u32(buf, at + BFS_VATTR_GID_OFFSET, 0);
    put_u32(buf, at + BFS_VATTR_NLINK_OFFSET, nlink);
    put_i32(buf, at + BFS_VATTR_ATIME_OFFSET, timestamp);
    put_i32(buf, at + BFS_VATTR_MTIME_OFFSET, timestamp);
    put_i32(buf, at + BFS_VATTR_CTIME_OFFSET, timestamp);
}

#[allow(clippy::too_many_arguments)]
fn put_dirent(
    buf: &mut [u8],
    at: usize,
    inode_number: u16,
    start_block: u32,
    end_block: u32,
    end_offset: u32,
    file_type: u32,
    mode: u32,
    nlink: u32,
    timestamp: i32,
) {
    put_u16(buf, at + BFS_DIRENT_INO_OFFSET, inode_number);
    put_u32(buf, at + BFS_DIRENT_SBLOCK_OFFSET, start_block);
    put_u32(buf, at + BFS_DIRENT_EBLOCK_OFFSET, end_block);
    put_u32(buf, at + BFS_DIRENT_EOFFSET_OFFSET, end_offset);
    put_vattr(buf, at + BFS_DIRENT_VATTR_OFFSET, file_type, mode, nlink, timestamp);
}

/// Lay out a BFS filesystem of `size_bytes` containing `files` (root-level
/// `(name, data)` pairs) and write it into `out` at byte offset `fs_start`.
/// Byte-for-byte identical to `host_tools.fs.bfs.build_bfs_filesystem_image`.
///
/// `dirent_slots`, when given, reserves at least that many inode-table slots
/// (the Python default is `max(16, files + 1)`).
pub fn format(
    out: &mut [u8],
    fs_start: u64,
    size_bytes: usize,
    files: &[(&str, &[u8])],
    dirent_slots: Option<usize>,
    timestamp: i32,
) -> Result<(), String> {
    if size_bytes < BFS_SUPER_SIZE + SECTOR_SIZE {
        return Err("error: bfs slice is too small to hold a filesystem image".into());
    }
    let mut seen: Vec<&str> = Vec::new();
    for (name, _) in files {
        if name.is_empty() || name.contains('/') {
            return Err(format!("error: bfs file name {name:?} must be a non-empty root entry name"));
        }
        if name.len() > BFS_MAX_NAME {
            return Err(format!("error: bfs file name {name:?} exceeds the 14-character BFS limit"));
        }
        if !name.is_ascii() {
            return Err(format!("error: bfs file name {name:?} must be ASCII"));
        }
        if seen.contains(name) {
            return Err(format!("error: duplicate bfs file name {name:?}"));
        }
        seen.push(name);
    }

    let required_slots = files.len() + 1;
    let total_slots = required_slots.max(dirent_slots.unwrap_or_else(|| 16.max(required_slots)));
    let data_start = round_up(BFS_SUPER_SIZE + total_slots * BFS_DIRENT_SIZE, SECTOR_SIZE);
    let root_dir_bytes = files.len() * BFS_LDIR_SIZE;
    let root_dir_alloc = SECTOR_SIZE.max(round_up(root_dir_bytes.max(1), SECTOR_SIZE));
    if data_start + root_dir_alloc > size_bytes {
        return Err("error: bfs slice is too small for the requested dirent table and root directory".into());
    }

    // Lay out file extents.
    struct Layout<'a> {
        inode: u16,
        name: &'a str,
        data: &'a [u8],
        start: usize,
        end_block: u32,
        end_offset: u32,
    }
    let mut layouts: Vec<Layout> = Vec::with_capacity(files.len());
    let mut current = data_start + root_dir_alloc;
    for (index, (name, data)) in files.iter().enumerate() {
        let inode = BFS_ROOT_INODE + (index as u16) + 1;
        if data.is_empty() {
            layouts.push(Layout { inode, name, data, start: 0, end_block: 0, end_offset: 0 });
            continue;
        }
        let allocation = round_up(data.len(), SECTOR_SIZE);
        if current + allocation > size_bytes {
            return Err(format!("error: bfs slice is too small for file {name:?}"));
        }
        let end_block = ((current + allocation) / SECTOR_SIZE - 1) as u32;
        let end_offset = (current + data.len() - 1) as u32;
        layouts.push(Layout { inode, name, data, start: current, end_block, end_offset });
        current += allocation;
    }

    let base = fs_start as usize;
    let image = &mut out[base..base + size_bytes];
    // Start from a clean slice, exactly like the Python writer's fresh buffer.
    image.fill(0);

    // Superblock.
    put_u32(image, 0, BFS_MAGIC);
    put_u32(image, 4, data_start as u32);
    put_u32(image, 8, (size_bytes - 1) as u32);

    // Root inode (slot 0).
    let root_start_block = (data_start / SECTOR_SIZE) as u32;
    let root_end_block = ((data_start + root_dir_alloc) / SECTOR_SIZE - 1) as u32;
    let root_end_offset = if root_dir_bytes != 0 {
        (data_start + root_dir_bytes - 1) as u32
    } else {
        (data_start - 1) as u32
    };
    put_dirent(
        image,
        BFS_SUPER_SIZE,
        BFS_ROOT_INODE,
        root_start_block,
        root_end_block,
        root_end_offset,
        BFS_VDIR,
        0o755,
        2,
        timestamp,
    );

    // File inodes + data + root directory entries.
    let mut directory_offset = data_start;
    for (index, layout) in layouts.iter().enumerate() {
        let inode_offset = BFS_SUPER_SIZE + (index + 1) * BFS_DIRENT_SIZE;
        if layout.data.is_empty() {
            put_dirent(image, inode_offset, layout.inode, 0, 0, 0, BFS_VREG, 0o644, 1, timestamp);
        } else {
            let start_block = (layout.start / SECTOR_SIZE) as u32;
            image[layout.start..layout.start + layout.data.len()].copy_from_slice(layout.data);
            put_dirent(
                image,
                inode_offset,
                layout.inode,
                start_block,
                layout.end_block,
                layout.end_offset,
                BFS_VREG,
                0o644,
                1,
                timestamp,
            );
        }
        put_u16(image, directory_offset, layout.inode);
        let name_bytes = layout.name.as_bytes();
        image[directory_offset + 2..directory_offset + 2 + name_bytes.len()].copy_from_slice(name_bytes);
        for b in &mut image[directory_offset + 2 + name_bytes.len()..directory_offset + BFS_LDIR_SIZE] {
            *b = 0;
        }
        directory_offset += BFS_LDIR_SIZE;
    }

    Ok(())
}

/// Detect a BFS filesystem whose superblock is at byte offset `fs_start`.
pub fn detect_at_start(image: &[u8], fs_start: u64) -> Option<Bfs> {
    let base = fs_start as usize;
    if base + BFS_SUPER_SIZE > image.len() {
        return None;
    }
    if u32(image, base) != BFS_MAGIC {
        return None;
    }
    let data_start = u32(image, base + 4) as u64;
    let data_end = u32(image, base + 8) as u64;
    if data_start < BFS_SUPER_SIZE as u64 || data_end < data_start {
        return None;
    }
    Some(Bfs { start_offset: fs_start, data_start, data_end })
}

/// Read the inode (dirent) record for `inode_number`, returning its
/// `(start_block, end_block, end_offset, file_type)`.
fn read_inode(image: &[u8], bfs: &Bfs, inode_number: u16) -> Option<(u32, u32, u32, u32)> {
    if inode_number < BFS_ROOT_INODE {
        return None;
    }
    let slot = (inode_number - BFS_ROOT_INODE) as usize;
    let at = bfs.start_offset as usize + BFS_SUPER_SIZE + slot * BFS_DIRENT_SIZE;
    if at + BFS_DIRENT_SIZE > image.len() {
        return None;
    }
    let stored_ino = u16(image, at + BFS_DIRENT_INO_OFFSET);
    if stored_ino != inode_number {
        return None;
    }
    let sblock = u32(image, at + BFS_DIRENT_SBLOCK_OFFSET);
    let eblock = u32(image, at + BFS_DIRENT_EBLOCK_OFFSET);
    let eoffset = u32(image, at + BFS_DIRENT_EOFFSET_OFFSET);
    let file_type = u32(image, at + BFS_DIRENT_VATTR_OFFSET + BFS_VATTR_TYPE_OFFSET);
    Some((sblock, eblock, eoffset, file_type))
}

/// Size in bytes of a file inode (from its contiguous extent). A `start_block`
/// of 0 is the "no extent" sentinel used for empty files (real data never lives
/// in sector 0, which holds the superblock).
fn inode_size(sblock: u32, eoffset: u32) -> u64 {
    if sblock == 0 {
        return 0;
    }
    let start = sblock as u64 * SECTOR_SIZE as u64;
    if eoffset as u64 >= start {
        eoffset as u64 - start + 1
    } else {
        0
    }
}

/// List the root directory entries.
pub fn list_root(image: &[u8], bfs: &Bfs) -> Vec<BfsEntry> {
    let mut entries = Vec::new();
    let Some((sblock, _eblock, eoffset, _type)) = read_inode(image, bfs, BFS_ROOT_INODE) else {
        return entries;
    };
    let dir_start = bfs.start_offset as usize + sblock as usize * SECTOR_SIZE;
    let dir_len = inode_size(sblock, eoffset) as usize;
    let mut offset = 0;
    while offset + BFS_LDIR_SIZE <= dir_len {
        let at = dir_start + offset;
        if at + BFS_LDIR_SIZE > image.len() {
            break;
        }
        let ino = u16(image, at);
        if ino != 0 {
            let raw = &image[at + 2..at + BFS_LDIR_SIZE];
            let name_len = raw.iter().position(|&b| b == 0).unwrap_or(raw.len());
            let name = String::from_utf8_lossy(&raw[..name_len]).into_owned();
            let size = read_inode(image, bfs, ino).map(|(s, _, e, _)| inode_size(s, e)).unwrap_or(0);
            entries.push(BfsEntry { name, inode: ino, size });
        }
        offset += BFS_LDIR_SIZE;
    }
    entries
}

/// Read a root file's bytes by name.
pub fn read_file(image: &[u8], bfs: &Bfs, name: &str) -> Option<Vec<u8>> {
    let entry = list_root(image, bfs).into_iter().find(|e| e.name == name)?;
    let (sblock, _eblock, eoffset, _type) = read_inode(image, bfs, entry.inode)?;
    let size = inode_size(sblock, eoffset) as usize;
    let start = bfs.start_offset as usize + sblock as usize * SECTOR_SIZE;
    if start + size > image.len() {
        return None;
    }
    Some(image[start..start + size].to_vec())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn format_then_read_round_trips() {
        let size = 64 * 1024;
        let mut image = vec![0u8; size + 4096];
        let fs_start = 4096u64;
        let unix = b"fake kernel image".repeat(40);
        let files: Vec<(&str, &[u8])> = vec![("unix", unix.as_slice()), ("boot", b"BOOT"), ("empty", b"")];
        format(&mut image, fs_start, size, &files, None, 0).unwrap();

        let bfs = detect_at_start(&image, fs_start).expect("detect");
        let mut names: Vec<String> = list_root(&image, &bfs).into_iter().map(|e| e.name).collect();
        names.sort();
        assert_eq!(names, vec!["boot", "empty", "unix"]);
        assert_eq!(read_file(&image, &bfs, "unix").unwrap(), unix);
        assert_eq!(read_file(&image, &bfs, "boot").unwrap(), b"BOOT");
        assert_eq!(read_file(&image, &bfs, "empty").unwrap(), Vec::<u8>::new());
        // Nothing was written before the slice start.
        assert!(image[..fs_start as usize].iter().all(|&b| b == 0));
    }

    #[test]
    fn detect_rejects_non_bfs() {
        let image = vec![0u8; 8192];
        assert!(detect_at_start(&image, 0).is_none());
    }
}
