//! High-level UFS read operations: file reads, directory listing, and path
//! resolution. Port of the read-side functions in `host_tools/fs/ufs.py`
//! (`read_ufs_data_range`, `read_ufs_inode_bytes`, `read_ufs_inode_range`,
//! `read_ufs_file`, `iter_ufs_directory_entries`, `lookup_ufs_directory_entry`,
//! `resolve_ufs_path`, `list_ufs_root`).

use svr4_fs_core::consts::{
    UFS_DIRBLKSIZ, UFS_DIRENT_HEADER_SIZE, UFS_DIRENT_NAME_OFFSET, UFS_ROOT_INODE,
};

use crate::dir::{decode_directory_header, iter_directory_records, DirEntry};
use crate::inode::{inode_data_blocks, read_inode, Inode};
use crate::superblock::Ufs;

/// One entry in a directory listing: name, inode number, and the child's size
/// if its inode could be read. Mirrors the dicts from `iter_ufs_directory_entries`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DirListEntry {
    pub name: String,
    pub inode: u32,
    pub size: Option<u64>,
}

/// Read a byte range out of an ordered list of data blocks. Port of
/// `read_ufs_data_range`.
pub fn read_data_range(
    image: &[u8],
    ufs: &Ufs,
    data_blocks: &[u32],
    offset: usize,
    size: usize,
) -> Vec<u8> {
    if size == 0 {
        return Vec::new();
    }
    let block_size = ufs.sb.bsize as usize;
    let end_offset = offset + size;
    let start_block = offset / block_size;
    let end_block = data_blocks.len().min(end_offset.div_ceil(block_size));
    let mut data = Vec::with_capacity(size);
    for (block_index, &fs_block) in data_blocks
        .iter()
        .enumerate()
        .take(end_block)
        .skip(start_block)
    {
        let logical_start = block_index * block_size;
        let block_inner_start = offset.saturating_sub(logical_start);
        let block_inner_end = block_size.min(end_offset - logical_start);
        if block_inner_start >= block_inner_end {
            continue;
        }
        let block_offset = ufs.sb.data_block_offset(ufs.start_offset, fs_block as i64) as usize;
        data.extend_from_slice(
            &image[block_offset + block_inner_start..block_offset + block_inner_end],
        );
    }
    data
}

/// Read an inode's entire contents (`size` bytes). Port of `read_ufs_inode_bytes`.
pub fn read_inode_bytes(image: &[u8], ufs: &Ufs, inode: &Inode) -> Vec<u8> {
    let inode_size = inode.size as usize;
    if inode_size == 0 {
        return Vec::new();
    }
    let blocks = inode_data_blocks(image, ufs, inode);
    read_data_range(image, ufs, &blocks, 0, inode_size)
}

/// Read a clamped byte range from an inode. Port of `read_ufs_inode_range`.
pub fn read_inode_range(
    image: &[u8],
    ufs: &Ufs,
    inode: &Inode,
    offset: usize,
    size: usize,
) -> Vec<u8> {
    let inode_size = inode.size as usize;
    if size == 0 || offset >= inode_size {
        return Vec::new();
    }
    let clamped_size = size.min(inode_size - offset);
    if clamped_size == 0 {
        return Vec::new();
    }
    let blocks = inode_data_blocks(image, ufs, inode);
    read_data_range(image, ufs, &blocks, offset, clamped_size)
}

/// All directory records in an inode, with offsets relative to the directory
/// start. Port of `iter_ufs_inode_directory_records`.
pub fn iter_inode_directory_records(image: &[u8], ufs: &Ufs, inode: &Inode) -> Vec<DirEntry> {
    let size = inode.size as usize;
    let directory_bytes = read_inode_bytes(image, ufs, inode);
    let mut records = Vec::new();
    let mut block_offset = 0;
    while block_offset < size {
        let block_span = UFS_DIRBLKSIZ.min(size - block_offset);
        let block_bytes = &directory_bytes[block_offset..(block_offset + block_span).min(directory_bytes.len())];
        for mut record in iter_directory_records(block_bytes, block_span) {
            record.offset += block_offset;
            records.push(record);
        }
        block_offset += UFS_DIRBLKSIZ;
    }
    records
}

/// Directory listing sorted by name, with child sizes resolved. Port of
/// `iter_ufs_directory_entries`.
pub fn iter_directory_entries(image: &[u8], ufs: &Ufs, inode: &Inode) -> Vec<DirListEntry> {
    let mut entries: Vec<DirListEntry> = Vec::new();
    for record in iter_inode_directory_records(image, ufs, inode) {
        if record.inode != 0 && record.name_length > 0 && record.name_length <= 255 {
            let size = read_inode(image, ufs, record.inode as i64).map(|child| child.size);
            entries.push(DirListEntry {
                name: record.name,
                inode: record.inode,
                size,
            });
        }
    }
    entries.sort_by(|a, b| a.name.cmp(&b.name));
    entries
}

/// List the root directory. Port of `list_ufs_root`.
pub fn list_root(image: &[u8], ufs: &Ufs) -> Vec<DirListEntry> {
    match read_inode(image, ufs, UFS_ROOT_INODE as i64) {
        Some(root) => iter_directory_entries(image, ufs, &root),
        None => Vec::new(),
    }
}

/// Look up `entry_name` in a directory inode. Port of `lookup_ufs_directory_entry`.
pub fn lookup_directory_entry(
    image: &[u8],
    ufs: &Ufs,
    directory_inode: &Inode,
    entry_name: &str,
) -> Option<(u32, Inode)> {
    let directory_size = directory_inode.size as usize;
    if directory_size == 0 {
        return None;
    }
    // Scan each DIRBLKSIZ block directly from the mapped data blocks, comparing
    // name bytes in place. This avoids copying the whole directory and avoids
    // allocating a String per record — both quadratic over a large directory
    // when looked up entry-by-entry (e.g. rsync stat'ing every dest path).
    let name = entry_name.as_bytes();
    let block_size = ufs.sb.bsize as usize;
    let data_blocks = inode_data_blocks(image, ufs, directory_inode);
    let mut block_offset = 0;
    while block_offset < directory_size {
        let span = UFS_DIRBLKSIZ.min(directory_size - block_offset);
        let logical_block = block_offset / block_size;
        let Some(&fs_block) = data_blocks.get(logical_block) else {
            break;
        };
        let backing = ufs.sb.data_block_offset(ufs.start_offset, fs_block as i64) as usize + (block_offset % block_size);
        let block = &image[backing..backing + span];
        let mut cursor = 0;
        while cursor + UFS_DIRENT_HEADER_SIZE <= span {
            let Some(header) = decode_directory_header(block, cursor, span) else {
                break;
            };
            if header.inode != 0 && header.name_length as usize == name.len() {
                let name_start = cursor + UFS_DIRENT_NAME_OFFSET;
                if &block[name_start..name_start + name.len()] == name {
                    let child = read_inode(image, ufs, header.inode as i64)?;
                    return Some((header.inode, child));
                }
            }
            cursor += header.record_length as usize;
        }
        block_offset += UFS_DIRBLKSIZ;
    }
    None
}

/// Resolve an absolute path to `(inode_number, inode)`. Port of `resolve_ufs_path`.
pub fn resolve_path(image: &[u8], ufs: &Ufs, path: &str) -> Option<(u32, Inode)> {
    let mut current_number = UFS_ROOT_INODE;
    let mut current = read_inode(image, ufs, current_number as i64)?;
    for part in path.split('/').filter(|p| !p.is_empty()) {
        let (number, inode) = lookup_directory_entry(image, ufs, &current, part)?;
        current_number = number;
        current = inode;
    }
    Some((current_number, current))
}

/// Read a symbolic link's target. SVR4 UFS stores the target in the inode's
/// data blocks (no fast-symlink form here), so this reads the inode bytes and
/// decodes them as ASCII — matching `UFSBackend.readlink`.
pub fn read_symlink_target(image: &[u8], ufs: &Ufs, inode: &Inode) -> String {
    let bytes = read_inode_bytes(image, ufs, inode);
    bytes
        .iter()
        .map(|&b| if b < 0x80 { b as char } else { '\u{FFFD}' })
        .collect()
}
