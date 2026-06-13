//! On-disk inode parsing and block-list resolution.
//!
//! Port of the inode half of `host_tools/fs/ufs_lowlevel.py` /
//! `host_tools/fs/ufs.py`: `read_ufs_inode`, `read_ufs_pointer_block`,
//! `collect_indirect_data_blocks`, `ufs_inode_data_blocks`, and the file-type
//! predicates.

use svr4_fs_core::codec::{u16, u32, u64};
use svr4_fs_core::consts::{
    UFS_DINODE_SIZE, UFS_DI_ATIME_OFFSET, UFS_DI_BLOCKS_OFFSET, UFS_DI_CTIME_OFFSET, UFS_DI_DB_OFFSET,
    UFS_DI_GID_OFFSET, UFS_DI_IB_OFFSET, UFS_DI_MODE_OFFSET, UFS_DI_MTIME_OFFSET, UFS_DI_NLINK_OFFSET,
    UFS_DI_SIZE_OFFSET, UFS_DI_UID_OFFSET, UFS_IFDIR, UFS_IFLNK, UFS_IFMT, UFS_IFREG, UFS_NDADDR,
    UFS_NIADDR,
};

use crate::superblock::Ufs;

/// A decoded on-disk inode. Mirrors the dict returned by `read_ufs_inode`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Inode {
    pub mode: u32,
    pub nlink: u16,
    pub uid: u32,
    pub gid: u32,
    pub atime: u32,
    pub mtime: u32,
    pub ctime: u32,
    pub size: u64,
    pub direct_blocks: [u32; UFS_NDADDR],
    pub indirect_blocks: [u32; UFS_NIADDR],
    pub blocks: u32,
}

impl Inode {
    #[inline]
    pub fn file_type(&self) -> u32 {
        self.mode & UFS_IFMT
    }

    #[inline]
    pub fn is_directory(&self) -> bool {
        self.file_type() == UFS_IFDIR
    }

    #[inline]
    pub fn is_symlink(&self) -> bool {
        self.file_type() == UFS_IFLNK
    }

    #[inline]
    pub fn is_regular(&self) -> bool {
        self.file_type() == UFS_IFREG
    }
}

/// Read inode `inode_number`, or `None` if its byte range falls outside the
/// image. Port of `read_ufs_inode`.
pub fn read_inode(image: &[u8], ufs: &Ufs, inode_number: i64) -> Option<Inode> {
    let inode_offset = ufs.sb.inode_byte_offset(ufs.start_offset, inode_number);
    if inode_offset < ufs.start_offset as i64
        || inode_offset + UFS_DINODE_SIZE as i64 > image.len() as i64
    {
        return None;
    }
    let base = inode_offset as usize;
    let raw = &image[base..base + UFS_DINODE_SIZE];

    let mut direct_blocks = [0u32; UFS_NDADDR];
    for (index, slot) in direct_blocks.iter_mut().enumerate() {
        *slot = u32(raw, UFS_DI_DB_OFFSET + index * 4);
    }
    let mut indirect_blocks = [0u32; UFS_NIADDR];
    for (index, slot) in indirect_blocks.iter_mut().enumerate() {
        *slot = u32(raw, UFS_DI_IB_OFFSET + index * 4);
    }

    Some(Inode {
        mode: u32(raw, UFS_DI_MODE_OFFSET),
        nlink: u16(raw, UFS_DI_NLINK_OFFSET),
        uid: u32(raw, UFS_DI_UID_OFFSET),
        gid: u32(raw, UFS_DI_GID_OFFSET),
        atime: u32(raw, UFS_DI_ATIME_OFFSET),
        mtime: u32(raw, UFS_DI_MTIME_OFFSET),
        ctime: u32(raw, UFS_DI_CTIME_OFFSET),
        size: u64(raw, UFS_DI_SIZE_OFFSET),
        direct_blocks,
        indirect_blocks,
        blocks: u32(raw, UFS_DI_BLOCKS_OFFSET),
    })
}

/// Read an indirect (pointer) block: `nindir` little-endian `u32` pointers.
/// Port of `read_ufs_pointer_block`.
pub fn read_pointer_block(image: &[u8], ufs: &Ufs, fs_block: u32) -> Vec<u32> {
    let block_offset = ufs.sb.data_block_offset(ufs.start_offset, fs_block as i64) as usize;
    let block_size = ufs.sb.bsize as usize;
    let raw = &image[block_offset..block_offset + block_size];
    (0..ufs.sb.nindir as usize)
        .map(|index| u32(raw, index * 4))
        .collect()
}

/// Recursively collect data blocks reachable through an indirect tree rooted at
/// `fs_block` with `levels` of indirection. Port of
/// `collect_indirect_data_blocks`.
pub fn collect_indirect_data_blocks(
    image: &[u8],
    ufs: &Ufs,
    fs_block: u32,
    levels: u32,
    max_blocks: Option<usize>,
) -> Vec<u32> {
    if fs_block == 0 || levels == 0 || max_blocks == Some(0) {
        return Vec::new();
    }
    let mut blocks: Vec<u32> = Vec::new();
    for pointer in read_pointer_block(image, ufs, fs_block) {
        if pointer == 0 {
            continue;
        }
        if levels == 1 {
            blocks.push(pointer);
        } else {
            let child_max = max_blocks.map(|m| m.saturating_sub(blocks.len()));
            blocks.extend(collect_indirect_data_blocks(
                image, ufs, pointer, levels - 1, child_max,
            ));
        }
        if let Some(max) = max_blocks {
            if blocks.len() >= max {
                blocks.truncate(max);
                return blocks;
            }
        }
    }
    blocks
}

/// Collect every pointer (indirect) block in the tree rooted at `fs_block`,
/// including `fs_block` itself. Port of `collect_indirect_pointer_blocks`.
pub fn collect_indirect_pointer_blocks(
    image: &[u8],
    ufs: &Ufs,
    fs_block: u32,
    levels: u32,
) -> Vec<u32> {
    if fs_block == 0 || levels == 0 {
        return Vec::new();
    }
    let mut blocks = vec![fs_block];
    if levels == 1 {
        return blocks;
    }
    for child in read_pointer_block(image, ufs, fs_block) {
        if child == 0 {
            continue;
        }
        blocks.extend(collect_indirect_pointer_blocks(image, ufs, child, levels - 1));
    }
    blocks
}

/// All indirect/pointer blocks an inode owns (across its three indirect roots).
/// Port of `ufs_inode_pointer_blocks`.
pub fn inode_pointer_blocks(image: &[u8], ufs: &Ufs, inode: &Inode) -> Vec<u32> {
    let mut blocks = Vec::new();
    for (level_index, &root_block) in inode.indirect_blocks.iter().enumerate() {
        blocks.extend(collect_indirect_pointer_blocks(
            image,
            ufs,
            root_block,
            level_index as u32 + 1,
        ));
    }
    blocks
}

/// The ordered list of data blocks backing `inode`, truncated to the number of
/// blocks its size requires. Port of `ufs_inode_data_blocks`.
pub fn inode_data_blocks(image: &[u8], ufs: &Ufs, inode: &Inode) -> Vec<u32> {
    let block_size = ufs.sb.bsize as u64;
    let needed_blocks = if inode.size == 0 {
        0usize
    } else {
        inode.size.div_ceil(block_size) as usize
    };
    let mut blocks: Vec<u32> = Vec::new();

    for &fs_block in &inode.direct_blocks {
        if fs_block == 0 {
            continue;
        }
        blocks.push(fs_block);
        if blocks.len() >= needed_blocks {
            blocks.truncate(needed_blocks);
            return blocks;
        }
    }

    for (level_index, &root_block) in inode.indirect_blocks.iter().enumerate() {
        let levels = level_index as u32 + 1;
        let remaining = needed_blocks.saturating_sub(blocks.len());
        blocks.extend(collect_indirect_data_blocks(
            image,
            ufs,
            root_block,
            levels,
            Some(remaining),
        ));
        if blocks.len() >= needed_blocks {
            blocks.truncate(needed_blocks);
            return blocks;
        }
    }

    blocks.truncate(needed_blocks);
    blocks
}
