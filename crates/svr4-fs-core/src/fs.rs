//! Filesystem identification shared by the disk-inspection and per-filesystem
//! crates.
//!
//! This is the typed equivalent of the Python `FilesystemCandidate`
//! (`host_tools/fs/common.py`), minus the untyped `details`/`root_entries`
//! grab-bags. Those held parsed superblock fields and directory listings; in the
//! Rust port they become strongly-typed structs owned by the filesystem crates
//! (e.g. `svr4-ufs`'s parsed superblock), so they are intentionally not carried
//! here.

/// Which filesystem was detected in a slice.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum FsKind {
    Ufs,
    Bfs,
}

impl FsKind {
    pub fn as_str(self) -> &'static str {
        match self {
            FsKind::Ufs => "ufs",
            FsKind::Bfs => "bfs",
        }
    }
}

/// Where a detected filesystem lives within a backing image.
///
/// `start_offset` is the byte offset of the slice within the whole disk image;
/// `super_offset` is the byte offset of the superblock relative to that start
/// (for UFS this is `start_offset + UFS_SB_OFFSET`'s relative part). Keeping both
/// mirrors how the Python tools address structures.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct FilesystemCandidate {
    pub kind: FsKind,
    pub start_offset: u64,
    pub super_offset: u64,
    pub block_size: Option<u32>,
}

impl FilesystemCandidate {
    pub fn new(kind: FsKind, start_offset: u64, super_offset: u64) -> Self {
        FilesystemCandidate {
            kind,
            start_offset,
            super_offset,
            block_size: None,
        }
    }

    pub fn with_block_size(mut self, block_size: u32) -> Self {
        self.block_size = Some(block_size);
        self
    }
}
