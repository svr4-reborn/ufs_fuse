//! Adapter that plugs the UFS reader into the disk crate's [`FsDetector`] hook,
//! so `svr4-disk-image inspect` reports UFS slices and their root entries.
//!
//! This is the typed equivalent of the Python `select_slice_filesystem` UFS
//! branch: detect a UFS superblock at the start of the slice and, if found,
//! list its root directory.

use svr4_disk::inspect::{DetectedFs, FsDetector};
use svr4_disk::structures::RootEntry;

use crate::reader::list_root;
use crate::superblock::detect_ufs_at_start;

/// Detects a UFS filesystem at the start of a slice.
pub struct UfsDetector;

impl FsDetector for UfsDetector {
    fn probe(&self, slice_bytes: &[u8]) -> Option<DetectedFs> {
        let ufs = detect_ufs_at_start(slice_bytes, 0)?;
        let root_entries = list_root(slice_bytes, &ufs)
            .into_iter()
            .map(|entry| RootEntry {
                name: entry.name,
                inode: entry.inode,
                size: entry.size,
            })
            .collect();
        Some(DetectedFs {
            filesystem: "ufs".to_string(),
            filesystem_offset: ufs.start_offset,
            root_entries,
        })
    }
}
