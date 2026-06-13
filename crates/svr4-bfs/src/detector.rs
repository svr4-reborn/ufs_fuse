//! Adapter plugging the BFS reader into the disk crate's [`FsDetector`] hook, so
//! `svr4-disk-image inspect` reports BFS slices (the `/stand` slice) and their
//! root entries.

use svr4_disk::inspect::{DetectedFs, FsDetector};
use svr4_disk::structures::RootEntry;

use crate::{detect_at_start, list_root};

/// Detects a BFS filesystem at the start of a slice.
pub struct BfsDetector;

impl FsDetector for BfsDetector {
    fn probe(&self, slice_bytes: &[u8]) -> Option<DetectedFs> {
        let bfs = detect_at_start(slice_bytes, 0)?;
        let root_entries = list_root(slice_bytes, &bfs)
            .into_iter()
            .map(|entry| RootEntry {
                name: entry.name,
                inode: u32::from(entry.inode),
                size: Some(entry.size),
            })
            .collect();
        Some(DetectedFs {
            filesystem: "bfs".to_string(),
            filesystem_offset: bfs.start_offset,
            root_entries,
        })
    }
}
