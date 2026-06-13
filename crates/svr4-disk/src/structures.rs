//! Data structures and constants for the SVR4 disk layout.
//!
//! Port of `host_tools/disk/structures.py`. The MBR partition table, the SVR4
//! `pdinfo` "physical description" sector, the VTOC (volume table of contents),
//! and the alternates tables.

use serde::Serialize;

pub const SECTOR_SIZE: usize = 512;
pub const UNIXWARE_PARTITION_TYPE: u8 = 0x63;
/// Sector offset of the pdinfo within the UNIX partition.
pub const HDPDLOC: u64 = 29;
pub const VALID_PD: u32 = 0xCA5E_600D;
pub const VTOC_SANE: u32 = 0x600D_DEEE;

/// A single 16-byte MBR partition table entry.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct PartitionEntry {
    pub index: u32,
    pub bootable: bool,
    pub partition_type: u8,
    pub start_lba: u32,
    pub sector_count: u32,
    /// Decoded (cylinder, head, sector).
    pub start_chs: (u16, u16, u16),
    pub end_chs: (u16, u16, u16),
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct MbrInfo {
    pub signature: u16,
    pub partitions: Vec<PartitionEntry>,
}

/// SVR4 physical-description sector (`pdinfo`).
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct PdInfo {
    pub drive_id: u32,
    pub sanity: u32,
    pub version: u32,
    pub serial: String,
    pub cylinders: u32,
    pub tracks: u32,
    pub sectors: u32,
    pub bytes_per_sector: u32,
    pub logical_sector_0: u32,
    pub vtoc_ptr: u32,
    pub vtoc_len: u16,
    pub alt_ptr: u32,
    pub alt_len: u16,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct AltTableInfo {
    pub used: u16,
    pub reserved: u16,
    pub base_sector: i32,
    pub bad_entries: Vec<i32>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct AltInfo {
    pub sanity: u32,
    pub version: u16,
    pub track_table: AltTableInfo,
    pub sector_table: AltTableInfo,
}

/// A single VTOC slice entry. `start_sector`/`sector_count` are stored signed
/// on disk; keep them as `i64` so the parse/print round-trips exactly.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct VtocPartition {
    pub index: u32,
    pub tag: u16,
    pub flag: u16,
    pub start_sector: i64,
    pub sector_count: i64,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct VtocInfo {
    pub sanity: u32,
    pub version: u32,
    pub volume: String,
    pub partition_count: u16,
    pub partitions: Vec<VtocPartition>,
}

/// One detected slice plus any filesystem found inside it.
///
/// `filesystem`/`root_entries` are populated by the FS-detection hook; in the
/// Phase 1 disk-only port they stay `None`/empty (the FS crates land in Phase 2).
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct SliceFilesystem {
    pub slice_index: u32,
    pub tag: u16,
    pub start_sector: i64,
    pub absolute_start_sector: i64,
    pub sector_count: i64,
    pub filesystem: Option<String>,
    pub filesystem_offset: u64,
    pub root_entries: Vec<RootEntry>,
}

/// A directory entry as reported in an inspection listing.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct RootEntry {
    pub name: String,
    pub inode: u32,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub size: Option<u64>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct DiskImageReport {
    pub path: String,
    pub file_size: u64,
    pub mbr: MbrInfo,
    pub active_unix_partition: Option<PartitionEntry>,
    pub pdinfo: Option<PdInfo>,
    pub vtoc: Option<VtocInfo>,
    pub slice_filesystems: Vec<SliceFilesystem>,
    pub notes: Vec<String>,
}
