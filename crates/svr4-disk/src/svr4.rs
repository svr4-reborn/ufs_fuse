//! SVR4 pdinfo / VTOC / alternates parsing and helpers.
//! Port of `host_tools/disk/svr4.py`.

use svr4_fs_core::codec::{i32, u16, u32};

use crate::structures::{AltInfo, AltTableInfo, PdInfo, VtocInfo, VtocPartition, VALID_PD, VTOC_SANE};

pub const VTOC_PARTITION_COUNT: usize = 16;
pub const PARTITION_STRUCT_OFFSET: usize = 60;
pub const PARTITION_STRUCT_SIZE: usize = 12;
pub const ALT_SANITY: u32 = 0xDEAD_BEEF;
pub const ALT_VERSION: u16 = 0x02;
pub const V_BACKUP: u16 = 0x05;
pub const V_OTHER: u16 = 0x07;

/// Known VTOC partition tags, in the same order as the Python dict.
pub const PARTITION_TAG_NAMES: &[(u16, &str)] = &[
    (0x01, "boot"),
    (0x02, "root"),
    (0x03, "swap"),
    (0x04, "usr"),
    (0x05, "backup"),
    (0x06, "alts"),
    (0x07, "other"),
    (0x08, "alttrk"),
    (0x09, "stand"),
    (0x0A, "var"),
    (0x0B, "home"),
    (0x0C, "dump"),
];

/// Human-readable name for a VTOC tag, or `unknown(0x..)` for unknown tags.
pub fn partition_tag_name(tag: u16) -> String {
    PARTITION_TAG_NAMES
        .iter()
        .find(|(value, _)| *value == tag)
        .map(|(_, name)| name.to_string())
        .unwrap_or_else(|| format!("unknown(0x{tag:02x})"))
}

/// Decode a NUL-terminated ASCII field, replacing invalid bytes with U+FFFD to
/// mirror Python's `decode('ascii', errors='replace')`.
fn decode_ascii_field(raw: &[u8]) -> String {
    let end = raw.iter().position(|&b| b == 0).unwrap_or(raw.len());
    raw[..end]
        .iter()
        .map(|&b| if b < 0x80 { b as char } else { '\u{FFFD}' })
        .collect()
}

pub fn parse_pdinfo(raw: &[u8]) -> PdInfo {
    assert!(raw.len() >= 98, "pdinfo sector is too small");
    PdInfo {
        drive_id: u32(raw, 0),
        sanity: u32(raw, 4),
        version: u32(raw, 8),
        serial: decode_ascii_field(&raw[12..24]),
        cylinders: u32(raw, 24),
        tracks: u32(raw, 28),
        sectors: u32(raw, 32),
        bytes_per_sector: u32(raw, 36),
        logical_sector_0: u32(raw, 40),
        vtoc_ptr: u32(raw, 84),
        vtoc_len: u16(raw, 88),
        alt_ptr: u32(raw, 92),
        alt_len: u16(raw, 96),
    }
}

pub fn parse_vtoc(raw: &[u8], offset: usize) -> VtocInfo {
    let view = &raw[offset..];
    assert!(
        view.len() >= PARTITION_STRUCT_OFFSET + VTOC_PARTITION_COUNT * PARTITION_STRUCT_SIZE,
        "vtoc block is too small"
    );
    let partitions = (0..VTOC_PARTITION_COUNT)
        .map(|index| {
            let base = PARTITION_STRUCT_OFFSET + index * PARTITION_STRUCT_SIZE;
            VtocPartition {
                index: index as u32,
                tag: u16(view, base),
                flag: u16(view, base + 2),
                start_sector: i32(view, base + 4) as i64,
                sector_count: i32(view, base + 8) as i64,
            }
        })
        .collect();
    VtocInfo {
        sanity: u32(view, 0),
        version: u32(view, 4),
        volume: decode_ascii_field(&view[8..16]),
        partition_count: u16(view, 16),
        partitions,
    }
}

fn parse_alt_table(raw: &[u8], offset: usize, entry_count: usize) -> (AltTableInfo, usize) {
    let end_offset = offset + 8 + entry_count * 4;
    assert!(raw.len() >= end_offset, "alternates table is truncated");
    let bad_entries = (offset + 8..end_offset)
        .step_by(4)
        .map(|entry_offset| i32(raw, entry_offset))
        .collect();
    let table = AltTableInfo {
        used: u16(raw, offset),
        reserved: entry_count as u16,
        base_sector: i32(raw, offset + 4),
        bad_entries,
    };
    (table, end_offset)
}

pub fn parse_alt_info(raw: &[u8], offset: usize) -> AltInfo {
    let view = &raw[offset..];
    assert!(view.len() >= 16, "alternates table is too small");
    let sanity = u32(view, 0);
    let version = u16(view, 4);
    let track_reserved = u16(view, 10) as usize;
    let (track_table, next_offset) = parse_alt_table(view, 8, track_reserved);
    assert!(
        view.len() >= next_offset + 4,
        "alternates table is missing sector metadata"
    );
    let sector_reserved = u16(view, next_offset + 2) as usize;
    let (sector_table, _) = parse_alt_table(view, next_offset, sector_reserved);
    AltInfo {
        sanity,
        version,
        track_table,
        sector_table,
    }
}

/// Remap an absolute sector through the alternates tables, mirroring the SVR4
/// driver's bad-block redirection. Port of `remap_guest_visible_sector`.
pub fn remap_guest_visible_sector(
    pdinfo: &PdInfo,
    partition: &VtocPartition,
    alt_info: Option<&AltInfo>,
    absolute_sector: i64,
) -> i64 {
    let Some(alt_info) = alt_info else {
        return absolute_sector;
    };
    if partition.index == 0 || partition.tag == V_BACKUP || partition.tag == V_OTHER {
        return absolute_sector;
    }
    assert!(pdinfo.sectors > 0, "pdinfo.sectors must be positive");
    let sectors = pdinfo.sectors as i64;

    let mut remapped_sector = absolute_sector;
    let track_number = remapped_sector / sectors;
    let track_used = alt_info.track_table.used as usize;
    for (index, &bad_track) in alt_info.track_table.bad_entries[..track_used]
        .iter()
        .enumerate()
    {
        if track_number == bad_track as i64 {
            remapped_sector = alt_info.track_table.base_sector as i64
                + (index as i64 * sectors)
                + (remapped_sector % sectors);
            break;
        }
    }

    let sector_used = alt_info.sector_table.used as usize;
    for (index, &bad_sector) in alt_info.sector_table.bad_entries[..sector_used]
        .iter()
        .enumerate()
    {
        if remapped_sector == bad_sector as i64 {
            remapped_sector = alt_info.sector_table.base_sector as i64 + index as i64;
            break;
        }
    }

    remapped_sector
}

pub fn is_valid_pdinfo(pdinfo: &PdInfo) -> bool {
    pdinfo.sanity == VALID_PD
}

pub fn is_valid_vtoc(vtoc: &VtocInfo) -> bool {
    vtoc.sanity == VTOC_SANE
}

pub fn is_valid_alt_info(alt_info: &AltInfo) -> bool {
    alt_info.sanity == ALT_SANITY && alt_info.version == ALT_VERSION
}
