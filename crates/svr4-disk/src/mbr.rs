//! MBR partition table parsing. Port of `host_tools/disk/mbr.py`.

use svr4_fs_core::codec::u32;

use crate::structures::{MbrInfo, PartitionEntry, SECTOR_SIZE};

/// Decode a 3-byte CHS field into `(cylinder, head, sector)`.
pub fn decode_chs(raw: &[u8]) -> (u16, u16, u16) {
    let head = raw[0] as u16;
    let sector = (raw[1] & 0x3F) as u16;
    let cylinder = (((raw[1] & 0xC0) as u16) << 2) | raw[2] as u16;
    (cylinder, head, sector)
}

/// Parse one 16-byte partition entry. `index` is 1-based, matching the Python.
pub fn parse_partition_entry(index: u32, raw: &[u8]) -> PartitionEntry {
    assert_eq!(raw.len(), 16, "partition entry must be 16 bytes");
    PartitionEntry {
        index,
        bootable: raw[0] == 0x80,
        start_chs: decode_chs(&raw[1..4]),
        partition_type: raw[4],
        end_chs: decode_chs(&raw[5..8]),
        start_lba: u32(raw, 8),
        sector_count: u32(raw, 12),
    }
}

/// Parse the four entries and boot signature out of a 512-byte MBR sector.
pub fn parse_mbr_sector(sector: &[u8]) -> MbrInfo {
    assert_eq!(
        sector.len(),
        SECTOR_SIZE,
        "MBR sector must be exactly {SECTOR_SIZE} bytes"
    );
    let partitions = (0..4)
        .map(|index| {
            let base = 446 + index * 16;
            parse_partition_entry(index as u32 + 1, &sector[base..base + 16])
        })
        .collect();
    let signature = svr4_fs_core::codec::u16(sector, 510);
    MbrInfo {
        signature,
        partitions,
    }
}
