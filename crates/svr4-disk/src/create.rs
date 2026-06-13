//! Raw disk image construction. Port of `host_tools/disk/create.py`.
//!
//! Builds the MBR, pdinfo, VTOC and (empty) alternates metadata for a blank
//! image. Validation failures return the same `error: ...` strings the Python
//! tool raised via `SystemExit`, so the CLI prints identical diagnostics.

use std::fs::OpenOptions;
use std::io::{Seek, SeekFrom, Write};
use std::path::Path;

use svr4_fs_core::codec::{put_i32, put_u16, put_u32};

use crate::structures::{
    PartitionEntry, VtocPartition, HDPDLOC, SECTOR_SIZE, UNIXWARE_PARTITION_TYPE, VALID_PD,
    VTOC_SANE,
};
use crate::svr4::{ALT_SANITY, ALT_VERSION};

pub const MAX_ALTENTS: usize = 253;
pub const MAX_CHS_CYLINDERS: u32 = 1024;
pub const MAX_KERNEL_CHS_HEADS: u32 = 16;
pub const MAX_CHS_SECTORS_PER_TRACK: u32 = 63;
pub const DISK_ADDRESSING_CHS: &str = "chs";
pub const DISK_ADDRESSING_LBA28: &str = "lba28";

/// Validation/build errors carry the full `error: ...` message verbatim.
pub type BuildResult<T> = Result<T, String>;

/// The active-partition chainloader stub used by the Python skeleton tests.
pub const ACTIVE_PARTITION_CHAINLOADER_MBR: &[u8] = &[
    0x31, 0xc0, 0xfa, 0x8e, 0xd0, 0xbc, 0x00, 0x7c, 0x8e, 0xc0, 0x8e, 0xd8, 0xfb, 0x89, 0xe6, 0xbf,
    0x00, 0x06, 0xb9, 0x00, 0x02, 0xfc, 0xf3, 0xa4, 0xea, 0x1d, 0x06, 0x00, 0x00, 0xb0, 0x04, 0xbe,
    0xbe, 0x07, 0x80, 0x3c, 0x80, 0x74, 0x0c, 0x83, 0xc6, 0x10, 0xfe, 0xc8, 0x75, 0xf4, 0xbe, 0xac,
    0x06, 0xeb, 0x32, 0x89, 0xf7, 0x8b, 0x14, 0x8b, 0x4c, 0x02, 0xbd, 0x05, 0x00, 0xbb, 0x00, 0x7c,
    0xb8, 0x01, 0x02, 0xcd, 0x13, 0x73, 0x0c, 0x31, 0xc0, 0xcd, 0x13, 0x4d, 0x75, 0xef, 0xbe, 0x94,
    0x06, 0xeb, 0x12, 0x81, 0x3e, 0xfe, 0x7d, 0x55, 0xaa, 0x75, 0x07, 0x89, 0xfe, 0xea, 0x00, 0x7c,
    0x00, 0x00, 0xbe, 0x73, 0x06, 0xac, 0x08, 0xc0, 0x74, 0x06, 0xb4, 0x0e, 0xcd, 0x10, 0xeb, 0xf5,
    0xfb, 0xeb, 0xfe, 0x49, 0x6e, 0x76, 0x61, 0x6c, 0x69, 0x64, 0x20, 0x70, 0x61, 0x72, 0x74, 0x69,
    0x74, 0x69, 0x6f, 0x6e, 0x20, 0x62, 0x6f, 0x6f, 0x74, 0x20, 0x73, 0x69, 0x67, 0x6e, 0x61, 0x74,
    0x75, 0x72, 0x65, 0x00, 0x45, 0x72, 0x72, 0x6f, 0x72, 0x20, 0x72, 0x65, 0x61, 0x64, 0x69, 0x6e,
    0x67, 0x20, 0x62, 0x6f, 0x6f, 0x74, 0x73, 0x74, 0x72, 0x61, 0x70, 0x00, 0x4e, 0x6f, 0x20, 0x61,
    0x63, 0x74, 0x69, 0x76, 0x65, 0x20, 0x70, 0x61, 0x72, 0x74, 0x69, 0x74, 0x69, 0x6f, 0x6e, 0x20,
    0x6f, 0x6e, 0x20, 0x68, 0x61, 0x72, 0x64, 0x20, 0x64, 0x69, 0x73, 0x6b, 0x00,
];

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct RawDiskGeometry {
    pub cylinders: u32,
    pub heads: u32,
    pub sectors_per_track: u32,
}

impl RawDiskGeometry {
    pub fn total_sectors(&self) -> u64 {
        self.cylinders as u64 * self.heads as u64 * self.sectors_per_track as u64
    }
}

pub fn validate_geometry(geometry: &RawDiskGeometry, disk_addressing: &str) -> BuildResult<()> {
    if geometry.cylinders == 0 || geometry.heads == 0 || geometry.sectors_per_track == 0 {
        return Err("error: disk geometry values must all be positive".into());
    }
    if disk_addressing != DISK_ADDRESSING_CHS && disk_addressing != DISK_ADDRESSING_LBA28 {
        return Err(format!(
            "error: unsupported disk addressing mode '{disk_addressing}'"
        ));
    }
    if disk_addressing == DISK_ADDRESSING_CHS && geometry.cylinders > MAX_CHS_CYLINDERS {
        return Err(format!(
            "error: disk geometry exceeds CHS cylinder limit ({} > {MAX_CHS_CYLINDERS})",
            geometry.cylinders
        ));
    }
    if geometry.heads > MAX_KERNEL_CHS_HEADS {
        return Err(format!(
            "error: disk geometry exceeds kernel head limit ({} > {MAX_KERNEL_CHS_HEADS})",
            geometry.heads
        ));
    }
    if geometry.sectors_per_track > MAX_CHS_SECTORS_PER_TRACK {
        return Err(format!(
            "error: disk geometry exceeds CHS sector-per-track limit ({} > {MAX_CHS_SECTORS_PER_TRACK})",
            geometry.sectors_per_track
        ));
    }
    Ok(())
}

pub fn max_chs_lba(geometry: &RawDiskGeometry) -> u64 {
    geometry.total_sectors() - 1
}

pub fn validate_unix_partition(
    total_sectors: u64,
    unix_partition_start: u64,
    unix_partition_size: u64,
) -> BuildResult<()> {
    if unix_partition_start < 1 {
        return Err("error: UNIX partition must start at or after sector 1".into());
    }
    if unix_partition_size == 0 {
        return Err("error: UNIX partition size must be positive".into());
    }
    if unix_partition_start + unix_partition_size > total_sectors {
        return Err("error: UNIX partition exceeds the declared disk geometry".into());
    }
    Ok(())
}

pub fn validate_vtoc_partitions(
    unix_partition_start: i64,
    unix_partition_size: i64,
    partitions: &[VtocPartition],
) -> BuildResult<()> {
    let mut seen = std::collections::HashSet::new();
    let unix_partition_end = unix_partition_start + unix_partition_size;
    for partition in partitions {
        if partition.index >= 16 {
            return Err(format!(
                "error: slice index {} is outside the supported VTOC range 0..15",
                partition.index
            ));
        }
        if !seen.insert(partition.index) {
            return Err(format!("error: duplicate slice index {}", partition.index));
        }
        if partition.start_sector < 0 {
            return Err(format!(
                "error: slice {} has a negative start sector",
                partition.index
            ));
        }
        if partition.sector_count < 0 {
            return Err(format!("error: slice {} has a negative size", partition.index));
        }
        if partition.start_sector < unix_partition_start {
            return Err(format!(
                "error: slice {} starts before the UNIX partition",
                partition.index
            ));
        }
        if partition.start_sector + partition.sector_count > unix_partition_end {
            return Err(format!(
                "error: slice {} exceeds the UNIX partition bounds",
                partition.index
            ));
        }
    }
    Ok(())
}

/// Encode an LBA into a 3-byte CHS field. Port of `encode_chs`.
pub fn encode_chs(lba: u64, geometry: &RawDiskGeometry, saturate: bool) -> BuildResult<[u8; 3]> {
    if lba == 0 {
        return Ok([0, 0, 0]);
    }
    let mut lba = lba;
    if lba > max_chs_lba(geometry) {
        if !saturate {
            return Err(format!(
                "error: LBA {lba} is outside the CHS-addressable disk geometry"
            ));
        }
        lba = max_chs_lba(geometry);
    }
    if saturate {
        let cap = MAX_CHS_CYLINDERS as u64 * geometry.heads as u64 * geometry.sectors_per_track as u64
            - 1;
        lba = lba.min(cap);
    }
    let sectors_per_cylinder = geometry.heads as u64 * geometry.sectors_per_track as u64;
    let cylinder = lba / sectors_per_cylinder;
    let temp = lba % sectors_per_cylinder;
    let head = temp / geometry.sectors_per_track as u64;
    let sector = (temp % geometry.sectors_per_track as u64) + 1;
    let sector_byte = (sector & 0x3F) | ((cylinder >> 2) & 0xC0);
    Ok([
        (head & 0xFF) as u8,
        (sector_byte & 0xFF) as u8,
        (cylinder & 0xFF) as u8,
    ])
}

pub fn serialize_partition_entry(
    partition: &PartitionEntry,
    geometry: &RawDiskGeometry,
    saturate_chs: bool,
) -> BuildResult<[u8; 16]> {
    let mut out = [0u8; 16];
    out[0] = if partition.bootable { 0x80 } else { 0x00 };
    out[1..4].copy_from_slice(&encode_chs(partition.start_lba as u64, geometry, saturate_chs)?);
    out[4] = partition.partition_type;
    let last = partition.start_lba as u64 + partition.sector_count.saturating_sub(1) as u64;
    out[5..8].copy_from_slice(&encode_chs(last, geometry, saturate_chs)?);
    put_u32(&mut out, 8, partition.start_lba);
    put_u32(&mut out, 12, partition.sector_count);
    Ok(out)
}

pub fn build_mbr(
    geometry: &RawDiskGeometry,
    unix_partition_start: u32,
    unix_partition_size: u32,
    boot_code: Option<&[u8]>,
    disk_addressing: &str,
) -> BuildResult<Vec<u8>> {
    let mut sector = vec![0u8; SECTOR_SIZE];
    if let Some(boot_code) = boot_code {
        if boot_code.len() > 446 {
            return Err(format!(
                "error: MBR boot code is too large ({} > 446 bytes)",
                boot_code.len()
            ));
        }
        sector[..boot_code.len()].copy_from_slice(boot_code);
    }
    let entry = serialize_partition_entry(
        &PartitionEntry {
            index: 1,
            bootable: true,
            partition_type: UNIXWARE_PARTITION_TYPE,
            start_lba: unix_partition_start,
            sector_count: unix_partition_size,
            start_chs: (0, 0, 0),
            end_chs: (0, 0, 0),
        },
        geometry,
        disk_addressing == DISK_ADDRESSING_LBA28,
    )?;
    sector[446..462].copy_from_slice(&entry);
    put_u16(&mut sector, 510, 0xAA55);
    Ok(sector)
}

#[allow(clippy::too_many_arguments)]
pub fn build_pdinfo(
    geometry: &RawDiskGeometry,
    logical_sector_0: u32,
    vtoc_ptr: u32,
    vtoc_len: u16,
    alt_ptr: u32,
    alt_len: u16,
) -> Vec<u8> {
    let mut sector = vec![0u8; SECTOR_SIZE];
    put_u32(&mut sector, 0, 0);
    put_u32(&mut sector, 4, VALID_PD);
    put_u32(&mut sector, 8, 1);
    put_u32(&mut sector, 24, geometry.cylinders);
    put_u32(&mut sector, 28, geometry.heads);
    put_u32(&mut sector, 32, geometry.sectors_per_track);
    put_u32(&mut sector, 36, SECTOR_SIZE as u32);
    put_u32(&mut sector, 40, logical_sector_0);
    put_u32(&mut sector, 84, vtoc_ptr);
    put_u16(&mut sector, 88, vtoc_len);
    put_u32(&mut sector, 92, alt_ptr);
    put_u16(&mut sector, 96, alt_len);
    sector
}

pub fn build_vtoc(volume: &str, partitions: &[VtocPartition]) -> Vec<u8> {
    let mut block = vec![0u8; SECTOR_SIZE];
    put_u32(&mut block, 0, VTOC_SANE);
    put_u32(&mut block, 4, 1);
    let volume_bytes = volume.as_bytes();
    let n = volume_bytes.len().min(8);
    block[8..8 + n].copy_from_slice(&volume_bytes[..n]);
    let partition_count = partitions
        .iter()
        .map(|p| p.index as i64)
        .max()
        .map(|m| m + 1)
        .unwrap_or(0);
    put_u16(&mut block, 16, partition_count as u16);
    for partition in partitions {
        let base = 60 + partition.index as usize * 12;
        put_u16(&mut block, base, partition.tag);
        put_u16(&mut block, base + 2, partition.flag);
        put_i32(&mut block, base + 4, partition.start_sector as i32);
        put_i32(&mut block, base + 8, partition.sector_count as i32);
    }
    block
}

pub fn build_empty_alt_info() -> Vec<u8> {
    let mut block = vec![0u8; 2048];
    put_u32(&mut block, 0, ALT_SANITY);
    put_u16(&mut block, 4, ALT_VERSION);
    put_u16(&mut block, 6, 0);

    let track_table_offset = 8;
    let sector_table_offset = track_table_offset + 8 + MAX_ALTENTS * 4;

    put_u16(&mut block, track_table_offset, 0);
    put_u16(&mut block, track_table_offset + 2, 0);
    put_i32(&mut block, track_table_offset + 4, 0);

    put_u16(&mut block, sector_table_offset, 0);
    put_u16(&mut block, sector_table_offset + 2, 0);
    put_i32(&mut block, sector_table_offset + 4, 0);
    block
}

#[allow(clippy::too_many_arguments)]
pub fn create_raw_image_skeleton(
    output_path: &Path,
    geometry: &RawDiskGeometry,
    unix_partition_start: u32,
    unix_partition_size: u32,
    volume: &str,
    slices: &[VtocPartition],
    mbr_boot_code: Option<&[u8]>,
    disk_addressing: &str,
) -> BuildResult<()> {
    validate_geometry(geometry, disk_addressing)?;
    validate_unix_partition(
        geometry.total_sectors(),
        unix_partition_start as u64,
        unix_partition_size as u64,
    )?;
    validate_vtoc_partitions(
        unix_partition_start as i64,
        unix_partition_size as i64,
        slices,
    )?;

    if let Some(parent) = output_path.parent() {
        if !parent.as_os_str().is_empty() {
            std::fs::create_dir_all(parent).map_err(|e| format!("error: {e}"))?;
        }
    }

    let total_bytes = geometry.total_sectors() * SECTOR_SIZE as u64;
    let mut handle = OpenOptions::new()
        .create(true)
        .write(true)
        .truncate(true)
        .open(output_path)
        .map_err(|e| format!("error: {e}"))?;
    handle.set_len(total_bytes).map_err(|e| format!("error: {e}"))?;

    let write_at = |handle: &mut std::fs::File, offset: u64, data: &[u8]| -> BuildResult<()> {
        handle
            .seek(SeekFrom::Start(offset))
            .and_then(|_| handle.write_all(data))
            .map_err(|e| format!("error: {e}"))
    };

    let mbr = build_mbr(
        geometry,
        unix_partition_start,
        unix_partition_size,
        mbr_boot_code,
        disk_addressing,
    )?;
    write_at(&mut handle, 0, &mbr)?;

    let vtoc_ptr: u32 = (HDPDLOC as u32 * SECTOR_SIZE as u32) + 100;
    let vtoc_len: u16 = 316;
    let alt_ptr: u32 = 30 * SECTOR_SIZE as u32;
    let alt_info = build_empty_alt_info();
    let alt_len = alt_info.len() as u16;

    let pdinfo_sector = unix_partition_start as u64 + HDPDLOC;
    let pdinfo = build_pdinfo(
        geometry,
        unix_partition_start,
        vtoc_ptr,
        vtoc_len,
        alt_ptr,
        alt_len,
    );
    write_at(&mut handle, pdinfo_sector * SECTOR_SIZE as u64, &pdinfo)?;

    let vtoc_sector = unix_partition_start as u64 + (vtoc_ptr as u64 / SECTOR_SIZE as u64);
    let vtoc_offset = vtoc_ptr as u64 % SECTOR_SIZE as u64;
    let vtoc_block = build_vtoc(volume, slices);
    let image_offset = vtoc_sector * SECTOR_SIZE as u64 + vtoc_offset;
    if image_offset + vtoc_block.len() as u64 > total_bytes {
        return Err("error: VTOC metadata does not fit inside the declared disk geometry".into());
    }
    write_at(&mut handle, image_offset, &vtoc_block)?;

    let alt_sector = unix_partition_start as u64 + (alt_ptr as u64 / SECTOR_SIZE as u64);
    let alt_offset = alt_ptr as u64 % SECTOR_SIZE as u64;
    let alt_image_offset = alt_sector * SECTOR_SIZE as u64 + alt_offset;
    if alt_image_offset + alt_info.len() as u64 > total_bytes {
        return Err("error: alternates metadata does not fit inside the declared disk geometry".into());
    }
    write_at(&mut handle, alt_image_offset, &alt_info)?;

    handle.flush().map_err(|e| format!("error: {e}"))?;
    Ok(())
}
