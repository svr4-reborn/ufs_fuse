//! Human-readable rendering of a [`DiskImageReport`].
//!
//! Byte-for-byte port of the `print_*` functions in `host_tools/disk/cli.py`,
//! so `svr4-disk-image inspect` produces output identical to the Python tool —
//! the basis for the Phase 1 differential test.

use std::fmt::Write as _;

use crate::structures::{
    DiskImageReport, MbrInfo, PartitionEntry, PdInfo, SliceFilesystem, VtocInfo,
};
use crate::svr4::partition_tag_name;

fn format_partition_type(partition_type: u8) -> String {
    format!("0x{partition_type:02x}")
}

fn chs(t: (u16, u16, u16)) -> String {
    format!("({}, {}, {})", t.0, t.1, t.2)
}

fn render_partition_table(out: &mut String, mbr: &MbrInfo) {
    let _ = writeln!(out, "MBR signature: 0x{:04x}", mbr.signature);
    let _ = writeln!(out, "Partitions:");
    for partition in &mbr.partitions {
        if partition.partition_type == 0 && partition.start_lba == 0 && partition.sector_count == 0 {
            continue;
        }
        let boot_flag = if partition.bootable { '*' } else { '-' };
        let _ = writeln!(
            out,
            "  {}: {} type={} start={} sectors={} start_chs={} end_chs={}",
            partition.index,
            boot_flag,
            format_partition_type(partition.partition_type),
            partition.start_lba,
            partition.sector_count,
            chs(partition.start_chs),
            chs(partition.end_chs),
        );
    }
}

fn render_active_partition(out: &mut String, active: &PartitionEntry) {
    let _ = writeln!(out, "Active UNIX partition:");
    let _ = writeln!(
        out,
        "  index={} start={} sectors={} type={}",
        active.index,
        active.start_lba,
        active.sector_count,
        format_partition_type(active.partition_type),
    );
}

fn render_pdinfo(out: &mut String, pdinfo: &PdInfo) {
    let _ = writeln!(out, "pdinfo:");
    let _ = writeln!(out, "  sanity: 0x{:08x}", pdinfo.sanity);
    let _ = writeln!(
        out,
        "  geometry: {}/{}/{}",
        pdinfo.cylinders, pdinfo.tracks, pdinfo.sectors
    );
    let _ = writeln!(out, "  bytes/sector: {}", pdinfo.bytes_per_sector);
    let _ = writeln!(out, "  logical sector 0: {}", pdinfo.logical_sector_0);
    let _ = writeln!(out, "  vtoc ptr/len: {}/{}", pdinfo.vtoc_ptr, pdinfo.vtoc_len);
    let _ = writeln!(out, "  alt ptr/len: {}/{}", pdinfo.alt_ptr, pdinfo.alt_len);
}

fn render_vtoc(out: &mut String, vtoc: &VtocInfo) {
    let _ = writeln!(out, "VTOC:");
    let _ = writeln!(out, "  sanity: 0x{:08x}", vtoc.sanity);
    let _ = writeln!(out, "  version: {}", vtoc.version);
    let _ = writeln!(out, "  volume: {}", vtoc.volume);
    let _ = writeln!(out, "  partitions: {}", vtoc.partition_count);
    for partition in &vtoc.partitions {
        if partition.tag == 0 && partition.start_sector == 0 && partition.sector_count == 0 {
            continue;
        }
        let _ = writeln!(
            out,
            "  slice {}: tag={} flag=0x{:04x} start={} size={}",
            partition.index,
            partition_tag_name(partition.tag),
            partition.flag,
            partition.start_sector,
            partition.sector_count,
        );
    }
}

fn render_slice_filesystems(out: &mut String, slice_filesystems: &[SliceFilesystem]) {
    if slice_filesystems.is_empty() {
        return;
    }
    let _ = writeln!(out, "Slice filesystems:");
    for slice_info in slice_filesystems {
        let filesystem = slice_info.filesystem.as_deref().unwrap_or("unknown");
        let _ = writeln!(
            out,
            "  slice {}: tag={} fs={} start={} absolute_start={} size={}",
            slice_info.slice_index,
            partition_tag_name(slice_info.tag),
            filesystem,
            slice_info.start_sector,
            slice_info.absolute_start_sector,
            slice_info.sector_count,
        );
        for entry in slice_info.root_entries.iter().take(8) {
            let size_suffix = match entry.size {
                Some(size) => format!(" size={size}"),
                None => String::new(),
            };
            let _ = writeln!(out, "    {} inode={}{}", entry.name, entry.inode, size_suffix);
        }
    }
}

/// Render the full report exactly as `print_report` in cli.py does.
pub fn format_report(report: &DiskImageReport) -> String {
    let mut out = String::new();
    let _ = writeln!(out, "Image: {}", report.path);
    let _ = writeln!(out, "File size: {} bytes", report.file_size);
    render_partition_table(&mut out, &report.mbr);
    if let Some(active) = &report.active_unix_partition {
        render_active_partition(&mut out, active);
    }
    if let Some(pdinfo) = &report.pdinfo {
        render_pdinfo(&mut out, pdinfo);
    }
    if let Some(vtoc) = &report.vtoc {
        render_vtoc(&mut out, vtoc);
    }
    render_slice_filesystems(&mut out, &report.slice_filesystems);
    if !report.notes.is_empty() {
        let _ = writeln!(out, "Notes:");
        for note in &report.notes {
            let _ = writeln!(out, "  - {note}");
        }
    }
    out
}
