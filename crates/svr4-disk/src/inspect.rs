//! Disk image inspection. Port of `host_tools/disk/inspect.py` (metadata path)
//! and the selector/trace helpers.
//!
//! Filesystem detection is abstracted behind [`FsDetector`] so the disk crate
//! has no dependency on the UFS/BFS crates. Phase 1 ships [`NullDetector`]
//! (every slice reports `filesystem: None`), which is correct for blank
//! skeleton images; Phase 2 supplies a real UFS detector.

use std::fs::File;
use std::io::{self, Read, Seek, SeekFrom};
use std::path::Path;

use svr4_fs_core::MappedImageRo;

use crate::mbr::parse_mbr_sector;
use crate::structures::{
    DiskImageReport, MbrInfo, PartitionEntry, PdInfo, RootEntry, SliceFilesystem, VtocInfo,
    VtocPartition, HDPDLOC, SECTOR_SIZE, UNIXWARE_PARTITION_TYPE,
};
use crate::svr4::{
    is_valid_alt_info, is_valid_pdinfo, is_valid_vtoc, parse_alt_info, parse_pdinfo, parse_vtoc,
    partition_tag_name, remap_guest_visible_sector,
};
use crate::structures::AltInfo;

/// A filesystem detected inside a slice.
pub struct DetectedFs {
    pub filesystem: String,
    pub filesystem_offset: u64,
    pub root_entries: Vec<RootEntry>,
}

/// Pluggable filesystem detection. Implemented by the FS crates from Phase 2.
pub trait FsDetector {
    /// Probe the raw bytes of a slice; return the detected filesystem, if any.
    fn probe(&self, slice_bytes: &[u8]) -> Option<DetectedFs>;

    /// Whether this detector needs the slice bytes read in. A detector that can
    /// never match (e.g. [`NullDetector`]) returns `false` so the inspector
    /// skips reading potentially huge slices — the result is identical to
    /// reading them and getting `None`.
    fn reads_slices(&self) -> bool {
        true
    }
}

/// Detector that finds nothing — the Phase 1 default.
pub struct NullDetector;

impl FsDetector for NullDetector {
    fn probe(&self, _slice_bytes: &[u8]) -> Option<DetectedFs> {
        None
    }

    fn reads_slices(&self) -> bool {
        false
    }
}

pub fn find_active_unix_partition(mbr: &MbrInfo) -> Option<PartitionEntry> {
    mbr.partitions
        .iter()
        .find(|p| p.bootable && p.partition_type == UNIXWARE_PARTITION_TYPE)
        .or_else(|| {
            mbr.partitions
                .iter()
                .find(|p| p.partition_type == UNIXWARE_PARTITION_TYPE)
        })
        .cloned()
}

pub fn read_sector(image_path: &Path, sector_number: u64, sector_count: u64) -> io::Result<Vec<u8>> {
    let mut handle = File::open(image_path)?;
    handle.seek(SeekFrom::Start(sector_number * SECTOR_SIZE as u64))?;
    let mut buf = vec![0u8; (sector_count * SECTOR_SIZE as u64) as usize];
    let read = read_up_to(&mut handle, &mut buf)?;
    buf.truncate(read);
    Ok(buf)
}

/// Read as many bytes as the file has, like Python's `handle.read(n)` (which
/// returns a short buffer at EOF rather than erroring).
fn read_up_to(handle: &mut File, buf: &mut [u8]) -> io::Result<usize> {
    let mut total = 0;
    while total < buf.len() {
        match handle.read(&mut buf[total..]) {
            Ok(0) => break,
            Ok(n) => total += n,
            Err(ref e) if e.kind() == io::ErrorKind::Interrupted => continue,
            Err(e) => return Err(e),
        }
    }
    Ok(total)
}

pub fn read_pdinfo(image_path: &Path, partition_start: u64) -> io::Result<PdInfo> {
    Ok(parse_pdinfo(&read_sector(
        image_path,
        partition_start + HDPDLOC,
        1,
    )?))
}

pub fn read_vtoc(image_path: &Path, partition_start: u64, pdinfo: &PdInfo) -> io::Result<VtocInfo> {
    let vtoc_sector = partition_start + (pdinfo.vtoc_ptr as u64 / SECTOR_SIZE as u64);
    let vtoc_offset = pdinfo.vtoc_ptr as u64 % SECTOR_SIZE as u64;
    let vtoc_span = (pdinfo.vtoc_len as u64).max(SECTOR_SIZE as u64);
    let sector_count = 1.max((vtoc_offset + vtoc_span).div_ceil(SECTOR_SIZE as u64));
    let block = read_sector(image_path, vtoc_sector, sector_count)?;
    Ok(parse_vtoc(&block, vtoc_offset as usize))
}

pub fn read_alt_info(
    image_path: &Path,
    partition_start: u64,
    pdinfo: &PdInfo,
) -> io::Result<Option<AltInfo>> {
    if pdinfo.alt_len == 0 {
        return Ok(None);
    }
    let alt_sector = partition_start + (pdinfo.alt_ptr as u64 / SECTOR_SIZE as u64);
    let alt_offset = pdinfo.alt_ptr as u64 % SECTOR_SIZE as u64;
    let alt_span = (pdinfo.alt_len as u64).max(SECTOR_SIZE as u64);
    let sector_count = 1.max((alt_offset + alt_span).div_ceil(SECTOR_SIZE as u64));
    let block = read_sector(image_path, alt_sector, sector_count)?;
    let alt_info = parse_alt_info(&block, alt_offset as usize);
    if !is_valid_alt_info(&alt_info) {
        return Ok(None);
    }
    Ok(Some(alt_info))
}

pub fn absolute_sector_for_slice(_pdinfo: &PdInfo, slice_start_sector: i64) -> i64 {
    slice_start_sector
}

/// Inspect a disk image, probing each slice with `detector`.
///
/// With [`NullDetector`] this matches the Python `inspect_disk_metadata`
/// (slices listed, no filesystem). With a real detector it matches
/// `inspect_disk_image`.
pub fn inspect_disk_image(
    image_path: &Path,
    detector: &dyn FsDetector,
) -> io::Result<DiskImageReport> {
    let image_path = image_path.canonicalize()?;
    let file_size = std::fs::metadata(&image_path)?.len();
    let mut notes: Vec<String> = Vec::new();

    let mbr = parse_mbr_sector(&read_sector(&image_path, 0, 1)?);
    if mbr.signature != 0xAA55 {
        notes.push(format!(
            "Unexpected MBR signature 0x{:04x}; image may be unpartitioned or use a non-MBR boot sector.",
            mbr.signature
        ));
    }

    let active_unix_partition = find_active_unix_partition(&mbr);
    let mut pdinfo = None;
    let mut vtoc = None;
    let mut slice_filesystems: Vec<SliceFilesystem> = Vec::new();

    match &active_unix_partition {
        None => notes.push("No UNIX partition (type 0x63) was found in the MBR.".into()),
        Some(active) => {
            let pd = read_pdinfo(&image_path, active.start_lba as u64)?;
            if !is_valid_pdinfo(&pd) {
                notes.push(format!(
                    "Invalid pdinfo sanity 0x{:08x} at sector {}; expected 0x{:08x}.",
                    pd.sanity,
                    active.start_lba as u64 + HDPDLOC,
                    0xCA5E_600Du32
                ));
            } else {
                let vt = read_vtoc(&image_path, active.start_lba as u64, &pd)?;
                if !is_valid_vtoc(&vt) {
                    notes.push(format!(
                        "Invalid VTOC sanity 0x{:08x}; expected 0x{:08x}.",
                        vt.sanity, 0x600D_DEEEu32
                    ));
                } else {
                    // Map the image read-only *once* so slice probing reads only
                    // the superblock/root-dir pages it touches — never the whole
                    // (potentially multi-gigabyte) slice into RAM. Skipped when
                    // the detector reads nothing (e.g. `NullDetector`).
                    let slice_map = if detector.reads_slices() && file_size > 0 {
                        Some(MappedImageRo::open(&image_path)?)
                    } else {
                        None
                    };
                    let slice_view = slice_map.as_ref().map(|m| m.as_slice());
                    for partition in &vt.partitions {
                        if partition.tag == 0 || partition.sector_count <= 0 {
                            continue;
                        }
                        let absolute_start_sector =
                            absolute_sector_for_slice(&pd, partition.start_sector);
                        slice_filesystems.push(probe_slice(
                            slice_view,
                            partition,
                            absolute_start_sector,
                            detector,
                        ));
                    }
                }
                vtoc = Some(vt);
            }
            pdinfo = Some(pd);
        }
    }

    Ok(DiskImageReport {
        path: image_path.to_string_lossy().into_owned(),
        file_size,
        mbr,
        active_unix_partition,
        pdinfo,
        vtoc,
        slice_filesystems,
        notes,
    })
}

/// Probe a single slice for a filesystem. `image` is a read-only memory map of
/// the whole disk image (or `None` when the detector reads nothing); the slice
/// is a sub-range of it, so the detector only faults in the pages it actually
/// reads — no whole-slice copy.
fn probe_slice(
    image: Option<&[u8]>,
    partition: &VtocPartition,
    absolute_start_sector: i64,
    detector: &dyn FsDetector,
) -> SliceFilesystem {
    let detected = image.and_then(|whole| {
        let start = (absolute_start_sector as u64).saturating_mul(SECTOR_SIZE as u64) as usize;
        let span = (partition.sector_count as u64).saturating_mul(SECTOR_SIZE as u64) as usize;
        // Clamp to the file: a slice may be declared larger than the image is
        // actually allocated (sparse/truncated images).
        let end = start.saturating_add(span).min(whole.len());
        if start >= end {
            return None;
        }
        detector.probe(&whole[start..end])
    });

    let (filesystem, filesystem_offset, root_entries) = match detected {
        Some(d) => (Some(d.filesystem), d.filesystem_offset, d.root_entries),
        None => (None, 0, Vec::new()),
    };

    SliceFilesystem {
        slice_index: partition.index,
        tag: partition.tag,
        start_sector: partition.start_sector,
        absolute_start_sector,
        sector_count: partition.sector_count,
        filesystem,
        filesystem_offset,
        root_entries,
    }
}

/// Convenience matching the Python `inspect_disk_metadata` (no FS probing).
pub fn inspect_disk_metadata(image_path: &Path) -> io::Result<DiskImageReport> {
    inspect_disk_image(image_path, &NullDetector)
}

pub fn get_vtoc_partition_by_selector(
    report: &DiskImageReport,
    selector: &str,
) -> Result<VtocPartition, String> {
    let Some(vtoc) = &report.vtoc else {
        return Err("error: image does not contain a valid VTOC".into());
    };
    let normalized = selector.trim().to_lowercase();
    if let Some(p) = vtoc
        .partitions
        .iter()
        .find(|p| p.index.to_string() == normalized)
    {
        return Ok(p.clone());
    }
    if let Some(p) = vtoc
        .partitions
        .iter()
        .find(|p| partition_tag_name(p.tag) == normalized)
    {
        return Ok(p.clone());
    }
    Err(format!("error: no slice matching '{selector}' was found"))
}

/// Resolve a slice-relative sector through the guest-visible (alternates) path.
/// Returns `(absolute_sector, guest_visible_sector, sector_bytes)`.
pub fn resolve_guest_visible_sector(
    image_path: &Path,
    selector: &str,
    slice_relative_sector: i64,
    detector: &dyn FsDetector,
) -> Result<(i64, i64, Vec<u8>), String> {
    let report = inspect_disk_image(image_path, detector).map_err(|e| format!("error: {e}"))?;
    let (Some(active), Some(pdinfo)) = (&report.active_unix_partition, &report.pdinfo) else {
        return Err("error: image does not contain a valid active UNIX partition".into());
    };
    let partition = get_vtoc_partition_by_selector(&report, selector)?;
    let absolute_sector = partition.start_sector + slice_relative_sector;
    let alt_info = read_alt_info(image_path, active.start_lba as u64, pdinfo)
        .map_err(|e| format!("error: {e}"))?;
    let guest_visible_sector =
        remap_guest_visible_sector(pdinfo, &partition, alt_info.as_ref(), absolute_sector);
    let data = read_sector(image_path, guest_visible_sector as u64, 1)
        .map_err(|e| format!("error: {e}"))?;
    Ok((absolute_sector, guest_visible_sector, data))
}
