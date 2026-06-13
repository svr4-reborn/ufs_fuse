//! `svr4-disk-image` — inspect and construct raw SVR4 disk images.
//!
//! Rust port of `host_tools/disk/cli.py` (Phase 1). Command names, flags, and
//! output formatting match the Python tool so it is a drop-in replacement. The
//! `format-bfs` subcommand formats the `/stand` (BFS) slice with boot files.

use std::path::{Path, PathBuf};
use std::process::ExitCode;

use clap::{Args, Parser, Subcommand};
use svr4_bfs::BfsDetector;
use svr4_disk::create::{
    create_raw_image_skeleton, RawDiskGeometry, DISK_ADDRESSING_CHS, DISK_ADDRESSING_LBA28,
};
use svr4_disk::inspect::{
    get_vtoc_partition_by_selector, inspect_disk_image, resolve_guest_visible_sector, DetectedFs,
    FsDetector,
};
use svr4_disk::report::format_report;
use svr4_disk::structures::{VtocPartition, SECTOR_SIZE};
use svr4_disk::svr4::PARTITION_TAG_NAMES;
use svr4_fs_core::MappedImage;
use svr4_ufs::{format as format_ufs_slice, FormatOptions, UfsDetector};

/// Filesystem detector that tries UFS first, then BFS — so `inspect` recognises
/// both the root (UFS) and `/stand` (BFS) slices of a real image.
struct AnyDetector;

impl FsDetector for AnyDetector {
    fn probe(&self, slice_bytes: &[u8]) -> Option<DetectedFs> {
        UfsDetector.probe(slice_bytes).or_else(|| BfsDetector.probe(slice_bytes))
    }
}

#[derive(Parser)]
#[command(about = "Inspect raw SVR4 disk images for host-side tooling.")]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    /// Inspect a raw disk image.
    Inspect {
        /// Path to the disk image to inspect.
        image: PathBuf,
        /// Emit machine-readable JSON.
        #[arg(long)]
        json: bool,
    },
    /// Create a raw image with MBR, pdinfo, and VTOC metadata.
    CreateSkeleton(CreateSkeletonArgs),
    /// Resolve a slice-relative sector through the guest-visible disk path and
    /// print a small fingerprint.
    TraceSector {
        /// Path to the disk image to inspect.
        image: PathBuf,
        /// Slice index or tag name, for example 1 or root.
        #[arg(long)]
        slice: String,
        /// Slice-relative sector number to resolve.
        #[arg(long)]
        sector: i64,
        /// Emit machine-readable JSON.
        #[arg(long)]
        json: bool,
    },
    /// Format the BFS `/stand` slice with a set of boot files.
    FormatBfs(FormatBfsArgs),
    /// Format a slice as an empty UFS filesystem.
    FormatUfs(FormatUfsArgs),
}

#[derive(Args)]
struct FormatUfsArgs {
    /// Disk image containing the slice to format.
    image: PathBuf,
    /// Slice to format, by VTOC index or tag name (e.g. `1` or `root`).
    #[arg(long)]
    slice: String,
    /// UFS block size in bytes (4096 or 8192).
    #[arg(long = "block-size", default_value_t = 8192)]
    block_size: u64,
    /// Bytes per inode (controls how many inodes are reserved).
    #[arg(long = "bytes-per-inode", default_value_t = 8192)]
    bytes_per_inode: u64,
    /// Timestamp (epoch seconds) stamped into the superblock and root inode.
    #[arg(long, default_value_t = 0)]
    timestamp: u32,
}

#[derive(Args)]
struct FormatBfsArgs {
    /// Disk image containing the BFS slice.
    image: PathBuf,
    /// Slice to format, by VTOC index or tag name (e.g. `10` or `stand`).
    #[arg(long)]
    slice: String,
    /// A root file to write, as `NAME=HOST_PATH` (repeatable). NAME is the BFS
    /// entry name (max 14 chars, no `/`).
    #[arg(long = "file")]
    files: Vec<String>,
    /// Timestamp (epoch seconds) stamped on the BFS inodes.
    #[arg(long, default_value_t = 0)]
    timestamp: i32,
}

#[derive(Args)]
struct CreateSkeletonArgs {
    /// Output raw image path.
    #[arg(long)]
    output: PathBuf,
    #[arg(long)]
    cylinders: u32,
    #[arg(long)]
    heads: u32,
    /// Sectors per track.
    #[arg(long)]
    sectors: u32,
    #[arg(long = "unix-partition-start", default_value_t = 1)]
    unix_partition_start: u32,
    /// Size of the UNIX partition in sectors. Defaults to the rest of the disk.
    #[arg(long = "unix-partition-size")]
    unix_partition_size: Option<u32>,
    /// Disk addressing mode for validation and MBR CHS fields.
    #[arg(long = "disk-addressing", default_value = DISK_ADDRESSING_CHS,
          value_parser = [DISK_ADDRESSING_CHS, DISK_ADDRESSING_LBA28])]
    disk_addressing: String,
    #[arg(long, default_value = "SVR4")]
    volume: String,
    /// Slice definition as index:tag:start:size:flag where start is an absolute
    /// disk sector and tag may be numeric or a known name like root, swap,
    /// stand, boot, backup, alts.
    #[arg(long = "slice")]
    slices: Vec<String>,
}

/// Parse an integer the way Python's `int(value, 0)` does: `0x`/`0o`/`0b`
/// prefixes select the radix, otherwise decimal.
fn parse_int_auto(value: &str) -> Result<i64, String> {
    let v = value.trim();
    let (neg, body) = match v.strip_prefix('-') {
        Some(rest) => (true, rest),
        None => (false, v),
    };
    let parsed = if let Some(hex) = body.strip_prefix("0x").or_else(|| body.strip_prefix("0X")) {
        i64::from_str_radix(hex, 16)
    } else if let Some(oct) = body.strip_prefix("0o").or_else(|| body.strip_prefix("0O")) {
        i64::from_str_radix(oct, 8)
    } else if let Some(bin) = body.strip_prefix("0b").or_else(|| body.strip_prefix("0B")) {
        i64::from_str_radix(bin, 2)
    } else {
        body.parse::<i64>()
    };
    parsed
        .map(|n| if neg { -n } else { n })
        .map_err(|_| format!("error: invalid integer {value:?}"))
}

/// Resolve a tag name or numeric tag, mirroring `parse_tag`.
fn parse_tag(value: &str) -> Result<u16, String> {
    let lower = value.to_lowercase();
    if let Some((tag_number, _)) = PARTITION_TAG_NAMES.iter().find(|(_, name)| *name == lower) {
        return Ok(*tag_number);
    }
    Ok(parse_int_auto(value)? as u16)
}

fn parse_slice_definition(value: &str) -> Result<VtocPartition, String> {
    let parts: Vec<&str> = value.split(':').collect();
    if parts.len() != 5 {
        return Err(format!(
            "error: invalid slice definition {value:?}; expected index:tag:start:size:flag"
        ));
    }
    Ok(VtocPartition {
        index: parse_int_auto(parts[0])? as u32,
        tag: parse_tag(parts[1])?,
        start_sector: parse_int_auto(parts[2])?,
        sector_count: parse_int_auto(parts[3])?,
        flag: parse_int_auto(parts[4])? as u16,
    })
}

fn sector_fingerprint(data: &[u8]) -> (usize, String, String) {
    let preview = &data[..data.len().min(32)];
    let hex_preview = preview.iter().map(|b| format!("{b:02x}")).collect();
    let ascii_preview = preview
        .iter()
        .map(|&b| if (32..127).contains(&b) { b as char } else { '.' })
        .collect();
    (data.len(), hex_preview, ascii_preview)
}

fn run() -> Result<(), String> {
    let cli = Cli::parse();
    match cli.command {
        Command::Inspect { image, json } => {
            let report = inspect_disk_image(&image, &AnyDetector).map_err(|e| format!("error: {e}"))?;
            if json {
                println!(
                    "{}",
                    serde_json::to_string_pretty(&report).map_err(|e| format!("error: {e}"))?
                );
            } else {
                print!("{}", format_report(&report));
            }
            Ok(())
        }
        Command::CreateSkeleton(args) => create_skeleton(args),
        Command::FormatBfs(args) => format_bfs(args),
        Command::FormatUfs(args) => format_ufs(args),
        Command::TraceSector {
            image,
            slice,
            sector,
            json,
        } => {
            let (absolute_sector, guest_visible_sector, data) =
                resolve_guest_visible_sector(&image, &slice, sector, &AnyDetector)?;
            let (size, hex_preview, ascii_preview) = sector_fingerprint(&data);
            if json {
                let payload = serde_json::json!({
                    "slice": slice,
                    "slice_relative_sector": sector,
                    "absolute_sector": absolute_sector,
                    "guest_visible_sector": guest_visible_sector,
                    "fingerprint": {
                        "size": size,
                        "hex_preview": hex_preview,
                        "ascii_preview": ascii_preview,
                    },
                });
                println!(
                    "{}",
                    serde_json::to_string_pretty(&payload).map_err(|e| format!("error: {e}"))?
                );
            } else {
                println!("slice={slice} sector={sector}");
                println!("absolute_sector={absolute_sector}");
                println!("guest_visible_sector={guest_visible_sector}");
                println!("size={size}");
                println!("hex_preview={hex_preview}");
                println!("ascii_preview={ascii_preview}");
            }
            Ok(())
        }
    }
}

fn create_skeleton(args: CreateSkeletonArgs) -> Result<(), String> {
    let geometry = RawDiskGeometry {
        cylinders: args.cylinders,
        heads: args.heads,
        sectors_per_track: args.sectors,
    };
    let unix_partition_size = args.unix_partition_size.unwrap_or_else(|| {
        (geometry.total_sectors() as u32).saturating_sub(args.unix_partition_start)
    });
    let slices = args
        .slices
        .iter()
        .map(|s| parse_slice_definition(s))
        .collect::<Result<Vec<_>, _>>()?;
    let output = absolutize(&args.output);
    create_raw_image_skeleton(
        &output,
        &geometry,
        args.unix_partition_start,
        unix_partition_size,
        &args.volume,
        &slices,
        None,
        &args.disk_addressing,
    )?;
    println!("Created raw disk skeleton at {}", output.display());
    Ok(())
}

fn format_bfs(args: FormatBfsArgs) -> Result<(), String> {
    // Locate the slice via the VTOC (reads only metadata, not the whole image).
    let report = inspect_disk_image(&args.image, &AnyDetector).map_err(|e| format!("error: {e}"))?;
    let partition = get_vtoc_partition_by_selector(&report, &args.slice)?;
    let offset = (partition.start_sector.max(0) as u64) * SECTOR_SIZE as u64;
    let size = (partition.sector_count.max(0) as u64) * SECTOR_SIZE as u64;
    if size == 0 {
        return Err(format!("error: slice '{}' has zero length", args.slice));
    }

    // Read each NAME=HOST_PATH file into memory (BFS /stand files are small).
    let mut owned: Vec<(String, Vec<u8>)> = Vec::new();
    for spec in &args.files {
        let (name, host_path) = spec
            .split_once('=')
            .ok_or_else(|| format!("error: --file expects NAME=HOST_PATH, got {spec:?}"))?;
        let data = std::fs::read(host_path)
            .map_err(|e| format!("error: cannot read {host_path}: {e}"))?;
        owned.push((name.to_string(), data));
    }
    let files: Vec<(&str, &[u8])> = owned.iter().map(|(n, d)| (n.as_str(), d.as_slice())).collect();

    let mut image = MappedImage::open(&args.image)
        .map_err(|e| format!("error: cannot open {}: {e}", args.image.display()))?;
    svr4_bfs::format(image.as_mut_slice(), offset, size as usize, &files, None, args.timestamp)?;
    image
        .flush_range(offset as usize, size as usize)
        .map_err(|e| format!("error: msync failed: {e}"))?;
    println!(
        "Formatted BFS slice '{}' ({} file(s)) at byte offset {offset}",
        args.slice,
        files.len()
    );
    Ok(())
}

fn format_ufs(args: FormatUfsArgs) -> Result<(), String> {
    let report = inspect_disk_image(&args.image, &AnyDetector).map_err(|e| format!("error: {e}"))?;
    let partition = get_vtoc_partition_by_selector(&report, &args.slice)?;
    let pdinfo = report
        .pdinfo
        .as_ref()
        .ok_or("error: image has no valid pdinfo; cannot determine disk geometry")?;
    let offset = (partition.start_sector.max(0) as u64) * SECTOR_SIZE as u64;
    let size = (partition.sector_count.max(0) as u64) * SECTOR_SIZE as u64;
    if size == 0 {
        return Err(format!("error: slice '{}' has zero length", args.slice));
    }

    let opts = FormatOptions {
        timestamp: args.timestamp,
        block_size: args.block_size,
        bytes_per_inode: args.bytes_per_inode,
        tracks_per_cylinder: Some(pdinfo.tracks),
        sectors_per_track: Some(pdinfo.sectors),
    };
    let mut image = MappedImage::open(&args.image)
        .map_err(|e| format!("error: cannot open {}: {e}", args.image.display()))?;
    format_ufs_slice(image.as_mut_slice(), offset, size, &opts)?;
    image
        .flush_range(offset as usize, size as usize)
        .map_err(|e| format!("error: msync failed: {e}"))?;
    println!("Formatted UFS slice '{}' at byte offset {offset} ({size} bytes)", args.slice);
    Ok(())
}

/// Resolve a path to absolute without requiring it to exist (unlike
/// `canonicalize`), matching Python's `Path(...).resolve()` for new files.
fn absolutize(path: &Path) -> PathBuf {
    if path.is_absolute() {
        path.to_path_buf()
    } else {
        std::env::current_dir()
            .map(|cwd| cwd.join(path))
            .unwrap_or_else(|_| path.to_path_buf())
    }
}

fn main() -> ExitCode {
    match run() {
        Ok(()) => ExitCode::SUCCESS,
        Err(message) => {
            eprintln!("{message}");
            ExitCode::FAILURE
        }
    }
}
