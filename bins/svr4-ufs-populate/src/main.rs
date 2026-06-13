//! `svr4-ufs-populate` — copy a host directory tree into an SVR4 UFS slice
//! directly, with no FUSE mount and no rsync.
//!
//! This is the dependency-free, fast replacement for the build's
//! "mount over pyfuse3 + rsync the sysroot in" step. It memory-maps the image
//! (so a tens-of-gigabyte disk image is never read into RAM — only the touched
//! pages fault in) and writes the tree through the tested UFS write path:
//! directories, regular files, symlinks, and hard links (deduplicated by host
//! device/inode). Character/block device nodes are applied from a `--device-table`
//! file, so the build system can keep generating that table however it likes
//! (e.g. a stdlib-only Python script) without this tool depending on it.
//!
//! Owners default to root (0:0) — the sane default for a system image — unless
//! `--preserve-owner` is given. Permission bits are taken from the host.

use std::collections::HashMap;
use std::os::unix::fs::{FileTypeExt, MetadataExt};
use std::path::{Path, PathBuf};
use std::process::ExitCode;

use clap::Parser;

use svr4_disk::inspect::{get_vtoc_partition_by_selector, inspect_disk_image};
use svr4_disk::structures::SECTOR_SIZE;
use svr4_fs_core::consts::{UFS_IFBLK, UFS_IFCHR, UFS_ROOT_INODE};
use svr4_fs_core::MappedImage;
use svr4_ufs::alloc::recompute_summary_counts;
use svr4_ufs::{
    create_empty_in_parent, detect_ufs_at_start, link_in_parent, lookup_directory_entry,
    mkdir_in_parent, mknod_in_parent, read_inode, set_inode_contents, symlink_in_parent,
    UfsDetector, Ufs,
};

#[derive(Parser)]
#[command(about = "Populate an SVR4 UFS slice from a host directory tree (no FUSE, no rsync).")]
struct Cli {
    /// Disk or filesystem image to write into.
    image: PathBuf,
    /// Host directory whose contents become the slice's root.
    sysroot: PathBuf,
    /// Byte offset of the UFS slice within the image (default: auto-detect).
    #[arg(long, conflicts_with = "slice")]
    offset: Option<u64>,
    /// Slice to populate, by VTOC index or tag name (e.g. `1` or `root`).
    #[arg(long)]
    slice: Option<String>,
    /// Device-node table: lines of `path type major minor [octal-mode]`, where
    /// `type` is `c` (char) or `b` (block). `#` comments and blank lines ignored.
    #[arg(long)]
    device_table: Option<PathBuf>,
    /// Preserve host uid/gid instead of forcing root (0:0).
    #[arg(long)]
    preserve_owner: bool,
    /// Timestamp (epoch seconds) stamped on created inodes.
    #[arg(long, default_value_t = 0)]
    timestamp: u32,
}

struct Options {
    preserve_owner: bool,
    timestamp: u32,
}

fn main() -> ExitCode {
    let cli = Cli::parse();
    match run(&cli) {
        Ok(()) => ExitCode::SUCCESS,
        Err(message) => {
            eprintln!("{message}");
            ExitCode::FAILURE
        }
    }
}

fn run(cli: &Cli) -> Result<(), String> {
    if !cli.sysroot.is_dir() {
        return Err(format!("error: sysroot {} is not a directory", cli.sysroot.display()));
    }
    let mut image = MappedImage::open(&cli.image)
        .map_err(|e| format!("error: cannot open {}: {e}", cli.image.display()))?;
    let ufs = resolve_ufs(&cli.image, image.as_slice(), cli.offset, cli.slice.as_deref())?;

    let options = Options { preserve_owner: cli.preserve_owner, timestamp: cli.timestamp };
    let mut hardlinks: HashMap<(u64, u64), i64> = HashMap::new();

    populate_dir(
        image.as_mut_slice(),
        &ufs,
        &cli.sysroot,
        i64::from(UFS_ROOT_INODE),
        &options,
        &mut hardlinks,
    )?;

    if let Some(table) = &cli.device_table {
        apply_device_table(image.as_mut_slice(), &ufs, table, &options)?;
    }

    recompute_summary_counts(image.as_mut_slice(), &ufs)?;
    image.flush().map_err(|e| format!("error: msync failed: {e}"))?;
    Ok(())
}

/// Resolve the target UFS filesystem from `--offset`, `--slice`, or by
/// auto-detection (bare image at 0, else first UFS slice in the VTOC). Reads
/// only metadata + superblock pages, never the whole image.
fn resolve_ufs(
    image_path: &Path,
    image: &[u8],
    offset: Option<u64>,
    slice: Option<&str>,
) -> Result<Ufs, String> {
    if let Some(off) = offset {
        return detect_ufs_at_start(image, off)
            .ok_or_else(|| format!("error: no UFS superblock at offset {off}"));
    }
    if let Some(selector) = slice {
        let report = inspect_disk_image(image_path, &UfsDetector)
            .map_err(|e| format!("error: cannot inspect {}: {e}", image_path.display()))?;
        let partition = get_vtoc_partition_by_selector(&report, selector)?;
        let off = (partition.start_sector.max(0) as u64) * SECTOR_SIZE as u64;
        return detect_ufs_at_start(image, off).ok_or_else(|| {
            format!("error: slice '{selector}' (sector {}) is not UFS", partition.start_sector)
        });
    }
    if let Some(ufs) = detect_ufs_at_start(image, 0) {
        return Ok(ufs);
    }
    let report = inspect_disk_image(image_path, &UfsDetector)
        .map_err(|e| format!("error: cannot inspect {}: {e}", image_path.display()))?;
    let slice = report
        .slice_filesystems
        .iter()
        .find(|s| s.filesystem.as_deref() == Some("ufs"))
        .ok_or_else(|| format!("error: no UFS filesystem found in {}", image_path.display()))?;
    let off = (slice.absolute_start_sector.max(0) as u64) * SECTOR_SIZE as u64 + slice.filesystem_offset;
    detect_ufs_at_start(image, off).ok_or_else(|| "error: UFS slice vanished after detection".into())
}

fn owner(meta: &std::fs::Metadata, options: &Options) -> (u32, u32) {
    if options.preserve_owner {
        (meta.uid(), meta.gid())
    } else {
        (0, 0)
    }
}

/// Recursively copy the contents of `host_dir` into the UFS directory inode
/// `parent_ino`. Entries are processed in sorted order for determinism.
fn populate_dir(
    image: &mut [u8],
    ufs: &Ufs,
    host_dir: &Path,
    parent_ino: i64,
    options: &Options,
    hardlinks: &mut HashMap<(u64, u64), i64>,
) -> Result<(), String> {
    let mut entries: Vec<_> = std::fs::read_dir(host_dir)
        .map_err(|e| format!("error: cannot read {}: {e}", host_dir.display()))?
        .collect::<Result<_, _>>()
        .map_err(|e| format!("error: reading {}: {e}", host_dir.display()))?;
    entries.sort_by_key(|e| e.file_name());

    for entry in entries {
        let path = entry.path();
        let name = match entry.file_name().into_string() {
            Ok(n) => n,
            Err(_) => {
                eprintln!("warning: skipping non-UTF-8 name in {}", host_dir.display());
                continue;
            }
        };
        let meta = std::fs::symlink_metadata(&path)
            .map_err(|e| format!("error: stat {}: {e}", path.display()))?;
        let ft = meta.file_type();
        let perm = meta.mode() & 0o7777;
        let (uid, gid) = owner(&meta, options);
        let ts = options.timestamp;

        if ft.is_dir() {
            let ino = mkdir_in_parent(image, ufs, parent_ino, &name, perm, uid, gid, ts)?;
            populate_dir(image, ufs, &path, ino, options, hardlinks)?;
        } else if ft.is_symlink() {
            let target = std::fs::read_link(&path)
                .map_err(|e| format!("error: readlink {}: {e}", path.display()))?;
            let target = target
                .to_str()
                .ok_or_else(|| format!("error: non-UTF-8 symlink target at {}", path.display()))?;
            symlink_in_parent(image, ufs, parent_ino, &name, target, 0o777, uid, gid, ts)?;
        } else if ft.is_file() {
            let key = (meta.dev(), meta.ino());
            if meta.nlink() > 1 {
                if let Some(&existing) = hardlinks.get(&key) {
                    link_in_parent(image, ufs, parent_ino, &name, existing)?;
                    continue;
                }
            }
            let data = std::fs::read(&path).map_err(|e| format!("error: read {}: {e}", path.display()))?;
            let ino = create_empty_in_parent(image, ufs, parent_ino, &name, perm, uid, gid, ts)?;
            set_inode_contents(image, ufs, ino, &data)?;
            if meta.nlink() > 1 {
                hardlinks.insert(key, ino);
            }
        } else if ft.is_block_device() || ft.is_char_device() {
            // Honour device nodes already present in the tree (e.g. a fakeroot
            // sysroot). rdev decoding uses the Linux gnu_dev split.
            let rdev = meta.rdev();
            let (major, minor) = split_rdev(rdev);
            let kind = if ft.is_block_device() { UFS_IFBLK } else { UFS_IFCHR };
            mknod_in_parent(image, ufs, parent_ino, &name, kind, major, minor, perm, uid, gid, ts)?;
        } else {
            eprintln!("warning: skipping unsupported file type at {}", path.display());
        }
    }
    Ok(())
}

/// Decode a Linux `dev_t` into (major, minor) per glibc's `gnu_dev_*`.
fn split_rdev(rdev: u64) -> (u32, u32) {
    let major = (((rdev >> 8) & 0xfff) | ((rdev >> 32) & !0xfff)) as u32;
    let minor = ((rdev & 0xff) | ((rdev >> 12) & !0xff)) as u32;
    (major, minor)
}

/// Ensure every directory component of `path` exists, creating missing ones as
/// 0755 root-owned directories, and return `(parent_inode, final_name)`.
fn ensure_parent_dirs(image: &mut [u8], ufs: &Ufs, path: &str, ts: u32) -> Result<(i64, String), String> {
    let components: Vec<&str> = path.split('/').filter(|c| !c.is_empty()).collect();
    if components.is_empty() {
        return Err(format!("error: invalid device path {path:?}"));
    }
    let mut cur = i64::from(UFS_ROOT_INODE);
    for comp in &components[..components.len() - 1] {
        let parent = read_inode(image, ufs, cur)
            .ok_or_else(|| format!("error: inode {cur} unreadable while resolving {path:?}"))?;
        match lookup_directory_entry(image, ufs, &parent, comp) {
            Some((n, inode)) => {
                if !inode.is_directory() {
                    return Err(format!("error: {comp:?} in {path:?} is not a directory"));
                }
                cur = n as i64;
            }
            None => {
                cur = mkdir_in_parent(image, ufs, cur, comp, 0o755, 0, 0, ts)?;
            }
        }
    }
    Ok((cur, components[components.len() - 1].to_string()))
}

fn apply_device_table(
    image: &mut [u8],
    ufs: &Ufs,
    table: &Path,
    options: &Options,
) -> Result<(), String> {
    let text = std::fs::read_to_string(table)
        .map_err(|e| format!("error: cannot read device table {}: {e}", table.display()))?;
    for (lineno, raw) in text.lines().enumerate() {
        let line = raw.split('#').next().unwrap_or("").trim();
        if line.is_empty() {
            continue;
        }
        let fields: Vec<&str> = line.split_whitespace().collect();
        if fields.len() < 4 {
            return Err(format!(
                "error: {}:{}: expected `path type major minor [mode]`",
                table.display(),
                lineno + 1
            ));
        }
        let dev_path = fields[0];
        let kind = match fields[1] {
            "c" => UFS_IFCHR,
            "b" => UFS_IFBLK,
            other => {
                return Err(format!(
                    "error: {}:{}: device type must be `c` or `b`, got {other:?}",
                    table.display(),
                    lineno + 1
                ))
            }
        };
        let major = parse_num(fields[2], table, lineno)?;
        let minor = parse_num(fields[3], table, lineno)?;
        let mode = if let Some(m) = fields.get(4) {
            u32::from_str_radix(m.trim_start_matches("0o"), 8)
                .map_err(|_| format!("error: {}:{}: bad mode {m:?}", table.display(), lineno + 1))?
        } else {
            0o600
        };
        let (parent, name) = ensure_parent_dirs(image, ufs, dev_path, options.timestamp)?;
        mknod_in_parent(image, ufs, parent, &name, kind, major, minor, mode, 0, 0, options.timestamp)?;
    }
    Ok(())
}

fn parse_num(value: &str, table: &Path, lineno: usize) -> Result<u32, String> {
    let parsed = if let Some(hex) = value.strip_prefix("0x") {
        u32::from_str_radix(hex, 16)
    } else {
        value.parse::<u32>()
    };
    parsed.map_err(|_| format!("error: {}:{}: invalid number {value:?}", table.display(), lineno + 1))
}
