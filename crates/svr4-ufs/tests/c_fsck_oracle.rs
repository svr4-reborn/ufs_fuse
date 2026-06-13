//! The original SVR4 `fsck`, used as a format-independent oracle for the Rust
//! write path.
//!
//! This runs the recovered C `fsck` (the port in `host-tools/original-ufs-fsck`)
//! against a UFS root slice inside a real geometried disk image that the Rust
//! write path populated. A clean exit (0) is the strongest correctness gate we
//! have, since it shares no code with our reader/writer.
//!
//! ## How it finds the tool
//!
//! It invokes the fsck binary by name on `PATH` (default `svr4-ufs-fsck`,
//! overridable with the `SVR4_UFS_FSCK` env var pointing at a name or full path),
//! passing the slice's start sector with `--offset-sectors` and `--no` (read-only
//! check). This is so it keeps working once the original fsck is shipped as its
//! own packaged tool on `PATH` — there is no dependency on Python or an in-tree
//! build here.
//!
//! ## Why it is opt-in (gated on `SVR4_RUN_C_FSCK`)
//!
//! The C oracle is a "decently hacked-together" port (see its README) and has
//! reported a *pre-existing* discrepancy — `DUP I=2` plus a read past the slice
//! end — even on a pristine slice produced by the **Python**
//! `format_ufs_filesystem` (the reference formatter), an image that boots fine in
//! the real SVR4 VM. That discrepancy is in the formatter/oracle pair, not the
//! rewrite (the Python fsck-reimpl gate in `disk_populate_fsck.rs` is clean), so
//! the test is skipped unless `SVR4_RUN_C_FSCK=1` is set. It still encodes the
//! real acceptance criterion and gives a one-command way to check it:
//!
//! ```text
//! SVR4_RUN_C_FSCK=1 SVR4_UFS_FSCK=/path/to/svr4-ufs-fsck \
//!   cargo test -p svr4-ufs --test c_fsck_oracle -- --nocapture
//! ```
//!
//! Building the geometried test image still uses `python3` + the in-tree
//! `host-tools` package (the UFS formatter); only the oracle itself is the
//! external binary.

use std::path::{Path, PathBuf};
use std::process::Command;

use svr4_fs_core::consts::SECTOR_SIZE;
use svr4_fs_core::MappedImage;
use svr4_ufs::alloc::recompute_summary_counts;
use svr4_ufs::{create_file, detect_ufs_at_start, make_directory};

fn repo_root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .ancestors()
        .nth(3)
        .unwrap()
        .to_path_buf()
}

fn ufs_tool(host_tools: &Path, args: &[&str]) -> std::process::Output {
    let mut cmd = Command::new("python3");
    cmd.env("PYTHONPATH", host_tools)
        .arg(Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/ufs_tool.py"));
    for a in args {
        cmd.arg(a);
    }
    cmd.output().expect("run python3 ufs_tool.py")
}

#[test]
fn c_fsck_oracle_reports_rust_populated_slice_clean() {
    if std::env::var_os("SVR4_RUN_C_FSCK").is_none() {
        eprintln!(
            "SVR4_RUN_C_FSCK not set; skipping the C fsck oracle (it has reported a \
             pre-existing formatter/oracle discrepancy — see the module docs)"
        );
        return;
    }
    let host_tools = repo_root().join("host-tools");
    if !host_tools.join("host_tools").is_dir() {
        eprintln!("host-tools package not found; skipping");
        return;
    }
    let fsck_bin = std::env::var("SVR4_UFS_FSCK").unwrap_or_else(|_| "svr4-ufs-fsck".to_string());

    let dir = tempfile::tempdir().unwrap();
    let img = dir.path().join("disk.img");

    // Geometried disk image + formatted UFS root slice; capture the slice's
    // absolute byte offset.
    let blank = ufs_tool(&host_tools, &["disk-blank", img.to_str().unwrap()]);
    assert!(
        blank.status.success(),
        "disk-blank failed:\n{}",
        String::from_utf8_lossy(&blank.stderr)
    );
    let offset: u64 = String::from_utf8_lossy(&blank.stdout).trim().parse().unwrap();
    let start_sector = offset / SECTOR_SIZE as u64;

    // Populate the slice with the Rust write path.
    {
        let mut image = MappedImage::open(&img).unwrap();
        let ufs = detect_ufs_at_start(image.as_slice(), offset).unwrap();
        make_directory(image.as_mut_slice(), &ufs, "/dir", 0o755, 0, 0, 0).unwrap();
        create_file(image.as_mut_slice(), &ufs, "/dir/file", b"oracle\n", 0o644, 0, 0, 0).unwrap();
        recompute_summary_counts(image.as_mut_slice(), &ufs).unwrap();
        image.flush().unwrap();
    }

    // Run the original C fsck (read-only) against the root slice, located by its
    // start sector.
    let result = Command::new(&fsck_bin)
        .arg("--offset-sectors")
        .arg(start_sector.to_string())
        .arg("--no")
        .arg(&img)
        .output();
    let out = match result {
        Ok(out) => out,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
            eprintln!(
                "fsck oracle {fsck_bin:?} not found on PATH; skipping \
                 (set SVR4_UFS_FSCK to its path/name once it is installed)"
            );
            return;
        }
        Err(e) => panic!("failed to run {fsck_bin:?}: {e}"),
    };

    eprintln!("--- {fsck_bin} stdout ---\n{}", String::from_utf8_lossy(&out.stdout));
    eprintln!("--- {fsck_bin} stderr ---\n{}", String::from_utf8_lossy(&out.stderr));

    assert!(
        out.status.success(),
        "{fsck_bin} reported the slice unclean (exit {:?})",
        out.status.code()
    );
}
