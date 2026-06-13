//! Differential gate: the Rust UFS formatter must be byte-for-byte identical to
//! the Python reference `build_ufs_filesystem_image` for the same parameters.
//!
//! Covers both layouts: a bare image (no geometry, single synthetic cylinder)
//! and a geometried slice (multiple cylinder groups).
//!
//! Needs `python3` + the in-tree `host-tools` package; skip with
//! `SVR4_SKIP_PYTHON_DIFF=1`.

use std::path::{Path, PathBuf};
use std::process::Command;

use svr4_ufs::{format, FormatOptions};

fn repo_root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).ancestors().nth(3).unwrap().to_path_buf()
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

fn check_match(label: &str, size: u64, opts: FormatOptions, py_args: &[&str]) {
    let host_tools = repo_root().join("host-tools");
    let dir = tempfile::tempdir().unwrap();
    let py_out = dir.path().join("py.img");

    let mut args = vec!["format-raw", py_out.to_str().unwrap()];
    args.extend_from_slice(py_args);
    let out = ufs_tool(&host_tools, &args);
    assert!(out.status.success(), "{label}: format-raw failed:\n{}", String::from_utf8_lossy(&out.stderr));
    let python_image = std::fs::read(&py_out).unwrap();
    assert_eq!(python_image.len() as u64, size, "{label}: size");

    let mut rust_image = vec![0u8; size as usize];
    format(&mut rust_image, 0, size, &opts).unwrap();

    if rust_image != python_image {
        let first = rust_image
            .iter()
            .zip(&python_image)
            .position(|(a, b)| a != b)
            .unwrap();
        panic!(
            "{label}: Rust formatter differs from Python at byte {first} \
             (rust=0x{:02x} python=0x{:02x})",
            rust_image[first], python_image[first]
        );
    }
}

#[test]
fn rust_formatter_matches_python_byte_for_byte() {
    if std::env::var_os("SVR4_SKIP_PYTHON_DIFF").is_some() {
        eprintln!("SVR4_SKIP_PYTHON_DIFF set; skipping");
        return;
    }
    let host_tools = repo_root().join("host-tools");
    if !host_tools.join("host_tools").is_dir() {
        eprintln!("host-tools package not found; skipping");
        return;
    }
    if Command::new("python3").arg("--version").output().is_err() {
        eprintln!("python3 not available; skipping");
        return;
    }

    // Bare 8 MiB image, 4 KiB blocks (matches `ufs_tool.py blank`).
    check_match(
        "bare-8MiB-4k",
        8 * 1024 * 1024,
        FormatOptions { block_size: 4096, ..FormatOptions::default() },
        &["8388608", "4096", "8192"],
    );

    // Bare 16 MiB image, 8 KiB blocks (the Python default block size).
    check_match(
        "bare-16MiB-8k",
        16 * 1024 * 1024,
        FormatOptions { block_size: 8192, ..FormatOptions::default() },
        &["16777216", "8192", "8192"],
    );

    // Geometried slice: heads=4, sectors=17 → 68 sectors/cyl, 512 cylinders
    // (17 MiB) → several cylinder groups.
    let spc = 4 * 17u64;
    let size = 512 * spc * 512;
    check_match(
        "geometry-4x17-512cyl",
        size,
        FormatOptions {
            block_size: 4096,
            bytes_per_inode: 8192,
            tracks_per_cylinder: Some(4),
            sectors_per_track: Some(17),
            ..FormatOptions::default()
        },
        &[&size.to_string(), "4096", "8192", "4", "17"],
    );
}
