//! Gate for the UFS write path inside a *real geometried disk image*.
//!
//! Unlike `write_fsck.rs` (a bare UFS superblock at offset 0), this exercises a
//! UFS root slice living at a non-zero byte offset inside a partitioned VTOC
//! disk image — the layout the actual build (`tasks/make_image.py`) produces.
//! It proves the Rust write path's slice-relative addressing (`Ufs::start_offset`
//! threaded through every geometry macro) is correct, and that population runs
//! through the memory-mapped backing without reading the whole (multi-megabyte,
//! and in principle multi-gigabyte) image into RAM.
//!
//! 1. Python builds a geometried disk image with a formatted UFS root slice and
//!    prints the slice's absolute byte offset.
//! 2. Rust populates the slice *at that offset* through `MappedImage`.
//! 3. The Python fsck reimplementation (the trusted structural gate) must report
//!    the slice clean, and its reader manifest must match the built tree.
//!
//! The stronger C `fsck` oracle is wired up separately (see
//! `c_fsck_oracle.rs`); it currently flags a pre-existing formatter/oracle-port
//! discrepancy even on known-good images, so it is not yet a hard gate.
//!
//! Needs `python3` + the in-tree `host-tools` package; skip with
//! `SVR4_SKIP_PYTHON_DIFF=1`.

use std::path::{Path, PathBuf};
use std::process::Command;

use serde_json::Value;
use sha2::{Digest, Sha256};
use svr4_fs_core::MappedImage;
use svr4_ufs::alloc::recompute_summary_counts;
use svr4_ufs::{
    create_file, detect_ufs_at_start, link, make_directory, remove_directory, symlink, unlink,
};

const MODE_FILE: u32 = 0o644;
const MODE_DIR: u32 = 0o755;

fn repo_root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .ancestors()
        .nth(3)
        .unwrap()
        .to_path_buf()
}

fn hex_sha256(data: &[u8]) -> String {
    Sha256::digest(data).iter().map(|b| format!("{b:02x}")).collect()
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
fn rust_populate_in_geometried_disk_image_is_fsck_clean() {
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

    let dir = tempfile::tempdir().unwrap();
    let img = dir.path().join("disk.img");
    let manifest = dir.path().join("manifest.json");

    // 1. Python builds a geometried disk image with a formatted UFS root slice
    //    and tells us the slice's absolute byte offset.
    let blank = ufs_tool(&host_tools, &["disk-blank", img.to_str().unwrap()]);
    assert!(
        blank.status.success(),
        "disk-blank failed:\n{}",
        String::from_utf8_lossy(&blank.stderr)
    );
    let offset: u64 = String::from_utf8_lossy(&blank.stdout)
        .trim()
        .parse()
        .expect("disk-blank prints the root slice byte offset");
    assert!(offset > 0, "root slice should be at a non-zero offset, got {offset}");

    // 2. Rust populates the slice *at that offset*, through the mmap.
    let big: Vec<u8> = (0..4096u64 * 20).map(|i| ((i * 7) & 0xff) as u8).collect();
    let multiblock = vec![b'M'; 4096 * 5 + 123];
    {
        let mut image = MappedImage::open(&img).expect("mmap disk image");
        let ufs = detect_ufs_at_start(image.as_slice(), offset)
            .expect("detect UFS at the root slice offset");
        assert_eq!(ufs.start_offset, offset);

        make_directory(image.as_mut_slice(), &ufs, "/dir", MODE_DIR, 0, 0, 0).unwrap();
        make_directory(image.as_mut_slice(), &ufs, "/dir/sub", MODE_DIR, 0, 0, 0).unwrap();
        create_file(image.as_mut_slice(), &ufs, "/dir/small", b"hello disk\n", MODE_FILE, 0, 0, 0).unwrap();
        create_file(image.as_mut_slice(), &ufs, "/dir/multiblock", &multiblock, MODE_FILE, 0, 0, 0).unwrap();
        create_file(image.as_mut_slice(), &ufs, "/dir/sub/indirect", &big, MODE_FILE, 0, 0, 0).unwrap();
        symlink(image.as_mut_slice(), &ufs, "dir/small", "/link", 0o777, 0, 0, 0).unwrap();
        link(image.as_mut_slice(), &ufs, "/dir/small", "/dir/hardlink").unwrap();

        // Removals must stay clean too.
        create_file(image.as_mut_slice(), &ufs, "/dir/scratch", &vec![b'X'; 9000], MODE_FILE, 0, 0, 0).unwrap();
        unlink(image.as_mut_slice(), &ufs, "/dir/scratch").unwrap();
        make_directory(image.as_mut_slice(), &ufs, "/dir/empty", MODE_DIR, 0, 0, 0).unwrap();
        remove_directory(image.as_mut_slice(), &ufs, "/dir/empty").unwrap();

        recompute_summary_counts(image.as_mut_slice(), &ufs).unwrap();
        image.flush().unwrap();
    }

    // 3. Python fsck reimpl + reader manifest at the slice offset.
    let check = ufs_tool(
        &host_tools,
        &[
            "disk-check",
            img.to_str().unwrap(),
            &offset.to_string(),
            manifest.to_str().unwrap(),
        ],
    );
    assert!(
        check.status.success(),
        "python fsck/check failed:\n{}",
        String::from_utf8_lossy(&check.stderr)
    );
    let m: Value = serde_json::from_slice(&std::fs::read(&manifest).unwrap()).unwrap();
    let obj = m.as_object().unwrap();

    assert_eq!(obj["/dir/small"]["sha256"], hex_sha256(b"hello disk\n"));
    assert_eq!(obj["/dir/multiblock"]["sha256"], hex_sha256(&multiblock));
    assert_eq!(obj["/dir/sub/indirect"]["sha256"], hex_sha256(&big));
    assert_eq!(obj["/link"]["type"], "link");
    assert_eq!(obj["/link"]["target"], "dir/small");
    assert_eq!(obj["/dir/hardlink"]["sha256"], obj["/dir/small"]["sha256"]);
    assert_eq!(obj["/dir/hardlink"]["nlink"], 2);
    assert!(!obj.contains_key("/dir/scratch"), "unlinked file lingers");
    assert!(!obj.contains_key("/dir/empty"), "rmdir'd dir lingers");
}
