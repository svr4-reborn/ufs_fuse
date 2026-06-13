//! Gate for the UFS write path.
//!
//! 1. Python formats a blank UFS image.
//! 2. Rust populates it (mkdir tree, files spanning direct/single/double
//!    indirect, a symlink, and a hardlink) and recomputes the summary.
//! 3. The Python fsck reimplementation must report the result clean (no issues,
//!    superblock totals == recomputed totals) — this is the structural gate.
//! 4. The Python reader's manifest of the Rust image must match both the Rust
//!    reader's manifest and the independently-computed expected file hashes —
//!    content-equivalence.
//!
//! (The C `fsck` oracle is a stronger, format-independent check, but it needs a
//! fully-geometried disk image — it flags even the Python writer's bare output at
//! offset 0 — so it is wired in once the disk-image populate pipeline exists.)
//!
//! Needs `python3` + the in-tree `host-tools` package; skip with
//! `SVR4_SKIP_PYTHON_DIFF=1`.

use std::path::{Path, PathBuf};
use std::process::Command;

use serde_json::{json, Map, Value};
use sha2::{Digest, Sha256};
use svr4_fs_core::MappedImage;
use svr4_ufs::{
    create_file, detect_ufs_at_start, format, iter_directory_entries, link, make_directory,
    read_inode, read_inode_bytes, read_symlink_target, remove_directory, symlink, unlink,
    FormatOptions, Inode, Ufs,
};
use svr4_ufs::alloc::recompute_summary_counts;

const MODE_FILE: u32 = 0o644;
const MODE_DIR755: u32 = 0o755;
const MODE_DIR700: u32 = 0o700;

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

/// The files the test creates, as `(path, contents)`. Shared by the writer and
/// the expected-hash check so they cannot drift.
fn file_cases() -> Vec<(&'static str, Vec<u8>)> {
    let frag: Vec<u8> = (0..3).flat_map(|_| (0u16..256).map(|i| i as u8)).collect();
    vec![
        ("/empty", Vec::new()),
        ("/dir/small", b"hello world\n".to_vec()),
        ("/dir/frag", frag),
        ("/dir/oneblock", vec![b'B'; 4096]),
        ("/dir/multiblock", vec![b'M'; 4096 * 5 + 123]),
        ("/dir/sub/indirect", (0..4096u64 * 20).map(|i| ((i * 7) & 0xff) as u8).collect()),
        ("/dir/sub/big", (0..(12 + 1024 + 5) as u64 * 4096).map(|i| ((i * 31) & 0xff) as u8).collect()),
    ]
}

fn node_record(image: &[u8], ufs: &Ufs, inode: &Inode) -> Value {
    let mut record = Map::new();
    record.insert("mode".into(), json!(inode.mode));
    record.insert("nlink".into(), json!(inode.nlink));
    record.insert("uid".into(), json!(inode.uid));
    record.insert("gid".into(), json!(inode.gid));
    record.insert("size".into(), json!(inode.size));
    if inode.is_directory() {
        record.insert("type".into(), json!("dir"));
    } else if inode.is_symlink() {
        record.insert("type".into(), json!("link"));
        record.insert("target".into(), json!(read_symlink_target(image, ufs, inode)));
    } else if inode.is_regular() {
        record.insert("type".into(), json!("file"));
        record.insert("sha256".into(), json!(hex_sha256(&read_inode_bytes(image, ufs, inode))));
    } else {
        record.insert("type".into(), json!(format!("other(0o{:o})", inode.file_type())));
    }
    Value::Object(record)
}

fn walk(image: &[u8], ufs: &Ufs, path: &str, inode: &Inode, out: &mut Map<String, Value>) {
    let key = if path.is_empty() { "/".to_string() } else { path.to_string() };
    out.insert(key, node_record(image, ufs, inode));
    if !inode.is_directory() {
        return;
    }
    for entry in iter_directory_entries(image, ufs, inode) {
        if entry.name == "." || entry.name == ".." {
            continue;
        }
        if let Some(child) = read_inode(image, ufs, entry.inode as i64) {
            walk(image, ufs, &format!("{path}/{}", entry.name), &child, out);
        }
    }
}

fn python(host_tools: &Path, args: &[&Path]) -> std::process::Output {
    let mut cmd = Command::new("python3");
    cmd.env("PYTHONPATH", host_tools)
        .arg(Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/ufs_tool.py"));
    for a in args {
        cmd.arg(a);
    }
    cmd.output().expect("run python3 ufs_tool.py")
}

#[test]
fn rust_write_path_is_fsck_clean_and_content_correct() {
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
    let blank = dir.path().join("blank.img");
    let out = dir.path().join("out.img");
    let manifest = dir.path().join("manifest.json");

    // 1. Python formats a blank image.
    let status = python(&host_tools, &[Path::new("blank"), &blank]);
    assert!(status.status.success(), "blank: {}", String::from_utf8_lossy(&status.stderr));

    // 2. Rust populates it *through the memory-mapped backing* (no full-image
    //    RAM copy — the kernel pages in only what the write path touches).
    std::fs::copy(&blank, &out).unwrap();
    let cases = file_cases();
    let rust_manifest = {
        let mut img = MappedImage::open(&out).expect("mmap image");
        let ufs = detect_ufs_at_start(img.as_slice(), 0).expect("detect blank ufs");
        make_directory(img.as_mut_slice(), &ufs, "/dir", MODE_DIR755, 0, 0, 0).unwrap();
        make_directory(img.as_mut_slice(), &ufs, "/dir/sub", MODE_DIR700, 0, 0, 0).unwrap();
        for (path, data) in &cases {
            create_file(img.as_mut_slice(), &ufs, path, data, MODE_FILE, 0, 0, 0).unwrap();
        }
        symlink(img.as_mut_slice(), &ufs, "dir/small", "/link-to-small", 0o777, 0, 0, 0).unwrap();
        link(img.as_mut_slice(), &ufs, "/dir/small", "/dir/hardlink").unwrap();
        recompute_summary_counts(img.as_mut_slice(), &ufs).unwrap();

        // Build the Rust reader's manifest from the live mapping, then msync.
        let mut rust_map = Map::new();
        let root = read_inode(img.as_slice(), &ufs, 2).unwrap();
        walk(img.as_slice(), &ufs, "", &root, &mut rust_map);
        img.flush().unwrap();
        Value::Object(rust_map)
    };

    // 3. Python fsck + reader manifest (exits 2 if not clean).
    let check = python(&host_tools, &[Path::new("check"), &out, &manifest]);
    assert!(
        check.status.success(),
        "python fsck/check failed:\n{}",
        String::from_utf8_lossy(&check.stderr)
    );
    let python_manifest: Value =
        serde_json::from_slice(&std::fs::read(&manifest).unwrap()).expect("parse manifest");

    // 4a. Rust reader manifest must equal the Python reader manifest.
    if rust_manifest != python_manifest {
        let py = python_manifest.as_object().unwrap();
        let rs = rust_manifest.as_object().unwrap();
        let mut keys: Vec<&String> = py.keys().chain(rs.keys()).collect();
        keys.sort();
        keys.dedup();
        for key in keys {
            if py.get(key) != rs.get(key) {
                panic!("manifest mismatch at {key:?}:\n  python: {:?}\n  rust: {:?}", py.get(key), rs.get(key));
            }
        }
    }

    // 4b. File hashes in the manifest must match the independently-computed
    //     expected hashes (catches a writer that both readers read consistently
    //     but wrongly).
    let manifest_obj = python_manifest.as_object().unwrap();
    for (path, data) in &cases {
        let entry = manifest_obj.get(*path).unwrap_or_else(|| panic!("missing {path}"));
        assert_eq!(entry["type"], json!("file"), "{path} should be a file");
        assert_eq!(entry["size"], json!(data.len()), "{path} size");
        assert_eq!(entry["sha256"], json!(hex_sha256(data)), "{path} content hash");
    }

    // Spot-check the symlink target and the hardlink sharing.
    assert_eq!(manifest_obj["/link-to-small"]["type"], json!("link"));
    assert_eq!(manifest_obj["/link-to-small"]["target"], json!("dir/small"));
    assert_eq!(manifest_obj["/dir/hardlink"]["sha256"], manifest_obj["/dir/small"]["sha256"]);
    assert_eq!(manifest_obj["/dir/hardlink"]["nlink"], json!(2));
    assert_eq!(manifest_obj["/dir/small"]["nlink"], json!(2));
}

#[test]
fn rust_removals_stay_fsck_clean() {
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
    let blank = dir.path().join("blank.img");
    let out = dir.path().join("out.img");
    let manifest = dir.path().join("manifest.json");
    assert!(python(&host_tools, &[Path::new("blank"), &blank]).status.success());
    std::fs::copy(&blank, &out).unwrap();

    {
        let mut img = MappedImage::open(&out).unwrap();
        let ufs = detect_ufs_at_start(img.as_slice(), 0).unwrap();
        make_directory(img.as_mut_slice(), &ufs, "/a", 0o755, 0, 0, 0).unwrap();
        make_directory(img.as_mut_slice(), &ufs, "/a/b", 0o755, 0, 0, 0).unwrap();
        create_file(img.as_mut_slice(), &ufs, "/a/keep", b"keep me\n", 0o644, 0, 0, 0).unwrap();
        create_file(img.as_mut_slice(), &ufs, "/a/drop", &vec![b'X'; 4096 * 5 + 7], 0o644, 0, 0, 0).unwrap();
        create_file(img.as_mut_slice(), &ufs, "/a/b/inner", &vec![b'Y'; 9000], 0o644, 0, 0, 0).unwrap();
        // A hard-linked pair: dropping one link must leave the other at nlink 1.
        create_file(img.as_mut_slice(), &ufs, "/a/twin", b"shared\n", 0o644, 0, 0, 0).unwrap();
        link(img.as_mut_slice(), &ufs, "/a/twin", "/a/twin2").unwrap();

        // Remove a multi-block file, empty out and remove a subdirectory, and
        // drop one of the two hard links.
        unlink(img.as_mut_slice(), &ufs, "/a/drop").unwrap();
        unlink(img.as_mut_slice(), &ufs, "/a/b/inner").unwrap();
        remove_directory(img.as_mut_slice(), &ufs, "/a/b").unwrap();
        unlink(img.as_mut_slice(), &ufs, "/a/twin2").unwrap();

        recompute_summary_counts(img.as_mut_slice(), &ufs).unwrap();
        img.flush().unwrap();
    }

    let check = python(&host_tools, &[Path::new("check"), &out, &manifest]);
    assert!(check.status.success(), "python fsck/check failed:\n{}", String::from_utf8_lossy(&check.stderr));
    let m: Value = serde_json::from_slice(&std::fs::read(&manifest).unwrap()).unwrap();
    let obj = m.as_object().unwrap();

    // Survivors present, removed paths gone.
    assert!(obj.contains_key("/a"));
    assert!(obj.contains_key("/a/keep"));
    assert!(obj.contains_key("/a/twin"));
    assert!(!obj.contains_key("/a/drop"), "unlinked file still present");
    assert!(!obj.contains_key("/a/b"), "removed directory still present");
    assert!(!obj.contains_key("/a/b/inner"), "child of removed dir still present");
    assert!(!obj.contains_key("/a/twin2"), "unlinked hard link still present");
    // The remaining hard link is back to a single link.
    assert_eq!(obj["/a/twin"]["nlink"], json!(1));
    assert_eq!(obj["/a/keep"]["sha256"], json!(hex_sha256(b"keep me\n")));
}

/// Regression test for directory growth, covering two historical bugs.
/// (1) `add_directory_entry` once errored "no directory slot available" as soon
/// as the first 512-byte DIRBLKSIZ block filled. (2) A directory big enough to
/// need *indirect* blocks was given a fragment tail (the allocation-size rule
/// missed `needed_blocks > NDADDR`), which `fsck` then flagged as a
/// block-count/bitmap mismatch. 6000 entries forces direct-block growth *and*
/// the crossing into indirect blocks; the result must be fsck-clean with every
/// entry intact. Uses the Rust formatter for a large-enough image (the 8 MiB
/// Python blank has too few inodes).
#[test]
fn rust_large_directory_grows_and_stays_fsck_clean() {
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
    let out = dir.path().join("out.img");
    let manifest = dir.path().join("manifest.json");

    const N: usize = 6000;
    // A geometried ~64 MiB slice (multiple cylinder groups → enough inodes, and
    // a cg bitmap that can represent each group). 16 heads * 63 sectors = 1008
    // sectors/cyl; 130 cylinders.
    let size_bytes: u64 = 130 * 1008 * 512;
    {
        let mut img = MappedImage::create(&out, size_bytes).unwrap();
        let opts = FormatOptions {
            block_size: 4096,
            tracks_per_cylinder: Some(16),
            sectors_per_track: Some(63),
            ..FormatOptions::default()
        };
        let ufs = format(img.as_mut_slice(), 0, size_bytes, &opts).unwrap();
        make_directory(img.as_mut_slice(), &ufs, "/big", 0o755, 0, 0, 0).unwrap();
        // Names of varied length so dir records vary in size, like a real tree.
        for i in 0..N {
            let path = format!("/big/entry_{i:04}_{}", "x".repeat(i % 11));
            create_file(img.as_mut_slice(), &ufs, &path, format!("data {i}\n").as_bytes(), 0o644, 0, 0, 0).unwrap();
        }
        recompute_summary_counts(img.as_mut_slice(), &ufs).unwrap();
        img.flush().unwrap();
    }

    let check = python(&host_tools, &[Path::new("check"), &out, &manifest]);
    assert!(check.status.success(), "python fsck/check failed:\n{}", String::from_utf8_lossy(&check.stderr));
    let m: Value = serde_json::from_slice(&std::fs::read(&manifest).unwrap()).unwrap();
    let obj = m.as_object().unwrap();

    for i in 0..N {
        let path = format!("/big/entry_{i:04}_{}", "x".repeat(i % 11));
        let entry = obj.get(&path).unwrap_or_else(|| panic!("missing {path} after dir growth"));
        assert_eq!(entry["sha256"], json!(hex_sha256(format!("data {i}\n").as_bytes())), "{path}");
    }
}
