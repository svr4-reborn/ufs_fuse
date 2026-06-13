//! Differential test for the UFS read path.
//!
//! A Python helper builds a populated UFS image with the Python *writer* and a
//! manifest of the whole tree (attrs + content hashes) with the Python
//! *reader*. The Rust reader walks the same image and must reproduce the
//! manifest exactly. Covers empty files, fragmented tails, single full blocks,
//! multi-block direct files, single- and double-indirect files, a directory
//! tree, a symlink, and a hardlink.
//!
//! Needs `python3` + the in-tree `host-tools` package; set
//! `SVR4_SKIP_PYTHON_DIFF=1` to skip.

use std::path::{Path, PathBuf};
use std::process::Command;

use serde_json::{json, Map, Value};
use sha2::{Digest, Sha256};
use svr4_ufs::{
    detect_ufs_at_start, iter_directory_entries, read_inode, read_inode_bytes, read_symlink_target,
    Inode, Ufs,
};

fn repo_root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .ancestors()
        .nth(3)
        .expect("repo root is three levels above the crate manifest")
        .to_path_buf()
}

fn hex_sha256(data: &[u8]) -> String {
    let digest = Sha256::digest(data);
    let mut out = String::with_capacity(64);
    for byte in digest {
        out.push_str(&format!("{byte:02x}"));
    }
    out
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
        let content = read_inode_bytes(image, ufs, inode);
        record.insert("sha256".into(), json!(hex_sha256(&content)));
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

#[test]
fn rust_tree_walk_matches_python_manifest() {
    if std::env::var_os("SVR4_SKIP_PYTHON_DIFF").is_some() {
        eprintln!("SVR4_SKIP_PYTHON_DIFF set; skipping Python differential");
        return;
    }

    let root = repo_root();
    let host_tools = root.join("host-tools");
    let script = Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/gen_ufs_image.py");
    if !host_tools.join("host_tools").is_dir() || !script.exists() {
        eprintln!("host-tools package or generator not found; skipping");
        return;
    }

    let dir = tempfile::tempdir().unwrap();
    let image_path = dir.path().join("ufs.img");
    let manifest_path = dir.path().join("manifest.json");

    let status = Command::new("python3")
        .env("PYTHONPATH", &host_tools)
        .arg(&script)
        .arg(&image_path)
        .arg(&manifest_path)
        .status();
    match status {
        Ok(s) if s.success() => {}
        Ok(s) => panic!("generator exited with {s}"),
        Err(e) => {
            eprintln!("could not run python3 ({e}); skipping");
            return;
        }
    }

    let python_manifest: Value =
        serde_json::from_slice(&std::fs::read(&manifest_path).unwrap()).expect("parse manifest");

    let image = std::fs::read(&image_path).unwrap();
    let ufs = detect_ufs_at_start(&image, 0).expect("detect ufs at start of image");

    let root_inode = read_inode(&image, &ufs, 2).expect("read root inode");
    let mut rust_manifest = Map::new();
    walk(&image, &ufs, "", &root_inode, &mut rust_manifest);
    let rust_manifest = Value::Object(rust_manifest);

    // The disk-crate detector adapter must recognise this image as UFS and list
    // its root (including "." and "..").
    let detected = svr4_disk::inspect::FsDetector::probe(&svr4_ufs::UfsDetector, &image)
        .expect("UfsDetector detects the image");
    assert_eq!(detected.filesystem, "ufs");
    let mut root_names: Vec<&str> = detected.root_entries.iter().map(|e| e.name.as_str()).collect();
    root_names.sort_unstable();
    assert_eq!(root_names, vec![".", "..", "dir", "empty", "link-to-small"]);

    if rust_manifest != python_manifest {
        // Pinpoint the first divergence for a useful failure message.
        let py = python_manifest.as_object().unwrap();
        let rs = rust_manifest.as_object().unwrap();
        let mut keys: Vec<&String> = py.keys().chain(rs.keys()).collect();
        keys.sort();
        keys.dedup();
        for key in keys {
            if py.get(key) != rs.get(key) {
                panic!(
                    "manifest mismatch at {key:?}:\n  python: {:?}\n  rust:   {:?}",
                    py.get(key),
                    rs.get(key)
                );
            }
        }
        panic!("manifests differ but no per-key diff found");
    }
}
