//! Differential gate: the Rust BFS formatter must be byte-for-byte identical to
//! the Python reference `build_bfs_filesystem_image`.
//!
//! Needs `python3` + the in-tree `host-tools` package; skip with
//! `SVR4_SKIP_PYTHON_DIFF=1`.

use std::path::{Path, PathBuf};
use std::process::Command;

fn repo_root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).ancestors().nth(3).unwrap().to_path_buf()
}

/// Kept in sync with `bfs_tool.py`'s FILES.
fn files() -> Vec<(&'static str, Vec<u8>)> {
    vec![("unix", vec![b'K'; 5000]), ("boot", b"BL".to_vec()), ("empty", Vec::new())]
}

#[test]
fn rust_bfs_format_matches_python_byte_for_byte() {
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

    let size = 64 * 1024usize;
    let dir = tempfile::tempdir().unwrap();
    let py_out = dir.path().join("py.bfs");

    let status = Command::new("python3")
        .env("PYTHONPATH", &host_tools)
        .arg(Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/bfs_tool.py"))
        .arg("format")
        .arg(&py_out)
        .arg(size.to_string())
        .status()
        .expect("run bfs_tool.py");
    assert!(status.success(), "python bfs_tool.py failed");
    let python_image = std::fs::read(&py_out).unwrap();
    assert_eq!(python_image.len(), size);

    let cases = files();
    let file_refs: Vec<(&str, &[u8])> = cases.iter().map(|(n, d)| (*n, d.as_slice())).collect();
    let mut rust_image = vec![0u8; size];
    svr4_bfs::format(&mut rust_image, 0, size, &file_refs, None, 0).unwrap();

    assert_eq!(rust_image, python_image, "Rust BFS image differs from the Python reference");
}
