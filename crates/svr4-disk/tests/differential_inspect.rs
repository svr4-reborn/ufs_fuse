//! Differential test: the Rust `inspect` rendering must byte-match the Python
//! `disk_image.py inspect` on the same image.
//!
//! Needs `python3` and the in-tree `host-tools` package. Set
//! `SVR4_SKIP_PYTHON_DIFF=1` to skip in environments without Python. The image
//! is a blank skeleton, so the (Phase 1) Rust tool with no FS detection reports
//! `fs=unknown` for every slice, exactly like Python on the same blank image.

use std::path::{Path, PathBuf};
use std::process::Command;

use svr4_disk::create::{create_raw_image_skeleton, RawDiskGeometry, DISK_ADDRESSING_CHS};
use svr4_disk::inspect::{inspect_disk_image, NullDetector};
use svr4_disk::report::format_report;
use svr4_disk::structures::VtocPartition;

fn repo_root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .ancestors()
        .nth(3)
        .expect("repo root is three levels above the crate manifest")
        .to_path_buf()
}

/// Drop the leading `Image: <path>` line so the comparison ignores how each
/// tool spells the (identical) path. Everything else must match exactly.
fn strip_image_line(text: &str) -> String {
    text.lines()
        .filter(|line| !line.starts_with("Image: "))
        .map(|line| format!("{line}\n"))
        .collect()
}

/// Same idea for the JSON `"path": "..."` field.
fn strip_json_path(text: &str) -> String {
    text.lines()
        .filter(|line| !line.trim_start().starts_with("\"path\":"))
        .map(|line| format!("{line}\n"))
        .collect()
}

fn run_python_inspect(host_tools: &Path, image: &Path, json: bool) -> Option<String> {
    let mut cmd = Command::new("python3");
    cmd.current_dir(host_tools).arg("disk_image.py").arg("inspect").arg(image);
    if json {
        cmd.arg("--json");
    }
    let output = match cmd.output() {
        Ok(output) => output,
        Err(e) => {
            eprintln!("could not run python3 ({e}); skipping Python differential");
            return None;
        }
    };
    assert!(
        output.status.success(),
        "python inspect failed:\n{}",
        String::from_utf8_lossy(&output.stderr)
    );
    Some(String::from_utf8(output.stdout).expect("python output is utf-8"))
}

#[test]
fn rust_inspect_matches_python_inspect() {
    if std::env::var_os("SVR4_SKIP_PYTHON_DIFF").is_some() {
        eprintln!("SVR4_SKIP_PYTHON_DIFF set; skipping Python differential");
        return;
    }

    let root = repo_root();
    let host_tools = root.join("host-tools");
    let script = host_tools.join("disk_image.py");
    if !script.exists() {
        eprintln!("host-tools/disk_image.py not found; skipping Python differential");
        return;
    }

    let dir = tempfile::tempdir().unwrap();
    let image = dir.path().join("skel.raw");
    let geometry = RawDiskGeometry {
        cylinders: 16,
        heads: 4,
        sectors_per_track: 17,
    };
    let slices = vec![
        VtocPartition { index: 0, tag: 0x05, flag: 0x0201, start_sector: 1, sector_count: 1087 },
        VtocPartition { index: 1, tag: 0x02, flag: 0x0200, start_sector: 64, sector_count: 128 },
        VtocPartition { index: 10, tag: 0x09, flag: 0x0200, start_sector: 32, sector_count: 32 },
    ];
    create_raw_image_skeleton(
        &image,
        &geometry,
        1,
        geometry.total_sectors() as u32 - 1,
        "SVR4",
        &slices,
        None,
        DISK_ADDRESSING_CHS,
    )
    .expect("skeleton creation succeeds");

    let Some(python_text) = run_python_inspect(&host_tools, &image, false) else {
        return;
    };
    let report = inspect_disk_image(&image, &NullDetector).expect("rust inspect succeeds");
    let rust_text = format_report(&report);
    assert_eq!(
        strip_image_line(&python_text),
        strip_image_line(&rust_text),
        "rust inspect text output diverged from python"
    );

    // The --json rendering must match too (path field aside).
    let Some(python_json) = run_python_inspect(&host_tools, &image, true) else {
        return;
    };
    let rust_json = serde_json::to_string_pretty(&report).expect("serialize report");
    assert_eq!(
        strip_json_path(&python_json),
        strip_json_path(&rust_json),
        "rust inspect json output diverged from python"
    );
}
