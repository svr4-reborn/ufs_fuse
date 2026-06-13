//! Static check: a complete, bootable-shaped SVR4 disk image can be assembled
//! end-to-end from a sysroot using ONLY the Rust host-tool binaries plus the
//! Python *standard library* — no pyfuse3, no rsync, no FUSE mount.
//!
//! This is the "make_image can create a suitable image" gate the build cutover
//! needs. The pipeline is:
//!
//!   1. `ufs_tool.py disk-blank`  — geometried VTOC disk image + formatted (empty)
//!      UFS root slice and an empty BFS /stand slice. (UFS *format* stays in
//!      stdlib Python, which the user said is fine to keep; it pulls in no
//!      external packages.)
//!   2. `svr4-ufs-populate`       — mirror a generated test sysroot into the root
//!      slice and apply a device-node table — no FUSE, no rsync.
//!   3. `svr4-disk-image format-bfs` — write the kernel/boot files into /stand.
//!   4. Validation: `svr4-disk-image inspect --json` recognises root=ufs +
//!      stand=bfs; `ufs_tool.py disk-check` confirms the root slice is fsck-clean
//!      and its tree matches what we populated (files, symlink, hard link, and
//!      device nodes).
//!
//! Skipped (not failed) when python3 / the in-tree host-tools package / the
//! sibling `svr4-disk-image` binary are unavailable, or `SVR4_SKIP_PYTHON_DIFF`
//! is set.

use std::fs;
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::process::Command;

use serde_json::Value;
use sha2::{Digest, Sha256};

fn repo_root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).ancestors().nth(3).unwrap().to_path_buf()
}

/// Directory holding the freshly-built workspace binaries (parent of this bin).
fn bins_dir() -> PathBuf {
    Path::new(env!("CARGO_BIN_EXE_svr4-ufs-populate")).parent().unwrap().to_path_buf()
}

fn hex_sha256(data: &[u8]) -> String {
    Sha256::digest(data).iter().map(|b| format!("{b:02x}")).collect()
}

fn ufs_tool(host_tools: &Path, args: &[&str]) -> std::process::Output {
    let mut cmd = Command::new("python3");
    cmd.env("PYTHONPATH", host_tools)
        .arg(repo_root().join("host-tools-rs/crates/svr4-ufs/tests/ufs_tool.py"));
    for a in args {
        cmd.arg(a);
    }
    cmd.output().expect("run python3 ufs_tool.py")
}

/// Build a small but representative sysroot: nested dirs, an executable, a
/// symlink, a hard-linked pair, and a multi-block file (to exercise indirect
/// blocks through the populate path).
fn build_sysroot(root: &Path) -> Vec<(String, Vec<u8>)> {
    let mut files = Vec::new();
    let mut write = |rel: &str, data: &[u8], mode: u32| {
        let path = root.join(rel);
        fs::create_dir_all(path.parent().unwrap()).unwrap();
        fs::write(&path, data).unwrap();
        fs::set_permissions(&path, fs::Permissions::from_mode(mode)).unwrap();
        files.push((format!("/{rel}"), data.to_vec()));
    };
    write("bin/sh", b"#!/bin/sh\nexit 0\n", 0o755);
    write("etc/motd", b"Welcome to SVR4\n", 0o644);
    write("etc/inittab", b"is:3:initdefault:\n", 0o644);
    write("usr/lib/libc.so.1", b"\x7fELF fake libc payload", 0o755);
    let big: Vec<u8> = (0..4096u64 * 20).map(|i| ((i * 13) & 0xff) as u8).collect();
    write("usr/share/big.dat", &big, 0o644);

    // Symlink usr/lib/libc.so -> libc.so.1
    std::os::unix::fs::symlink("libc.so.1", root.join("usr/lib/libc.so")).unwrap();
    // Hard-linked pair: bin/test and bin/[
    fs::write(root.join("bin/test"), b"test-builtin\n").unwrap();
    fs::set_permissions(root.join("bin/test"), fs::Permissions::from_mode(0o755)).unwrap();
    fs::hard_link(root.join("bin/test"), root.join("bin/[")).unwrap();
    files.push(("/bin/test".into(), b"test-builtin\n".to_vec()));

    files
}

#[test]
fn make_image_static_check() {
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
    let disk_image_bin = bins_dir().join("svr4-disk-image");
    let populate_bin = bins_dir().join("svr4-ufs-populate");
    if !disk_image_bin.exists() {
        eprintln!("svr4-disk-image binary not built (run the whole `cargo test`); skipping");
        return;
    }

    let dir = tempfile::tempdir().unwrap();
    let img = dir.path().join("disk.img");
    let sysroot = dir.path().join("sysroot");
    let manifest = dir.path().join("manifest.json");
    let device_table = dir.path().join("devices.tab");
    let kernel = dir.path().join("unix");
    fs::create_dir(&sysroot).unwrap();

    let expected_files = build_sysroot(&sysroot);
    fs::write(
        &device_table,
        "# path type major minor mode\n\
         /dev/console c 30 0 0600\n\
         /dev/null    c 2  2 0666\n\
         /dev/zero    c 2  4 0666\n\
         /dev/root    b 0  1 0600\n\
         /dev/kd/kd00 c 30 0 0600\n",
    )
    .unwrap();
    let kernel_bytes = b"FAKE SVR4 KERNEL IMAGE".repeat(100);
    fs::write(&kernel, &kernel_bytes).unwrap();

    // 1. Geometried image + formatted (empty) UFS root slice; capture its offset.
    let blank = ufs_tool(&host_tools, &["disk-blank", img.to_str().unwrap()]);
    assert!(blank.status.success(), "disk-blank: {}", String::from_utf8_lossy(&blank.stderr));
    let root_offset = String::from_utf8_lossy(&blank.stdout).trim().to_string();

    // 2. Populate the root slice from the sysroot + device table (no FUSE/rsync).
    let pop = Command::new(&populate_bin)
        .arg(&img)
        .arg(&sysroot)
        .arg("--slice")
        .arg("root")
        .arg("--device-table")
        .arg(&device_table)
        .output()
        .expect("run svr4-ufs-populate");
    assert!(pop.status.success(), "populate failed:\n{}", String::from_utf8_lossy(&pop.stderr));

    // 3. Format the /stand BFS slice with the kernel.
    let bfs = Command::new(&disk_image_bin)
        .arg("format-bfs")
        .arg(&img)
        .arg("--slice")
        .arg("stand")
        .arg("--file")
        .arg(format!("unix={}", kernel.display()))
        .output()
        .expect("run format-bfs");
    assert!(bfs.status.success(), "format-bfs failed:\n{}", String::from_utf8_lossy(&bfs.stderr));

    // 4a. inspect --json recognises both filesystems.
    let inspect = Command::new(&disk_image_bin)
        .arg("inspect")
        .arg("--json")
        .arg(&img)
        .output()
        .expect("run inspect");
    assert!(inspect.status.success(), "inspect failed:\n{}", String::from_utf8_lossy(&inspect.stderr));
    let report: Value = serde_json::from_slice(&inspect.stdout).unwrap();
    let slices = report["slice_filesystems"].as_array().unwrap();
    let find_fs = |fs: &str| slices.iter().find(|s| s["filesystem"] == fs).cloned();
    let root_slice = find_fs("ufs").expect("a UFS slice");
    let stand_slice = find_fs("bfs").expect("a BFS slice");
    let stand_names: Vec<&str> = stand_slice["root_entries"]
        .as_array()
        .unwrap()
        .iter()
        .map(|e| e["name"].as_str().unwrap())
        .collect();
    assert!(stand_names.contains(&"unix"), "/stand should contain the kernel, got {stand_names:?}");
    assert_eq!(root_slice["filesystem"], "ufs");

    // 4b. fsck-clean + a manifest of the populated root tree.
    let check = ufs_tool(
        &host_tools,
        &["disk-check", img.to_str().unwrap(), &root_offset, manifest.to_str().unwrap()],
    );
    assert!(
        check.status.success(),
        "disk-check failed:\n{}",
        String::from_utf8_lossy(&check.stderr)
    );
    let m: Value = serde_json::from_slice(&fs::read(&manifest).unwrap()).unwrap();
    let obj = m.as_object().unwrap();

    // Files copied with content + permissions.
    for (path, data) in &expected_files {
        let entry = obj.get(path).unwrap_or_else(|| panic!("missing {path} in image"));
        assert_eq!(entry["type"], "file", "{path}");
        assert_eq!(entry["sha256"], hex_sha256(data), "{path} content");
    }
    assert_eq!(obj["/bin/sh"]["mode"], 0o100755, "executable bit preserved");
    assert_eq!(obj["/etc/motd"]["mode"], 0o100644);

    // Symlink + hard link.
    assert_eq!(obj["/usr/lib/libc.so"]["type"], "link");
    assert_eq!(obj["/usr/lib/libc.so"]["target"], "libc.so.1");
    assert_eq!(obj["/bin/test"]["nlink"], 2, "hard-linked pair");
    assert_eq!(obj["/bin/["]["sha256"], obj["/bin/test"]["sha256"]);

    // Device nodes (the Python walker reports specials as `other(0o<type>)`).
    assert_eq!(obj["/dev/console"]["type"], "other(0o20000)", "char device");
    assert_eq!(obj["/dev/null"]["type"], "other(0o20000)");
    assert_eq!(obj["/dev/root"]["type"], "other(0o60000)", "block device");
    assert!(obj.contains_key("/dev/kd/kd00"), "nested device dir created");
    assert_eq!(obj["/dev/kd/kd00"]["type"], "other(0o20000)");

    // Owners default to root.
    assert_eq!(obj["/etc/motd"]["uid"], 0);
    assert_eq!(obj["/etc/motd"]["gid"], 0);
}

/// The same end-to-end image build, but with NO Python in the build path at all:
/// the disk skeleton, the UFS root format, the BFS /stand format, and the
/// populate are ALL done by the Rust binaries. Python is used only afterwards as
/// an independent fsck oracle. This exercises the Rust `format-ufs` formatter as
/// the final piece of the dependency-free pipeline.
#[test]
fn make_image_all_rust_build() {
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
    let disk_image_bin = bins_dir().join("svr4-disk-image");
    let populate_bin = bins_dir().join("svr4-ufs-populate");
    if !disk_image_bin.exists() {
        eprintln!("svr4-disk-image binary not built (run the whole `cargo test`); skipping");
        return;
    }

    let dir = tempfile::tempdir().unwrap();
    let img = dir.path().join("disk.img");
    let sysroot = dir.path().join("sysroot");
    let manifest = dir.path().join("manifest.json");
    let kernel = dir.path().join("unix");
    fs::create_dir(&sysroot).unwrap();
    let expected_files = build_sysroot(&sysroot);
    fs::write(&kernel, b"FAKE KERNEL".repeat(50)).unwrap();

    // Geometry: heads=4, sectors=17 -> 68 sectors/cyl, 512 cylinders (~17 MiB),
    // with a cylinder-aligned /stand and root slice.
    let run = |bin: &Path, args: &[&str]| -> std::process::Output {
        Command::new(bin).args(args).output().expect("run binary")
    };
    let ok = |out: std::process::Output, what: &str| {
        assert!(out.status.success(), "{what} failed:\n{}", String::from_utf8_lossy(&out.stderr));
    };

    // 1. Skeleton (Rust): whole UNIX partition + root + stand slices.
    ok(
        run(
            &disk_image_bin,
            &[
                "create-skeleton",
                "--output", img.to_str().unwrap(),
                "--cylinders", "512", "--heads", "4", "--sectors", "17",
                "--slice", "0:5:1:34815:0x201",
                "--slice", "1:2:4284:30532:0x200",
                "--slice", "10:9:68:2108:0x200",
            ],
        ),
        "create-skeleton",
    );

    // 2. Format the root slice as UFS (Rust formatter).
    ok(
        run(&disk_image_bin, &["format-ufs", img.to_str().unwrap(), "--slice", "root", "--block-size", "4096"]),
        "format-ufs",
    );

    // 3. Format /stand as BFS with the kernel (Rust).
    ok(
        run(&disk_image_bin, &["format-bfs", img.to_str().unwrap(), "--slice", "stand", "--file", &format!("unix={}", kernel.display())]),
        "format-bfs",
    );

    // 4. Populate the root slice from the sysroot (Rust).
    ok(
        run(&populate_bin, &[img.to_str().unwrap(), sysroot.to_str().unwrap(), "--slice", "root"]),
        "populate",
    );

    // 5. inspect --json: both filesystems recognised; grab the root offset.
    let inspect = run(&disk_image_bin, &["inspect", "--json", img.to_str().unwrap()]);
    ok(inspect.clone(), "inspect");
    let report: Value = serde_json::from_slice(&inspect.stdout).unwrap();
    let slices = report["slice_filesystems"].as_array().unwrap();
    let root = slices.iter().find(|s| s["filesystem"] == "ufs").expect("ufs slice");
    assert!(slices.iter().any(|s| s["filesystem"] == "bfs"), "bfs /stand slice");
    let root_offset = (root["absolute_start_sector"].as_i64().unwrap() * 512).to_string();

    // 6. Python fsck oracle (validation only) + content check.
    let check = ufs_tool(
        &host_tools,
        &["disk-check", img.to_str().unwrap(), &root_offset, manifest.to_str().unwrap()],
    );
    assert!(check.status.success(), "disk-check failed:\n{}", String::from_utf8_lossy(&check.stderr));
    let m: Value = serde_json::from_slice(&fs::read(&manifest).unwrap()).unwrap();
    let obj = m.as_object().unwrap();
    for (path, data) in &expected_files {
        let entry = obj.get(path).unwrap_or_else(|| panic!("missing {path}"));
        assert_eq!(entry["sha256"], hex_sha256(data), "{path}");
    }
    assert_eq!(obj["/usr/lib/libc.so"]["type"], "link");
    assert_eq!(obj["/bin/test"]["nlink"], 2);
}
