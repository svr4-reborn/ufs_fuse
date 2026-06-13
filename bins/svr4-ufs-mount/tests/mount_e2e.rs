//! End-to-end gate for the FUSE daemon.
//!
//! 1. Python formats a blank UFS image.
//! 2. The `svr4-ufs-mount` binary mounts it over a real FUSE mount.
//! 3. We drive an rsync-shaped workload through the kernel via `std::fs`
//!    (mkdir/write/read/symlink/hardlink/rename/chmod/unlink/rmdir, including a
//!    file large enough to need indirect blocks and a directory moved across
//!    parents).
//! 4. We unmount and wait for the daemon to exit, so its `destroy` recomputes
//!    the summary counts and msyncs the mapping.
//! 5. The Python fsck reimplementation must report the unmounted image clean,
//!    and its reader manifest must reflect exactly the tree we built.
//!
//! Needs a working FUSE lane (`/dev/fuse` + `fusermount`), `python3`, and the
//! in-tree `host-tools` package. Skipped (not failed) when any are missing, or
//! when `SVR4_SKIP_PYTHON_DIFF` / `SVR4_SKIP_FUSE` is set.

use std::fs;
use std::io::Read;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::thread::sleep;
use std::time::{Duration, Instant};

use serde_json::Value;
use sha2::{Digest, Sha256};

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

fn ufs_tool(host_tools: &Path, args: &[&Path]) -> std::process::Output {
    let mut cmd = Command::new("python3");
    cmd.env("PYTHONPATH", host_tools).arg(
        repo_root().join("host-tools-rs/crates/svr4-ufs/tests/ufs_tool.py"),
    );
    for a in args {
        cmd.arg(a);
    }
    cmd.output().expect("run python3 ufs_tool.py")
}

/// Is `mountpoint` currently a live mount? (Checks /proc/mounts.)
fn is_mounted(mountpoint: &Path) -> bool {
    let target = mountpoint.to_string_lossy();
    fs::read_to_string("/proc/mounts")
        .map(|mounts| {
            mounts
                .lines()
                .any(|line| line.split(' ').nth(1) == Some(&target))
        })
        .unwrap_or(false)
}

/// Unmount `mountpoint`, trying fusermount3 then fusermount.
fn fusermount_unmount(mountpoint: &Path) -> bool {
    for tool in ["fusermount3", "fusermount"] {
        let ok = Command::new(tool)
            .arg("-u")
            .arg(mountpoint)
            .status()
            .map(|s| s.success())
            .unwrap_or(false);
        if ok {
            return true;
        }
    }
    false
}

fn have_fuse() -> bool {
    Path::new("/dev/fuse").exists()
        && (Command::new("fusermount3").arg("--version").output().is_ok()
            || Command::new("fusermount").arg("--version").output().is_ok())
}

#[test]
fn fuse_mount_roundtrip_is_fsck_clean() {
    if std::env::var_os("SVR4_SKIP_PYTHON_DIFF").is_some()
        || std::env::var_os("SVR4_SKIP_FUSE").is_some()
    {
        eprintln!("skip flag set; skipping");
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
    if !have_fuse() {
        eprintln!("no usable FUSE lane (/dev/fuse + fusermount); skipping");
        return;
    }

    let dir = tempfile::tempdir().unwrap();
    let blank = dir.path().join("blank.img");
    let out = dir.path().join("out.img");
    let mnt = dir.path().join("mnt");
    let manifest = dir.path().join("manifest.json");
    let daemon_log = dir.path().join("daemon.log");
    fs::create_dir(&mnt).unwrap();

    // 1. Python formats a blank image; work on a copy.
    assert!(
        ufs_tool(&host_tools, &[Path::new("blank"), &blank]).status.success(),
        "blank image format failed"
    );
    fs::copy(&blank, &out).unwrap();

    // 2. Mount it with the daemon (foreground; it blocks until unmounted). Logs
    //    go to a file so we can surface them if the mount never comes up.
    let log_file = fs::File::create(&daemon_log).unwrap();
    let mut child: Child = Command::new(env!("CARGO_BIN_EXE_svr4-ufs-mount"))
        .arg(&out)
        .arg(&mnt)
        .arg("--offset")
        .arg("0")
        .stdout(Stdio::from(log_file.try_clone().unwrap()))
        .stderr(Stdio::from(log_file))
        .spawn()
        .expect("spawn svr4-ufs-mount");

    // Wait for the mount to come up (or the daemon to die trying).
    let deadline = Instant::now() + Duration::from_secs(10);
    let mut mounted = false;
    while Instant::now() < deadline {
        if is_mounted(&mnt) {
            mounted = true;
            break;
        }
        if let Some(status) = child.try_wait().unwrap() {
            let mut log = String::new();
            fs::File::open(&daemon_log).unwrap().read_to_string(&mut log).ok();
            panic!("daemon exited before mounting ({status}):\n{log}");
        }
        sleep(Duration::from_millis(50));
    }
    if !mounted {
        let _ = child.kill();
        let mut log = String::new();
        fs::File::open(&daemon_log).unwrap().read_to_string(&mut log).ok();
        panic!("mount did not come up within 10s:\n{log}");
    }

    // 3. Drive a workload through the kernel. Anything that panics here must
    //    still unmount, so capture the result and tear down afterwards.
    let big: Vec<u8> = (0..4096u64 * 20).map(|i| ((i * 7) & 0xff) as u8).collect();
    let frag: Vec<u8> = (0..3000u32).map(|i| (i & 0xff) as u8).collect();
    let workload = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        fs::create_dir(mnt.join("dir")).unwrap();
        fs::write(mnt.join("dir/small"), b"hello world\n").unwrap();
        fs::write(mnt.join("dir/big"), &big).unwrap();
        fs::write(mnt.join("dir/frag"), &frag).unwrap();

        // Read-back through the daemon while mounted.
        assert_eq!(fs::read(mnt.join("dir/big")).unwrap(), big, "readback of big file");

        // Symlink + hard link.
        std::os::unix::fs::symlink("dir/small", mnt.join("link")).unwrap();
        fs::hard_link(mnt.join("dir/small"), mnt.join("dir/hardlink")).unwrap();

        // Rename within a directory.
        fs::create_dir(mnt.join("dir/sub")).unwrap();
        fs::write(mnt.join("dir/sub/tmp"), b"temp\n").unwrap();
        fs::rename(mnt.join("dir/sub/tmp"), mnt.join("dir/sub/renamed")).unwrap();

        // Move a non-empty directory across parents (exercises '..' rewrite).
        fs::create_dir(mnt.join("dir/movedir")).unwrap();
        fs::write(mnt.join("dir/movedir/f"), b"inside\n").unwrap();
        fs::rename(mnt.join("dir/movedir"), mnt.join("movedir2")).unwrap();

        // Unlink + rmdir.
        fs::write(mnt.join("dir/todelete"), b"x").unwrap();
        fs::remove_file(mnt.join("dir/todelete")).unwrap();
        fs::create_dir(mnt.join("emptydir")).unwrap();
        fs::remove_dir(mnt.join("emptydir")).unwrap();

        // chmod (shared by the hard-linked pair).
        fs::set_permissions(mnt.join("dir/small"), std::os::unix::fs::PermissionsExt::from_mode(0o600))
            .unwrap();
    }));

    // 4. Unmount and wait for the daemon to finish (so destroy runs).
    assert!(fusermount_unmount(&mnt), "fusermount -u failed");
    let exit = child.wait().expect("wait for daemon");
    let mut log = String::new();
    fs::File::open(&daemon_log).unwrap().read_to_string(&mut log).ok();
    assert!(exit.success(), "daemon exited unsuccessfully ({exit}):\n{log}");
    if let Err(payload) = workload {
        std::panic::resume_unwind(payload);
    }

    // 5. Python fsck + manifest of the unmounted image.
    let check = ufs_tool(&host_tools, &[Path::new("check"), &out, &manifest]);
    assert!(
        check.status.success(),
        "python fsck/check failed:\n{}\n--- daemon log ---\n{log}",
        String::from_utf8_lossy(&check.stderr)
    );
    let m: Value = serde_json::from_slice(&fs::read(&manifest).unwrap()).unwrap();
    let obj = m.as_object().unwrap();

    // Content + structure assertions.
    assert_eq!(obj["/dir/small"]["type"], "file");
    assert_eq!(obj["/dir/small"]["sha256"], hex_sha256(b"hello world\n"));
    assert_eq!(obj["/dir/small"]["mode"], 0o100600, "chmod applied");
    assert_eq!(obj["/dir/big"]["sha256"], hex_sha256(&big));
    assert_eq!(obj["/dir/big"]["size"], big.len());
    assert_eq!(obj["/dir/frag"]["sha256"], hex_sha256(&frag));

    // Symlink + hard link.
    assert_eq!(obj["/link"]["type"], "link");
    assert_eq!(obj["/link"]["target"], "dir/small");
    assert_eq!(obj["/dir/hardlink"]["sha256"], obj["/dir/small"]["sha256"]);
    assert_eq!(obj["/dir/hardlink"]["nlink"], 2);
    assert_eq!(obj["/dir/small"]["nlink"], 2);
    assert_eq!(obj["/dir/hardlink"]["mode"], 0o100600, "chmod shared via hard link");

    // Rename within a directory.
    assert!(obj.contains_key("/dir/sub/renamed"));
    assert!(!obj.contains_key("/dir/sub/tmp"));
    assert_eq!(obj["/dir/sub/renamed"]["sha256"], hex_sha256(b"temp\n"));

    // Cross-parent directory move.
    assert!(obj.contains_key("/movedir2"));
    assert_eq!(obj["/movedir2"]["type"], "dir");
    assert_eq!(obj["/movedir2/f"]["sha256"], hex_sha256(b"inside\n"));
    assert!(!obj.contains_key("/dir/movedir"));
    assert!(!obj.contains_key("/dir/movedir/f"));

    // Unlink + rmdir removed their targets.
    assert!(!obj.contains_key("/dir/todelete"));
    assert!(!obj.contains_key("/emptydir"));
}

/// Same as `ufs_tool` but with string args, and used where stdout matters.
fn ufs_tool_str(host_tools: &Path, args: &[&str]) -> std::process::Output {
    let mut cmd = Command::new("python3");
    cmd.env("PYTHONPATH", host_tools)
        .arg(repo_root().join("host-tools-rs/crates/svr4-ufs/tests/ufs_tool.py"));
    for a in args {
        cmd.arg(a);
    }
    cmd.output().expect("run python3 ufs_tool.py")
}

/// Spawn the daemon and block until the mountpoint is live. Panics (after
/// surfacing the daemon log) if it dies or never comes up.
// The returned `Child` is waited on by the caller after it unmounts; clippy
// can't see that across the function boundary.
#[allow(clippy::zombie_processes)]
fn spawn_and_wait_mounted(args: &[&std::ffi::OsStr], mnt: &Path, daemon_log: &Path) -> Child {
    let log_file = fs::File::create(daemon_log).unwrap();
    let mut child = Command::new(env!("CARGO_BIN_EXE_svr4-ufs-mount"))
        .args(args)
        .stdout(Stdio::from(log_file.try_clone().unwrap()))
        .stderr(Stdio::from(log_file))
        .spawn()
        .expect("spawn svr4-ufs-mount");

    let deadline = Instant::now() + Duration::from_secs(10);
    while Instant::now() < deadline {
        if is_mounted(mnt) {
            return child;
        }
        if let Some(status) = child.try_wait().unwrap() {
            let mut log = String::new();
            fs::File::open(daemon_log).unwrap().read_to_string(&mut log).ok();
            panic!("daemon exited before mounting ({status}):\n{log}");
        }
        sleep(Duration::from_millis(50));
    }
    let _ = child.kill();
    let mut log = String::new();
    fs::File::open(daemon_log).unwrap().read_to_string(&mut log).ok();
    panic!("mount did not come up within 10s:\n{log}");
}

/// Mount a *geometried VTOC disk image* by slice name (`--slice root`) — the
/// path the build (`tasks/make_image.py`) uses — and confirm a populate
/// roundtrip through the daemon is fsck-clean at the slice's offset.
#[test]
fn fuse_mount_by_slice_on_disk_image() {
    if std::env::var_os("SVR4_SKIP_PYTHON_DIFF").is_some()
        || std::env::var_os("SVR4_SKIP_FUSE").is_some()
    {
        eprintln!("skip flag set; skipping");
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
    if !have_fuse() {
        eprintln!("no usable FUSE lane; skipping");
        return;
    }

    let dir = tempfile::tempdir().unwrap();
    let img = dir.path().join("disk.img");
    let mnt = dir.path().join("mnt");
    let manifest = dir.path().join("manifest.json");
    let daemon_log = dir.path().join("daemon.log");
    fs::create_dir(&mnt).unwrap();

    // Geometried disk image + formatted UFS root slice; remember the offset.
    let blank = ufs_tool_str(&host_tools, &["disk-blank", img.to_str().unwrap()]);
    assert!(blank.status.success(), "disk-blank: {}", String::from_utf8_lossy(&blank.stderr));
    let offset = String::from_utf8_lossy(&blank.stdout).trim().to_string();

    // Mount by slice name (resolves the offset from the VTOC).
    let args: Vec<&std::ffi::OsStr> = vec![
        img.as_os_str(),
        mnt.as_os_str(),
        "--slice".as_ref(),
        "root".as_ref(),
    ];
    let mut child = spawn_and_wait_mounted(&args, &mnt, &daemon_log);

    let big: Vec<u8> = (0..4096u64 * 20).map(|i| ((i * 11) & 0xff) as u8).collect();
    let workload = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        fs::create_dir(mnt.join("etc")).unwrap();
        fs::write(mnt.join("etc/motd"), b"welcome\n").unwrap();
        fs::write(mnt.join("etc/big"), &big).unwrap();
        assert_eq!(fs::read(mnt.join("etc/big")).unwrap(), big, "readback");
    }));

    assert!(fusermount_unmount(&mnt), "fusermount -u failed");
    let exit = child.wait().expect("wait for daemon");
    let mut log = String::new();
    fs::File::open(&daemon_log).unwrap().read_to_string(&mut log).ok();
    assert!(exit.success(), "daemon exited unsuccessfully ({exit}):\n{log}");
    if let Err(payload) = workload {
        std::panic::resume_unwind(payload);
    }

    // fsck-clean + content at the slice offset.
    let check = ufs_tool_str(
        &host_tools,
        &["disk-check", img.to_str().unwrap(), &offset, manifest.to_str().unwrap()],
    );
    assert!(
        check.status.success(),
        "python fsck/check failed:\n{}\n--- daemon log ---\n{log}",
        String::from_utf8_lossy(&check.stderr)
    );
    let m: Value = serde_json::from_slice(&fs::read(&manifest).unwrap()).unwrap();
    let obj = m.as_object().unwrap();
    assert_eq!(obj["/etc/motd"]["sha256"], hex_sha256(b"welcome\n"));
    assert_eq!(obj["/etc/big"]["sha256"], hex_sha256(&big));
}
