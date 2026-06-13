//! Pin every transcribed on-disk constant against the real C struct layout.
//!
//! Compiles `tests/probe/offsets.c` with `cc -m32` (the on-disk format is 32-bit,
//! so `long`/`daddr_t`/`time_t` are 4 bytes) against the UTS kernel headers and
//! the original-ufs-fsck compat environment, runs it, and asserts every emitted
//! `offsetof`/`sizeof`/magic equals the corresponding constant in `consts.rs`.
//!
//! This is the cheapest possible guard against a transcription error in the
//! hand-copied offset tables: if a constant drifts from the headers, this fails
//! before any logic depends on it. It needs a compiler with 32-bit support
//! (the same requirement as building the fsck oracle). Set `SVR4_SKIP_C_PROBE=1`
//! to skip it in an environment that cannot build 32-bit objects.

use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::process::Command;

use svr4_fs_core::consts::*;

fn repo_root() -> PathBuf {
    // .../svr4-src/host-tools-rs/crates/svr4-fs-core -> .../svr4-src
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .ancestors()
        .nth(3)
        .expect("repo root is three levels above the crate manifest")
        .to_path_buf()
}

/// Compile and run the probe, returning the parsed `KEY=VALUE` pairs.
fn run_probe() -> HashMap<String, i64> {
    let root = repo_root();
    let manifest = Path::new(env!("CARGO_MANIFEST_DIR"));
    let probe = manifest.join("tests/probe/offsets.c");
    let port = root.join("host-tools/original-ufs-fsck");

    let out_dir = tempfile::tempdir().expect("create temp dir for probe binary");
    let binary = out_dir.path().join("offprobe");

    // Same flags the fsck oracle build uses (host_tools/fs/ufs_fsck_original.py).
    let compile = Command::new("cc")
        .args([
            "-m32",
            "-std=gnu89",
            "-fcommon",
            "-Wno-implicit-int",
            "-Wno-implicit-function-declaration",
            "-Wno-return-type",
            "-Wno-int-conversion",
        ])
        .arg(format!("-I{}", port.join("compat").display()))
        .arg(format!("-I{}", port.display()))
        .arg(format!("-I{}", root.join("uts/i386").display()))
        .arg("-o")
        .arg(&binary)
        .arg(&probe)
        .output()
        .expect("failed to invoke cc; install a C compiler with 32-bit support");

    assert!(
        compile.status.success(),
        "offset probe failed to compile:\n{}",
        String::from_utf8_lossy(&compile.stderr)
    );

    let run = Command::new(&binary)
        .output()
        .expect("failed to run the compiled offset probe");
    assert!(run.status.success(), "offset probe exited with failure");

    let stdout = String::from_utf8(run.stdout).expect("probe output is utf-8");
    stdout
        .lines()
        .filter_map(|line| {
            let (key, value) = line.split_once('=')?;
            Some((key.to_string(), value.trim().parse::<i64>().ok()?))
        })
        .collect()
}

#[test]
fn rust_constants_match_c_struct_layout() {
    if std::env::var_os("SVR4_SKIP_C_PROBE").is_some() {
        eprintln!("SVR4_SKIP_C_PROBE set; skipping C layout assertion");
        return;
    }

    let probe = run_probe();

    // (probe key, rust constant). Every value the probe emits must appear here,
    // and vice versa, so neither side can silently grow an unchecked constant.
    let expected: &[(&str, i64)] = &[
        // struct fs
        ("UFS_FS_SBLKNO_OFFSET", UFS_FS_SBLKNO_OFFSET as i64),
        ("UFS_FS_CBLKNO_OFFSET", UFS_FS_CBLKNO_OFFSET as i64),
        ("UFS_FS_IBLKNO_OFFSET", UFS_FS_IBLKNO_OFFSET as i64),
        ("UFS_FS_DBLKNO_OFFSET", UFS_FS_DBLKNO_OFFSET as i64),
        ("UFS_FS_CGOFFSET_OFFSET", UFS_FS_CGOFFSET_OFFSET as i64),
        ("UFS_FS_CGMASK_OFFSET", UFS_FS_CGMASK_OFFSET as i64),
        ("UFS_FS_TIME_OFFSET", UFS_FS_TIME_OFFSET as i64),
        ("UFS_FS_SIZE_OFFSET", UFS_FS_SIZE_OFFSET as i64),
        ("UFS_FS_DSIZE_OFFSET", UFS_FS_DSIZE_OFFSET as i64),
        ("UFS_FS_NCG_OFFSET", UFS_FS_NCG_OFFSET as i64),
        ("UFS_FS_BSIZE_OFFSET", UFS_FS_BSIZE_OFFSET as i64),
        ("UFS_FS_FSIZE_OFFSET", UFS_FS_FSIZE_OFFSET as i64),
        ("UFS_FS_FRAG_OFFSET", UFS_FS_FRAG_OFFSET as i64),
        ("UFS_FS_MINFREE_OFFSET", UFS_FS_MINFREE_OFFSET as i64),
        ("UFS_FS_ROTDLY_OFFSET", UFS_FS_ROTDLY_OFFSET as i64),
        ("UFS_FS_RPS_OFFSET", UFS_FS_RPS_OFFSET as i64),
        ("UFS_FS_BMASK_OFFSET", UFS_FS_BMASK_OFFSET as i64),
        ("UFS_FS_FMASK_OFFSET", UFS_FS_FMASK_OFFSET as i64),
        ("UFS_FS_BSHIFT_OFFSET", UFS_FS_BSHIFT_OFFSET as i64),
        ("UFS_FS_FSHIFT_OFFSET", UFS_FS_FSHIFT_OFFSET as i64),
        ("UFS_FS_MAXCONTIG_OFFSET", UFS_FS_MAXCONTIG_OFFSET as i64),
        ("UFS_FS_MAXBPG_OFFSET", UFS_FS_MAXBPG_OFFSET as i64),
        ("UFS_FS_FRAGSHIFT_OFFSET", UFS_FS_FRAGSHIFT_OFFSET as i64),
        ("UFS_FS_FSBTODB_OFFSET", UFS_FS_FSBTODB_OFFSET as i64),
        ("UFS_FS_SBSIZE_OFFSET", UFS_FS_SBSIZE_OFFSET as i64),
        ("UFS_FS_CSMASK_OFFSET", UFS_FS_CSMASK_OFFSET as i64),
        ("UFS_FS_CSSHIFT_OFFSET", UFS_FS_CSSHIFT_OFFSET as i64),
        ("UFS_FS_NINDIR_OFFSET", UFS_FS_NINDIR_OFFSET as i64),
        ("UFS_FS_INOPB_OFFSET", UFS_FS_INOPB_OFFSET as i64),
        ("UFS_FS_NSPF_OFFSET", UFS_FS_NSPF_OFFSET as i64),
        ("UFS_FS_OPTIM_OFFSET", UFS_FS_OPTIM_OFFSET as i64),
        ("UFS_FS_STATE_OFFSET", UFS_FS_STATE_OFFSET as i64),
        ("UFS_FS_CSADDR_OFFSET", UFS_FS_CSADDR_OFFSET as i64),
        ("UFS_FS_CSSIZE_OFFSET", UFS_FS_CSSIZE_OFFSET as i64),
        ("UFS_FS_CGSIZE_OFFSET", UFS_FS_CGSIZE_OFFSET as i64),
        ("UFS_FS_NTRAK_OFFSET", UFS_FS_NTRAK_OFFSET as i64),
        ("UFS_FS_NSECT_OFFSET", UFS_FS_NSECT_OFFSET as i64),
        ("UFS_FS_SPC_OFFSET", UFS_FS_SPC_OFFSET as i64),
        ("UFS_FS_NCYL_OFFSET", UFS_FS_NCYL_OFFSET as i64),
        ("UFS_FS_CPG_OFFSET", UFS_FS_CPG_OFFSET as i64),
        ("UFS_FS_IPG_OFFSET", UFS_FS_IPG_OFFSET as i64),
        ("UFS_FS_FPG_OFFSET", UFS_FS_FPG_OFFSET as i64),
        ("UFS_FS_CSTOTAL_NDIR_OFFSET", UFS_FS_CSTOTAL_NDIR_OFFSET as i64),
        ("UFS_FS_CSTOTAL_NBFREE_OFFSET", UFS_FS_CSTOTAL_NBFREE_OFFSET as i64),
        ("UFS_FS_CSTOTAL_NIFREE_OFFSET", UFS_FS_CSTOTAL_NIFREE_OFFSET as i64),
        ("UFS_FS_CSTOTAL_NFFREE_OFFSET", UFS_FS_CSTOTAL_NFFREE_OFFSET as i64),
        ("UFS_FS_FMOD_OFFSET", UFS_FS_FMOD_OFFSET as i64),
        ("UFS_FS_CLEAN_OFFSET", UFS_FS_CLEAN_OFFSET as i64),
        ("UFS_FS_RONLY_OFFSET", UFS_FS_RONLY_OFFSET as i64),
        ("UFS_FS_MAGIC_OFFSET", UFS_FS_MAGIC_OFFSET as i64),
        // struct cg
        ("UFS_CG_TIME_OFFSET", UFS_CG_TIME_OFFSET as i64),
        ("UFS_CG_CGX_OFFSET", UFS_CG_CGX_OFFSET as i64),
        ("UFS_CG_NCYL_OFFSET", UFS_CG_NCYL_OFFSET as i64),
        ("UFS_CG_NIBLK_OFFSET", UFS_CG_NIBLK_OFFSET as i64),
        ("UFS_CG_NDBLK_OFFSET", UFS_CG_NDBLK_OFFSET as i64),
        ("UFS_CG_CS_NDIR_OFFSET", UFS_CG_CS_NDIR_OFFSET as i64),
        ("UFS_CG_CS_NBFREE_OFFSET", UFS_CG_CS_NBFREE_OFFSET as i64),
        ("UFS_CG_CS_NIFREE_OFFSET", UFS_CG_CS_NIFREE_OFFSET as i64),
        ("UFS_CG_CS_NFFREE_OFFSET", UFS_CG_CS_NFFREE_OFFSET as i64),
        ("UFS_CG_ROTOR_OFFSET", UFS_CG_ROTOR_OFFSET as i64),
        ("UFS_CG_FROTOR_OFFSET", UFS_CG_FROTOR_OFFSET as i64),
        ("UFS_CG_IROTOR_OFFSET", UFS_CG_IROTOR_OFFSET as i64),
        ("UFS_CG_FRSUM_OFFSET", UFS_CG_FRSUM_OFFSET as i64),
        ("UFS_CG_BTOT_OFFSET", UFS_CG_BTOT_OFFSET as i64),
        ("UFS_CG_B_OFFSET", UFS_CG_B_OFFSET as i64),
        ("UFS_CG_IUSED_OFFSET", UFS_CG_IUSED_OFFSET as i64),
        ("UFS_CG_MAGIC_OFFSET", UFS_CG_MAGIC_OFFSET as i64),
        ("UFS_CG_FREE_OFFSET", UFS_CG_FREE_OFFSET as i64),
        // struct icommon
        ("UFS_DI_SMODE_OFFSET", UFS_DI_SMODE_OFFSET as i64),
        ("UFS_DI_NLINK_OFFSET", UFS_DI_NLINK_OFFSET as i64),
        ("UFS_DI_SUID_OFFSET", UFS_DI_SUID_OFFSET as i64),
        ("UFS_DI_SGID_OFFSET", UFS_DI_SGID_OFFSET as i64),
        ("UFS_DI_SIZE_OFFSET", UFS_DI_SIZE_OFFSET as i64),
        ("UFS_DI_ATIME_OFFSET", UFS_DI_ATIME_OFFSET as i64),
        ("UFS_DI_MTIME_OFFSET", UFS_DI_MTIME_OFFSET as i64),
        ("UFS_DI_CTIME_OFFSET", UFS_DI_CTIME_OFFSET as i64),
        ("UFS_DI_DB_OFFSET", UFS_DI_DB_OFFSET as i64),
        ("UFS_DI_IB_OFFSET", UFS_DI_IB_OFFSET as i64),
        ("UFS_DI_FLAGS_OFFSET", UFS_DI_FLAGS_OFFSET as i64),
        ("UFS_DI_BLOCKS_OFFSET", UFS_DI_BLOCKS_OFFSET as i64),
        ("UFS_DI_GEN_OFFSET", UFS_DI_GEN_OFFSET as i64),
        ("UFS_DI_MODE_OFFSET", UFS_DI_MODE_OFFSET as i64),
        ("UFS_DI_UID_OFFSET", UFS_DI_UID_OFFSET as i64),
        ("UFS_DI_GID_OFFSET", UFS_DI_GID_OFFSET as i64),
        ("UFS_DI_EFTFLAG_OFFSET", UFS_DI_EFTFLAG_OFFSET as i64),
        // struct direct
        ("UFS_DIRENT_INO_OFFSET", UFS_DIRENT_INO_OFFSET as i64),
        ("UFS_DIRENT_RECLEN_OFFSET", UFS_DIRENT_RECLEN_OFFSET as i64),
        ("UFS_DIRENT_NAMLEN_OFFSET", UFS_DIRENT_NAMLEN_OFFSET as i64),
        ("UFS_DIRENT_NAME_OFFSET", UFS_DIRENT_NAME_OFFSET as i64),
        // sizes & dimensioning
        ("UFS_DINODE_SIZE", UFS_DINODE_SIZE as i64),
        ("UFS_CSUM_SIZE", UFS_CSUM_SIZE as i64),
        ("UFS_SB_SIZE", UFS_SB_SIZE as i64),
        ("UFS_DIRBLKSIZ", UFS_DIRBLKSIZ as i64),
        ("UFS_NDADDR", UFS_NDADDR as i64),
        ("UFS_NIADDR", UFS_NIADDR as i64),
        ("NBBY", NBBY as i64),
        ("MAXFRAG", MAXFRAG as i64),
        ("MAXCPG", MAXCPG as i64),
        ("MAXIPG", MAXIPG as i64),
        ("NRPOS", NRPOS as i64),
        // magics & misc
        ("UFS_MAGIC", UFS_MAGIC as i64),
        ("UFS_CG_MAGIC", UFS_CG_MAGIC as i64),
        ("UFS_EFT_MAGIC", UFS_EFT_MAGIC as i64),
        ("UFS_FS_OKAY", UFS_FS_OKAY as i64),
        ("UFS_ROOT_INODE", UFS_ROOT_INODE as i64),
        ("UFS_SB_OFFSET", UFS_SB_OFFSET as i64),
    ];

    let mut mismatches = Vec::new();
    for (key, rust_value) in expected {
        match probe.get(*key) {
            Some(c_value) if c_value == rust_value => {}
            Some(c_value) => {
                mismatches.push(format!("{key}: rust={rust_value} c={c_value}"));
            }
            None => mismatches.push(format!("{key}: missing from probe output")),
        }
    }

    // Catch the reverse: a probe key with no Rust counterpart in the table.
    let expected_keys: std::collections::HashSet<&str> =
        expected.iter().map(|(k, _)| *k).collect();
    for key in probe.keys() {
        if !expected_keys.contains(key.as_str()) {
            mismatches.push(format!("{key}: emitted by probe but not asserted in Rust"));
        }
    }

    assert!(
        mismatches.is_empty(),
        "layout constant mismatches vs C headers:\n  {}",
        mismatches.join("\n  ")
    );
}
