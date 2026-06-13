//! Self-contained tests built on the Rust consistency checker (no Python/C).
//!
//! Two jobs: (1) prove the checker itself catches corruption (otherwise a clean
//! result means nothing), and (2) exercise the write path across the block /
//! fragment / indirect-block boundaries where off-by-one bugs love to hide,
//! asserting the result stays consistent.

use svr4_fs_core::codec::put_u32;
use svr4_fs_core::consts::UFS_DI_BLOCKS_OFFSET;
use svr4_ufs::{
    check_filesystem, create_file, format, make_directory, read_inode, read_inode_bytes,
    resolve_path, FormatOptions, Ufs,
};
use svr4_ufs::alloc::recompute_summary_counts;

/// A fresh in-memory geometried filesystem (no files, no I/O).
fn fresh(cylinders: u64, heads: u32, sectors: u32, block_size: u64) -> (Vec<u8>, Ufs) {
    let size = cylinders * u64::from(heads) * u64::from(sectors) * 512;
    let mut image = vec![0u8; size as usize];
    let opts = FormatOptions {
        block_size,
        tracks_per_cylinder: Some(heads),
        sectors_per_track: Some(sectors),
        ..FormatOptions::default()
    };
    let ufs = format(&mut image, 0, size, &opts).unwrap();
    (image, ufs)
}

/// Default 8 MiB test fs: 4 KiB blocks, 512-byte fragments.
fn fresh_default() -> (Vec<u8>, Ufs) {
    fresh(64, 8, 32, 4096)
}

fn assert_clean(image: &[u8], ufs: &Ufs, context: &str) {
    let problems = check_filesystem(image, ufs);
    assert!(problems.is_empty(), "{context}: expected clean, got:\n  {}", problems.join("\n  "));
}

#[test]
fn empty_filesystem_is_clean() {
    let (image, ufs) = fresh_default();
    assert_clean(&image, &ufs, "freshly formatted");
}

#[test]
fn checker_flags_corrupt_di_blocks() {
    let (mut image, ufs) = fresh_default();
    create_file(&mut image, &ufs, "/f", b"hello", 0o644, 0, 0, 0).unwrap();
    recompute_summary_counts(&mut image, &ufs).unwrap();
    assert_clean(&image, &ufs, "before corruption");

    // Corrupt the file inode's di_blocks field.
    let (ino, _) = resolve_path(&image, &ufs, "/f").unwrap();
    let off = ufs.sb.inode_byte_offset(ufs.start_offset, ino as i64) as usize;
    put_u32(&mut image, off + UFS_DI_BLOCKS_OFFSET, 999);
    let problems = check_filesystem(&image, &ufs);
    assert!(
        problems.iter().any(|p| p.contains("di_blocks")),
        "checker should flag the bad di_blocks, got: {problems:?}"
    );
}

#[test]
fn checker_flags_bitmap_leak() {
    let (mut image, ufs) = fresh_default();
    create_file(&mut image, &ufs, "/f", &vec![b'x'; 9000], 0o644, 0, 0, 0).unwrap();
    recompute_summary_counts(&mut image, &ufs).unwrap();
    assert_clean(&image, &ufs, "before corruption");

    // Mark a fragment allocated in cg 0's bitmap that no inode references.
    let mut cg0 = svr4_ufs::alloc::read_cg_block(&image, &ufs, 0);
    // Pick a data fragment well past the metadata that is currently free.
    let data_start = ufs.sb.cgdmin(0) - ufs.sb.cgbase(0);
    let victim = data_start + 200;
    svr4_ufs::alloc::set_frag_state(&mut cg0, victim, false); // false = used
    svr4_ufs::alloc::write_cg_block(&mut image, &ufs, 0, &cg0);
    let problems = check_filesystem(&image, &ufs);
    assert!(
        problems.iter().any(|p| p.contains("leak")),
        "checker should flag the leaked fragment, got: {problems:?}"
    );
}

#[test]
fn checker_flags_bad_nlink() {
    let (mut image, ufs) = fresh_default();
    create_file(&mut image, &ufs, "/f", b"hi", 0o644, 0, 0, 0).unwrap();
    recompute_summary_counts(&mut image, &ufs).unwrap();
    let (ino, _) = resolve_path(&image, &ufs, "/f").unwrap();
    // nlink is the u16 at the start+? — use the inode field offset.
    use svr4_fs_core::codec::put_u16;
    use svr4_fs_core::consts::UFS_DI_NLINK_OFFSET;
    let off = ufs.sb.inode_byte_offset(ufs.start_offset, ino as i64) as usize;
    put_u16(&mut image, off + UFS_DI_NLINK_OFFSET, 7);
    let problems = check_filesystem(&image, &ufs);
    assert!(
        problems.iter().any(|p| p.contains("nlink")),
        "checker should flag the wrong nlink, got: {problems:?}"
    );
}

/// File sizes straddling every interesting boundary: empty, sub-fragment,
/// fragment multiples, exact block, multi-block, the last direct block, and the
/// first few that require single indirect blocks. Each must read back exactly
/// and leave the filesystem consistent.
#[test]
fn file_size_boundaries_stay_consistent() {
    // bsize 4096, fsize 512, frag 8, NDADDR 12 -> direct limit 49152.
    let sizes: &[usize] = &[
        0, 1, 7, 511, 512, 513, 1024, 4095, 4096, 4097, 8192, 12288, // direct, frag tails
        49152 - 1, 49152, 49152 + 1, 49152 + 512, 49152 + 4096, // direct->indirect crossing
        49152 + 4096 * 8, 200_000, // deeper into single indirect
    ];
    for &size in sizes {
        let (mut image, ufs) = fresh(64, 16, 32, 4096); // 16 MiB: room for the big ones
        let content: Vec<u8> = (0..size).map(|i| ((i * 31 + 7) & 0xff) as u8).collect();
        create_file(&mut image, &ufs, "/data", &content, 0o644, 0, 0, 0).unwrap();
        recompute_summary_counts(&mut image, &ufs).unwrap();
        assert_clean(&image, &ufs, &format!("file of {size} bytes"));
        let (ino, inode) = resolve_path(&image, &ufs, "/data").unwrap();
        assert_eq!(inode.size as usize, size, "size {size}: stored size");
        let read = read_inode_bytes(&image, &ufs, &read_inode(&image, &ufs, ino as i64).unwrap());
        assert_eq!(read, content, "file of {size} bytes read back wrong");
    }
}

/// A directory grown well past the direct-block limit (into indirect blocks)
/// must stay consistent, with every entry resolvable.
#[test]
fn directory_crossing_indirect_blocks_is_consistent() {
    let (mut image, ufs) = fresh(128, 16, 63, 4096); // ~64 MiB, plenty of inodes
    make_directory(&mut image, &ufs, "/d", 0o755, 0, 0, 0).unwrap();
    const N: usize = 4000; // dir size >> 12*4096, forces indirect
    for i in 0..N {
        create_file(&mut image, &ufs, &format!("/d/f{i:05}"), b"x", 0o644, 0, 0, 0).unwrap();
    }
    recompute_summary_counts(&mut image, &ufs).unwrap();
    assert_clean(&image, &ufs, "4000-entry directory");
    // Spot-check resolvability of first/last entries.
    assert!(resolve_path(&image, &ufs, "/d/f00000").is_some());
    assert!(resolve_path(&image, &ufs, &format!("/d/f{:05}", N - 1)).is_some());
}
