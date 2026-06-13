//! A self-contained UFS consistency checker (a small `fsck`), used as the test
//! oracle so the suite needs no Python/C fixtures.
//!
//! [`check_filesystem`] reconstructs what the filesystem *should* look like by
//! walking the inodes, and compares that against the on-disk bitmaps, counts,
//! and link counts. It catches exactly the class of "silly" bugs that slip past
//! a read-back round-trip: double-allocated or leaked fragments, a wrong
//! `di_blocks`, a free-bitmap that disagrees with the inodes, summary counts
//! that have drifted, and broken directory link counts. (The `allocation_byte_sizes`
//! fragment-tail bug, for instance, showed up here as a `di_blocks` + bitmap
//! mismatch.)
//!
//! It returns a list of human-readable problems; an empty list means clean.

use std::collections::HashMap;

use svr4_fs_core::codec::{i32 as read_i32, u32};
use svr4_fs_core::consts::{
    SECTOR_SIZE, UFS_CG_CS_NBFREE_OFFSET, UFS_CG_CS_NDIR_OFFSET, UFS_CG_CS_NFFREE_OFFSET,
    UFS_CG_CS_NIFREE_OFFSET, UFS_CG_NDBLK_OFFSET, UFS_FS_CSTOTAL_NBFREE_OFFSET,
    UFS_FS_CSTOTAL_NDIR_OFFSET, UFS_FS_CSTOTAL_NFFREE_OFFSET, UFS_FS_CSTOTAL_NIFREE_OFFSET,
    UFS_ROOT_INODE,
};

use crate::alloc::{is_frag_free, is_inode_used, read_cg_block};
use crate::inode::{inode_data_blocks, inode_pointer_blocks, read_inode};
use crate::reader::iter_directory_entries;
use crate::superblock::Ufs;

/// Run all consistency checks; returns one string per problem found.
pub fn check_filesystem(image: &[u8], ufs: &Ufs) -> Vec<String> {
    let sb = &ufs.sb;
    let mut problems = Vec::new();
    let cgs: Vec<Vec<u8>> = (0..sb.ncg).map(|cg| read_cg_block(image, ufs, cg)).collect();

    // fragment -> owning inode, for double-allocation detection.
    let mut owner: HashMap<i64, i64> = HashMap::new();
    let mut used_inodes: Vec<i64> = Vec::new();

    // --- pass 1: walk used inodes, account their blocks, check di_blocks ----
    for cg in 0..sb.ncg {
        for local in 0..sb.ipg {
            let ino = cg * sb.ipg + local;
            if cg == 0 && ino < UFS_ROOT_INODE as i64 {
                continue; // inodes 0 and 1 are reserved
            }
            if !is_inode_used(&cgs[cg as usize], local) {
                continue;
            }
            let Some(inode) = read_inode(image, ufs, ino) else {
                problems.push(format!("inode {ino}: marked used but unreadable"));
                continue;
            };
            used_inodes.push(ino);

            let data_blocks = inode_data_blocks(image, ufs, &inode);
            let alloc = sb.allocation_byte_sizes(inode.size as i64);
            if data_blocks.len() != alloc.len() {
                problems.push(format!(
                    "inode {ino}: {} data blocks but allocation list has {} entries",
                    data_blocks.len(),
                    alloc.len()
                ));
            }
            let mut frags = 0i64;
            for (i, &block) in data_blocks.iter().enumerate() {
                let alloc_bytes = alloc.get(i).copied().unwrap_or(sb.bsize);
                let nfrags = alloc_bytes / sb.fsize;
                claim_run(&mut owner, &mut problems, ino, block as i64, nfrags, sb.dsize, "data");
                frags += nfrags;
            }
            for &pointer in inode_pointer_blocks(image, ufs, &inode).iter() {
                claim_run(&mut owner, &mut problems, ino, pointer as i64, sb.frag, sb.dsize, "indirect");
                frags += sb.frag;
            }

            let expected_sectors = frags * (sb.fsize / SECTOR_SIZE as i64);
            if inode.blocks as i64 != expected_sectors {
                problems.push(format!(
                    "inode {ino}: di_blocks={} but allocations total {expected_sectors} sectors (size={})",
                    inode.blocks, inode.size
                ));
            }
        }
    }

    // --- pass 2: free-bitmap reconstruction (leaks / phantom allocations) ---
    for cg in 0..sb.ncg {
        let cg_bytes = &cgs[cg as usize];
        let cg_ndblk = u32(cg_bytes, UFS_CG_NDBLK_OFFSET) as i64;
        let data_start = sb.cgdmin(cg) - sb.cgbase(cg);
        let base = sb.cgbase(cg);
        for local_frag in data_start..cg_ndblk {
            let abs_frag = base + local_frag;
            let referenced = owner.contains_key(&abs_frag);
            let marked_free = is_frag_free(cg_bytes, local_frag);
            if referenced && marked_free {
                problems.push(format!(
                    "fragment {abs_frag} (cg {cg}) is used by inode {} but the bitmap marks it free",
                    owner[&abs_frag]
                ));
            } else if !referenced && !marked_free {
                problems.push(format!(
                    "fragment {abs_frag} (cg {cg}) is marked allocated but no inode references it (leak)"
                ));
            }
        }
    }

    // --- pass 3: directory tree + link counts ------------------------------
    // ref_count[ino] = number of directory records (incl. "." / "..") pointing
    // at it across the whole filesystem; for a consistent fs this equals nlink.
    let mut ref_count: HashMap<i64, u32> = HashMap::new();
    let used_set: std::collections::HashSet<i64> = used_inodes.iter().copied().collect();
    for &ino in &used_inodes {
        let Some(inode) = read_inode(image, ufs, ino) else { continue };
        if !inode.is_directory() {
            continue;
        }
        let mut saw_dot = false;
        let mut saw_dotdot = false;
        for entry in iter_directory_entries(image, ufs, &inode) {
            let child = entry.inode as i64;
            *ref_count.entry(child).or_insert(0) += 1;
            if entry.name == "." {
                saw_dot = true;
                if child != ino {
                    problems.push(format!("directory {ino}: '.' points to {child}, not itself"));
                }
            } else if entry.name == ".." {
                saw_dotdot = true;
            } else if !used_set.contains(&child) {
                problems.push(format!(
                    "directory {ino}: entry {:?} points to unused/invalid inode {child}",
                    entry.name
                ));
            }
        }
        if !saw_dot {
            problems.push(format!("directory {ino}: missing '.' entry"));
        }
        if !saw_dotdot {
            problems.push(format!("directory {ino}: missing '..' entry"));
        }
    }
    for &ino in &used_inodes {
        let Some(inode) = read_inode(image, ufs, ino) else { continue };
        let refs = ref_count.get(&ino).copied().unwrap_or(0);
        if ino != UFS_ROOT_INODE as i64 && refs == 0 {
            problems.push(format!("inode {ino}: used but not referenced by any directory (orphan)"));
        }
        if refs != u32::from(inode.nlink) {
            problems.push(format!(
                "inode {ino}: nlink={} but {refs} directory entries reference it",
                inode.nlink
            ));
        }
    }

    // --- pass 4: summary counts (cstotal == sum of cg counts) --------------
    let so = ufs.super_offset as usize;
    let mut sum_ndir = 0i64;
    let mut sum_nbfree = 0i64;
    let mut sum_nifree = 0i64;
    let mut sum_nffree = 0i64;
    for cg_bytes in &cgs {
        sum_ndir += u32(cg_bytes, UFS_CG_CS_NDIR_OFFSET) as i64;
        sum_nbfree += u32(cg_bytes, UFS_CG_CS_NBFREE_OFFSET) as i64;
        sum_nifree += u32(cg_bytes, UFS_CG_CS_NIFREE_OFFSET) as i64;
        sum_nffree += u32(cg_bytes, UFS_CG_CS_NFFREE_OFFSET) as i64;
    }
    let check_total = |problems: &mut Vec<String>, name: &str, off: usize, cg_sum: i64| {
        let stored = read_i32(image, so + off) as i64;
        if stored != cg_sum {
            problems.push(format!(
                "superblock cstotal.{name}={stored} but cylinder groups sum to {cg_sum}"
            ));
        }
    };
    check_total(&mut problems, "ndir", UFS_FS_CSTOTAL_NDIR_OFFSET, sum_ndir);
    check_total(&mut problems, "nbfree", UFS_FS_CSTOTAL_NBFREE_OFFSET, sum_nbfree);
    check_total(&mut problems, "nifree", UFS_FS_CSTOTAL_NIFREE_OFFSET, sum_nifree);
    check_total(&mut problems, "nffree", UFS_FS_CSTOTAL_NFFREE_OFFSET, sum_nffree);

    problems
}

/// Claim `count` fragments starting at `start` for `inode`, recording double
/// references and out-of-range fragments.
fn claim_run(
    owner: &mut HashMap<i64, i64>,
    problems: &mut Vec<String>,
    inode: i64,
    start: i64,
    count: i64,
    total_frags: i64,
    kind: &str,
) {
    for f in 0..count {
        let frag = start + f;
        if frag < 0 || frag >= total_frags {
            problems.push(format!("inode {inode}: {kind} fragment {frag} is out of range"));
            continue;
        }
        if let Some(&other) = owner.get(&frag) {
            problems.push(format!(
                "fragment {frag} is referenced by both inode {other} and inode {inode} ({kind})"
            ));
        } else {
            owner.insert(frag, inode);
        }
    }
}
