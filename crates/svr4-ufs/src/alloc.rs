//! UFS allocation primitives and summary maintenance.
//!
//! Port of the allocation half of `host_tools/fs/ufs_lowlevel.py` and the
//! summary-recompute functions in `host_tools/fs/ufs.py`
//! (`_write_ufs_summary_counts`, `expected_ufs_cg_header`, and helpers).
//!
//! All functions operate on the full in-memory image as `&mut [u8]` (reads use a
//! shared reborrow), mirroring the Python `bytearray` handling. The incremental
//! `adjust_*` updates keep the cylinder-group and superblock counts roughly in
//! step during a populate; [`recompute_summary_counts`] then rebuilds every
//! cylinder-group header and the on-disk summary (`fs_cs`) area exactly, which is
//! what `fsck` pass 5 validates.

use svr4_fs_core::codec::{put_u16, put_u32, u32};
use svr4_fs_core::consts::{
    MAXCPG, MAXFRAG, NBBY, NRPOS, UFS_CG_BTOT_OFFSET, UFS_CG_B_OFFSET, UFS_CG_CGX_OFFSET,
    UFS_CG_CS_NBFREE_OFFSET, UFS_CG_CS_NDIR_OFFSET, UFS_CG_CS_NFFREE_OFFSET, UFS_CG_CS_NIFREE_OFFSET,
    UFS_CG_FREE_OFFSET, UFS_CG_FROTOR_OFFSET, UFS_CG_FRSUM_OFFSET, UFS_CG_IROTOR_OFFSET,
    UFS_CG_IUSED_OFFSET, UFS_CG_MAGIC, UFS_CG_MAGIC_OFFSET, UFS_CG_NCYL_OFFSET, UFS_CG_NDBLK_OFFSET,
    UFS_CG_NIBLK_OFFSET, UFS_CG_ROTOR_OFFSET, UFS_CG_TIME_OFFSET, UFS_CSUM_SIZE,
    UFS_FS_CSTOTAL_NBFREE_OFFSET, UFS_FS_CSTOTAL_NDIR_OFFSET, UFS_FS_CSTOTAL_NFFREE_OFFSET,
    UFS_FS_CSTOTAL_NIFREE_OFFSET,
};

use crate::inode::read_inode;
use crate::superblock::Ufs;

// --- bitmap accessors -------------------------------------------------------

pub fn is_frag_free(cg: &[u8], frag_index: i64) -> bool {
    let byte = cg[UFS_CG_FREE_OFFSET + (frag_index / NBBY as i64) as usize];
    (byte & (1 << (frag_index % NBBY as i64))) != 0
}

pub fn set_frag_state(cg: &mut [u8], frag_index: i64, free: bool) {
    let byte_offset = UFS_CG_FREE_OFFSET + (frag_index / NBBY as i64) as usize;
    let mask = 1u8 << (frag_index % NBBY as i64);
    if free {
        cg[byte_offset] |= mask;
    } else {
        cg[byte_offset] &= !mask;
    }
}

pub fn is_inode_used(cg: &[u8], inode_index: i64) -> bool {
    let byte = cg[UFS_CG_IUSED_OFFSET + (inode_index / NBBY as i64) as usize];
    (byte & (1 << (inode_index % NBBY as i64))) != 0
}

pub fn set_inode_state(cg: &mut [u8], inode_index: i64, used: bool) {
    let byte_offset = UFS_CG_IUSED_OFFSET + (inode_index / NBBY as i64) as usize;
    let mask = 1u8 << (inode_index % NBBY as i64);
    if used {
        cg[byte_offset] |= mask;
    } else {
        cg[byte_offset] &= !mask;
    }
}

/// The `frags_per_block` free-bits window starting at `frag_index`, as a small
/// integer. Port of `_frag_block_free_bits`.
fn frag_block_free_bits(cg: &[u8], frag_index: i64, frags_per_block: i64) -> u64 {
    if frags_per_block <= 0 {
        return 0;
    }
    let bit_offset = (frag_index % NBBY as i64) as u32;
    let byte_offset = UFS_CG_FREE_OFFSET + (frag_index / NBBY as i64) as usize;
    let bits_to_cover = bit_offset as usize + frags_per_block as usize;
    let bytes_to_cover = bits_to_cover.div_ceil(NBBY);
    let mut window: u64 = 0;
    for i in 0..bytes_to_cover {
        window |= (cg[byte_offset + i] as u64) << (8 * i);
    }
    (window >> bit_offset) & ((1u64 << frags_per_block) - 1)
}

// --- cylinder-group block I/O ----------------------------------------------

fn cg_block_offset(ufs: &Ufs, cg: i64) -> usize {
    (ufs.start_offset as i64 + ufs.sb.fsbtobytes(ufs.sb.cgtod(cg))) as usize
}

pub fn read_cg_block(image: &[u8], ufs: &Ufs, cg: i64) -> Vec<u8> {
    let offset = cg_block_offset(ufs, cg);
    let block_size = ufs.sb.bsize as usize;
    image[offset..offset + block_size].to_vec()
}

pub fn write_cg_block(image: &mut [u8], ufs: &Ufs, cg: i64, cg_bytes: &[u8]) {
    let offset = cg_block_offset(ufs, cg);
    image[offset..offset + cg_bytes.len()].copy_from_slice(cg_bytes);
}

/// Number of data fragments in cylinder group `cg`. Port of `ufs_cg_data_frag_count`.
fn cg_data_frag_count(ufs: &Ufs, cg: i64) -> i64 {
    let frags_per_group = ufs.sb.fpg;
    let total_data_frags = if ufs.sb.dsize != 0 {
        ufs.sb.dsize
    } else {
        frags_per_group * ufs.sb.ncg
    };
    let remaining = total_data_frags - cg * frags_per_group;
    if remaining <= 0 {
        0
    } else {
        frags_per_group.min(remaining)
    }
}

fn looks_like_pristine_cg(cg: &[u8]) -> bool {
    cg.iter().all(|&b| b == 0)
}

/// Initialise a never-written cylinder group. Port of `initialize_pristine_ufs_cg`.
/// Used by the write path on first touch of a CG, and by the formatter to lay
/// every CG out from scratch.
pub fn initialize_pristine_cg(image: &mut [u8], ufs: &Ufs, cg: i64) -> Vec<u8> {
    let sb = &ufs.sb;
    let mut cg_bytes = vec![0u8; sb.bsize as usize];
    let cg_ndblk = cg_data_frag_count(ufs, cg);
    let data_start_frag = sb.cgdmin(cg) % sb.fpg;
    let free_fragments = (cg_ndblk - data_start_frag).max(0);
    let free_blocks = free_fragments / sb.frag;
    let free_fragment_remainder = free_fragments % sb.frag;

    let cg_ncyl = if sb.cpg > 0 {
        if cg == sb.ncg - 1 {
            sb.ncyl % sb.cpg
        } else {
            sb.cpg
        }
    } else {
        0
    };

    put_u32(&mut cg_bytes, UFS_CG_CGX_OFFSET, cg as u32);
    put_u16(&mut cg_bytes, UFS_CG_NCYL_OFFSET, cg_ncyl as u16);
    put_u16(&mut cg_bytes, UFS_CG_NIBLK_OFFSET, sb.ipg as u16);
    put_u32(&mut cg_bytes, UFS_CG_NDBLK_OFFSET, cg_ndblk as u32);
    put_u32(&mut cg_bytes, UFS_CG_CS_NDIR_OFFSET, 0);
    put_u32(&mut cg_bytes, UFS_CG_CS_NBFREE_OFFSET, free_blocks as u32);
    let initial_nifree = sb.ipg - if cg == 0 { 2 } else { 0 };
    put_u32(&mut cg_bytes, UFS_CG_CS_NIFREE_OFFSET, initial_nifree as u32);
    put_u32(&mut cg_bytes, UFS_CG_CS_NFFREE_OFFSET, free_fragment_remainder as u32);
    put_u32(&mut cg_bytes, UFS_CG_IROTOR_OFFSET, 0);
    put_u32(&mut cg_bytes, UFS_CG_MAGIC_OFFSET, UFS_CG_MAGIC);

    // Inodes 0 and 1 are reserved; the original mkfs marks them allocated in the
    // first cylinder group.
    if cg == 0 {
        set_inode_state(&mut cg_bytes, 0, true);
        set_inode_state(&mut cg_bytes, 1, true);
    }

    for frag_index in data_start_frag..cg_ndblk {
        set_frag_state(&mut cg_bytes, frag_index, true);
    }
    write_cg_block(image, ufs, cg, &cg_bytes);
    cg_bytes
}

fn read_allocatable_cg_block(image: &mut [u8], ufs: &Ufs, cg: i64) -> Vec<u8> {
    let cg_bytes = read_cg_block(image, ufs, cg);
    if u32(&cg_bytes, UFS_CG_MAGIC_OFFSET) == UFS_CG_MAGIC {
        return cg_bytes;
    }
    if looks_like_pristine_cg(&cg_bytes) {
        return initialize_pristine_cg(image, ufs, cg);
    }
    cg_bytes
}

// --- incremental count adjustments -----------------------------------------

fn adjust_u32_at(buf: &mut [u8], offset: usize, delta: i64) {
    let current = u32(buf, offset) as i64;
    put_u32(buf, offset, (current + delta) as u32);
}

pub fn adjust_superblock_free_blocks(image: &mut [u8], ufs: &Ufs, delta: i64) {
    adjust_u32_at(image, ufs.super_offset as usize + UFS_FS_CSTOTAL_NBFREE_OFFSET, delta);
}

pub fn adjust_superblock_free_inodes(image: &mut [u8], ufs: &Ufs, delta: i64) {
    adjust_u32_at(image, ufs.super_offset as usize + UFS_FS_CSTOTAL_NIFREE_OFFSET, delta);
}

pub fn adjust_superblock_directory_count(image: &mut [u8], ufs: &Ufs, delta: i64) {
    adjust_u32_at(image, ufs.super_offset as usize + UFS_FS_CSTOTAL_NDIR_OFFSET, delta);
}

fn adjust_cg_free_blocks(cg: &mut [u8], delta: i64) {
    adjust_u32_at(cg, UFS_CG_CS_NBFREE_OFFSET, delta);
}

fn adjust_cg_free_inodes(cg: &mut [u8], delta: i64) {
    adjust_u32_at(cg, UFS_CG_CS_NIFREE_OFFSET, delta);
}

fn adjust_cg_directory_count(cg: &mut [u8], delta: i64) {
    adjust_u32_at(cg, UFS_CG_CS_NDIR_OFFSET, delta);
}

// --- inode allocation -------------------------------------------------------

/// Allocate a free inode, preferring the cylinder group of `preferred_inode`.
/// Port of `allocate_ufs_inode`.
pub fn allocate_inode(
    image: &mut [u8],
    ufs: &Ufs,
    preferred_inode: Option<i64>,
    directory: bool,
) -> Result<i64, String> {
    let sb = &ufs.sb;
    let total_cg = sb.ncg;
    let start_cg = preferred_inode.map(|i| sb.itog(i)).unwrap_or(0);
    let preferred_local = preferred_inode.map(|i| i % sb.ipg);
    for attempt in 0..total_cg {
        let cg = (start_cg + attempt) % total_cg;
        let mut cg_bytes = read_allocatable_cg_block(image, ufs, cg);
        if u32(&cg_bytes, UFS_CG_MAGIC_OFFSET) != UFS_CG_MAGIC {
            continue;
        }
        if u32(&cg_bytes, UFS_CG_CS_NIFREE_OFFSET) == 0 {
            continue;
        }

        let mut local_inode: Option<i64> = None;
        if attempt == 0 {
            if let Some(pref) = preferred_local {
                if !is_inode_used(&cg_bytes, pref) {
                    local_inode = Some(pref);
                }
            }
        }
        if local_inode.is_none() {
            let start_inode = u32(&cg_bytes, UFS_CG_IROTOR_OFFSET) as i64 % sb.ipg;
            for offset in 0..sb.ipg {
                let candidate = (start_inode + offset) % sb.ipg;
                if !is_inode_used(&cg_bytes, candidate) {
                    local_inode = Some(candidate);
                    break;
                }
            }
        }
        let Some(local_inode) = local_inode else {
            continue;
        };

        set_inode_state(&mut cg_bytes, local_inode, true);
        put_u32(&mut cg_bytes, UFS_CG_IROTOR_OFFSET, local_inode as u32);
        adjust_cg_free_inodes(&mut cg_bytes, -1);
        if directory {
            adjust_cg_directory_count(&mut cg_bytes, 1);
        }
        write_cg_block(image, ufs, cg, &cg_bytes);
        adjust_superblock_free_inodes(image, ufs, -1);
        if directory {
            adjust_superblock_directory_count(image, ufs, 1);
        }
        return Ok(cg * sb.ipg + local_inode);
    }
    Err("error: no free UFS inodes remain for allocation".into())
}

/// Free an inode. Port of `free_ufs_inode`.
pub fn free_inode(image: &mut [u8], ufs: &Ufs, inode_number: i64, directory: bool) -> Result<(), String> {
    let sb = &ufs.sb;
    let cg = sb.itog(inode_number);
    let local = inode_number % sb.ipg;
    let mut cg_bytes = read_cg_block(image, ufs, cg);
    if u32(&cg_bytes, UFS_CG_MAGIC_OFFSET) != UFS_CG_MAGIC {
        return Err(format!(
            "error: invalid cylinder group {cg} while freeing UFS inode {inode_number}"
        ));
    }
    if !is_inode_used(&cg_bytes, local) {
        return Err(format!("error: UFS inode {inode_number} is already free"));
    }
    set_inode_state(&mut cg_bytes, local, false);
    adjust_cg_free_inodes(&mut cg_bytes, 1);
    if directory {
        adjust_cg_directory_count(&mut cg_bytes, -1);
    }
    write_cg_block(image, ufs, cg, &cg_bytes);
    adjust_superblock_free_inodes(image, ufs, 1);
    if directory {
        adjust_superblock_directory_count(image, ufs, -1);
    }
    Ok(())
}

// --- block / fragment allocation -------------------------------------------

/// Allocate one full block (zeroed). Port of `allocate_ufs_block`.
pub fn allocate_block(image: &mut [u8], ufs: &Ufs, inode_number: i64) -> Result<i64, String> {
    let sb = &ufs.sb;
    let start_cg = sb.itog(inode_number);
    let total_cg = sb.ncg;
    let frags_per_block = sb.frag;
    let block_size = sb.bsize as usize;
    for attempt in 0..total_cg {
        let cg = (start_cg + attempt) % total_cg;
        let mut cg_bytes = read_allocatable_cg_block(image, ufs, cg);
        if u32(&cg_bytes, UFS_CG_MAGIC_OFFSET) != UFS_CG_MAGIC {
            continue;
        }
        let cg_ndblk = u32(&cg_bytes, UFS_CG_NDBLK_OFFSET) as i64;
        let data_start_frag = sb.cgdmin(cg) % sb.fpg;
        let mut frag_index = data_start_frag;
        while frag_index < cg_ndblk - frags_per_block + 1 {
            if (0..frags_per_block).all(|o| is_frag_free(&cg_bytes, frag_index + o)) {
                for o in 0..frags_per_block {
                    set_frag_state(&mut cg_bytes, frag_index + o, false);
                }
                adjust_cg_free_blocks(&mut cg_bytes, -1);
                write_cg_block(image, ufs, cg, &cg_bytes);
                adjust_superblock_free_blocks(image, ufs, -1);
                let fs_block = sb.cgbase(cg) + frag_index;
                let block_offset = sb.data_block_offset(ufs.start_offset, fs_block) as usize;
                image[block_offset..block_offset + block_size].fill(0);
                return Ok(fs_block);
            }
            frag_index += frags_per_block;
        }
    }
    Err("error: no free UFS blocks remain for allocation".into())
}

/// Allocate `allocation_bytes` worth of contiguous fragments (zeroed). Port of
/// `allocate_ufs_fragments`.
pub fn allocate_fragments(
    image: &mut [u8],
    ufs: &Ufs,
    inode_number: i64,
    allocation_bytes: i64,
) -> Result<i64, String> {
    let sb = &ufs.sb;
    let fragment_size = sb.fsize;
    let frags_needed = allocation_bytes / fragment_size;
    if frags_needed <= 0 || allocation_bytes >= sb.bsize {
        return Err(format!(
            "error: invalid UFS fragment allocation request for {allocation_bytes} bytes"
        ));
    }
    let start_cg = sb.itog(inode_number);
    let total_cg = sb.ncg;
    let frags_per_block = sb.frag;
    for attempt in 0..total_cg {
        let cg = (start_cg + attempt) % total_cg;
        let mut cg_bytes = read_allocatable_cg_block(image, ufs, cg);
        if u32(&cg_bytes, UFS_CG_MAGIC_OFFSET) != UFS_CG_MAGIC {
            continue;
        }
        let cg_ndblk = u32(&cg_bytes, UFS_CG_NDBLK_OFFSET) as i64;
        let data_start_frag = sb.cgdmin(cg) % sb.fpg;
        let mut frag_index = data_start_frag;
        while frag_index < cg_ndblk - frags_per_block + 1 {
            if (0..frags_per_block).all(|o| is_frag_free(&cg_bytes, frag_index + o)) {
                for o in 0..frags_needed {
                    set_frag_state(&mut cg_bytes, frag_index + o, false);
                }
                adjust_cg_free_blocks(&mut cg_bytes, -1);
                write_cg_block(image, ufs, cg, &cg_bytes);
                adjust_superblock_free_blocks(image, ufs, -1);
                let fs_block = sb.cgbase(cg) + frag_index;
                let block_offset = sb.data_block_offset(ufs.start_offset, fs_block) as usize;
                image[block_offset..block_offset + allocation_bytes as usize].fill(0);
                return Ok(fs_block);
            }
            frag_index += frags_per_block;
        }
    }
    Err("error: no free UFS fragments remain for allocation".into())
}

/// Allocate either a full block or a fragment run, by size. Port of
/// `allocate_ufs_allocation`.
pub fn allocate_allocation(
    image: &mut [u8],
    ufs: &Ufs,
    inode_number: i64,
    allocation_bytes: i64,
) -> Result<i64, String> {
    if allocation_bytes <= 0 {
        return Err("error: UFS allocation size must be positive".into());
    }
    if allocation_bytes == ufs.sb.bsize {
        allocate_block(image, ufs, inode_number)
    } else {
        allocate_fragments(image, ufs, inode_number, allocation_bytes)
    }
}

/// Free a full block. Port of `free_ufs_block`.
pub fn free_block(image: &mut [u8], ufs: &Ufs, fs_block: i64) -> Result<(), String> {
    let sb = &ufs.sb;
    let cg = fs_block / sb.fpg;
    let frag_index = fs_block % sb.fpg;
    let mut cg_bytes = read_cg_block(image, ufs, cg);
    if u32(&cg_bytes, UFS_CG_MAGIC_OFFSET) != UFS_CG_MAGIC {
        return Err(format!(
            "error: invalid cylinder group {cg} while freeing UFS block {fs_block}"
        ));
    }
    for o in 0..sb.frag {
        set_frag_state(&mut cg_bytes, frag_index + o, true);
    }
    adjust_cg_free_blocks(&mut cg_bytes, 1);
    write_cg_block(image, ufs, cg, &cg_bytes);
    adjust_superblock_free_blocks(image, ufs, 1);
    Ok(())
}

/// Free an allocation (block or fragment run). Port of `free_ufs_allocation`.
pub fn free_allocation(
    image: &mut [u8],
    ufs: &Ufs,
    fs_block: i64,
    allocation_bytes: i64,
) -> Result<(), String> {
    if allocation_bytes <= 0 {
        return Ok(());
    }
    let sb = &ufs.sb;
    if allocation_bytes == sb.bsize {
        return free_block(image, ufs, fs_block);
    }
    let fragment_size = sb.fsize;
    let frags_to_free = allocation_bytes / fragment_size;
    let frags_per_block = sb.frag;
    let cg = fs_block / sb.fpg;
    let frag_index = fs_block % sb.fpg;
    let mut cg_bytes = read_cg_block(image, ufs, cg);
    if u32(&cg_bytes, UFS_CG_MAGIC_OFFSET) != UFS_CG_MAGIC {
        return Err(format!(
            "error: invalid cylinder group {cg} while freeing UFS allocation at block {fs_block}"
        ));
    }
    for o in 0..frags_to_free {
        set_frag_state(&mut cg_bytes, frag_index + o, true);
    }
    let block_base = frag_index - (frag_index % frags_per_block);
    if (0..frags_per_block).all(|o| is_frag_free(&cg_bytes, block_base + o)) {
        adjust_cg_free_blocks(&mut cg_bytes, 1);
        adjust_superblock_free_blocks(image, ufs, 1);
    }
    write_cg_block(image, ufs, cg, &cg_bytes);
    Ok(())
}

// --- rotational position helpers (for the recomputed cg header) -------------

fn cbtocylno(ufs: &Ufs, frag_base: i64) -> i64 {
    let spc = ufs.sb.spc;
    let nspf = ufs.sb.nspf;
    if spc <= 0 || nspf <= 0 {
        return 0;
    }
    (frag_base * nspf) / spc
}

fn cbtorpos(ufs: &Ufs, frag_base: i64) -> i64 {
    let spc = ufs.sb.spc;
    let nsect = ufs.sb.nsect;
    let nspf = ufs.sb.nspf;
    if spc <= 0 || nsect <= 0 || nspf <= 0 {
        return 0;
    }
    ((frag_base * nspf) % spc % nsect * NRPOS as i64) / nsect
}

fn account_fragment_run(free_flags: &[bool], frsum: &mut [i64]) {
    let mut run_length = 0usize;
    for &free in free_flags.iter().chain(std::iter::once(&false)) {
        if free {
            run_length += 1;
            continue;
        }
        if run_length > 0 && run_length < frsum.len() {
            frsum[run_length] += 1;
        }
        run_length = 0;
    }
}

fn csum_offset(ufs: &Ufs, cg: i64) -> Option<usize> {
    let csaddr = ufs.sb.csaddr;
    let cssize = ufs.sb.cssize;
    if csaddr <= 0 || cssize < (cg + 1) * UFS_CSUM_SIZE as i64 {
        return None;
    }
    Some((ufs.start_offset as i64 + ufs.sb.fsbtobytes(csaddr) + cg * UFS_CSUM_SIZE as i64) as usize)
}

/// Recompute the canonical header bytes for cylinder group `cg` plus its
/// `(ndir, nbfree, nifree, nffree)` counts, by counting the bitmaps and inodes.
/// Port of `expected_ufs_cg_header` with `trust_current_inode_counts=False`.
fn expected_cg_header(image: &[u8], ufs: &Ufs, cg: i64, cg_bytes: &[u8]) -> (Vec<u8>, (i64, i64, i64, i64)) {
    let sb = &ufs.sb;
    let ipg = sb.ipg;
    let ncg = sb.ncg;
    let cpg = sb.cpg;
    let ncyl = sb.ncyl;
    let frags_per_block = sb.frag;
    let cg_ndblk = u32(cg_bytes, UFS_CG_NDBLK_OFFSET) as i64;
    let mut expected = vec![0u8; sb.bsize as usize];

    let current_time = u32(cg_bytes, UFS_CG_TIME_OFFSET);
    // Python clamps to min(current, now); a populate uses timestamp 0, so keep
    // the stored value as-is (no wall-clock dependence in the port).
    put_u32(&mut expected, UFS_CG_TIME_OFFSET, current_time);
    put_u32(&mut expected, UFS_CG_CGX_OFFSET, cg as u32);
    let cg_ncyl = if cpg > 0 {
        if cg == ncg - 1 {
            ncyl % cpg
        } else {
            cpg
        }
    } else {
        0
    };
    put_u16(&mut expected, UFS_CG_NCYL_OFFSET, cg_ncyl as u16);
    put_u16(&mut expected, UFS_CG_NIBLK_OFFSET, ipg as u16);
    put_u32(&mut expected, UFS_CG_NDBLK_OFFSET, cg_ndblk as u32);

    let mut ndir = 0i64;
    let mut nifree = ipg;
    if cg == 0 {
        nifree -= 2;
    }
    for inode_index in 0..ipg {
        if cg == 0 && inode_index < 2 {
            continue;
        }
        if !is_inode_used(cg_bytes, inode_index) {
            continue;
        }
        nifree -= 1;
        let inode_number = cg * ipg + inode_index;
        if let Some(inode) = read_inode(image, ufs, inode_number) {
            if inode.is_directory() {
                ndir += 1;
            }
        }
    }

    let mut nbfree = 0i64;
    let mut nffree = 0i64;
    let mut frsum = vec![0i64; MAXFRAG];
    let mut btot = vec![0i64; MAXCPG];
    let mut bpos = vec![0i64; MAXCPG * NRPOS];

    let full_block_limit = cg_ndblk - frags_per_block + 1;
    let mut frag_base = 0i64;
    while frag_base < full_block_limit {
        let free_bits = frag_block_free_bits(cg_bytes, frag_base, frags_per_block);
        let free_fragments = free_bits.count_ones() as i64;
        if free_fragments == frags_per_block {
            nbfree += 1;
            let cyl = cbtocylno(ufs, frag_base);
            let pos = cbtorpos(ufs, frag_base);
            if (0..MAXCPG as i64).contains(&cyl) && (0..NRPOS as i64).contains(&pos) {
                btot[cyl as usize] += 1;
                bpos[(cyl as usize) * NRPOS + pos as usize] += 1;
            }
        } else if free_fragments > 0 {
            nffree += free_fragments;
            let flags: Vec<bool> = (0..frags_per_block)
                .map(|o| (free_bits & (1 << o)) != 0)
                .collect();
            account_fragment_run(&flags, &mut frsum);
        }
        frag_base += frags_per_block;
    }
    if frag_base < cg_ndblk {
        let flags: Vec<bool> = (frag_base..cg_ndblk)
            .map(|f| is_frag_free(cg_bytes, f))
            .collect();
        let trailing_free = flags.iter().filter(|&&f| f).count() as i64;
        if trailing_free > 0 {
            nffree += trailing_free;
            account_fragment_run(&flags, &mut frsum);
        }
    }

    put_u32(&mut expected, UFS_CG_CS_NDIR_OFFSET, ndir as u32);
    put_u32(&mut expected, UFS_CG_CS_NBFREE_OFFSET, nbfree as u32);
    put_u32(&mut expected, UFS_CG_CS_NIFREE_OFFSET, nifree as u32);
    put_u32(&mut expected, UFS_CG_CS_NFFREE_OFFSET, nffree as u32);

    let rotor = u32(cg_bytes, UFS_CG_ROTOR_OFFSET) as i64;
    let frotor = u32(cg_bytes, UFS_CG_FROTOR_OFFSET) as i64;
    let irotor = u32(cg_bytes, UFS_CG_IROTOR_OFFSET) as i64;
    put_u32(&mut expected, UFS_CG_ROTOR_OFFSET, if rotor < cg_ndblk { rotor } else { 0 } as u32);
    put_u32(&mut expected, UFS_CG_FROTOR_OFFSET, if frotor < cg_ndblk { frotor } else { 0 } as u32);
    put_u32(&mut expected, UFS_CG_IROTOR_OFFSET, if irotor < ipg { irotor } else { 0 } as u32);

    for (index, &value) in frsum.iter().enumerate() {
        put_u32(&mut expected, UFS_CG_FRSUM_OFFSET + index * 4, value as u32);
    }
    for (index, &value) in btot.iter().enumerate() {
        put_u32(&mut expected, UFS_CG_BTOT_OFFSET + index * 4, value as u32);
    }
    for (index, &value) in bpos.iter().enumerate() {
        put_u16(&mut expected, UFS_CG_B_OFFSET + index * 2, value as u16);
    }

    (expected, (ndir, nbfree, nifree, nffree))
}

/// Rebuild every cylinder-group header, the on-disk summary (`fs_cs`) area, and
/// the superblock `cstotal` from the bitmaps/inodes. Port of
/// `recompute_ufs_summary_counts` (the `trust_current_inode_counts=False` path).
/// This is what `fsck` pass 5 validates; call it once after a populate.
pub fn recompute_summary_counts(image: &mut [u8], ufs: &Ufs) -> Result<(), String> {
    let sb = &ufs.sb;
    let (mut total_ndir, mut total_nbfree, mut total_nifree, mut total_nffree) = (0i64, 0i64, 0i64, 0i64);

    for cg in 0..sb.ncg {
        let mut cg_bytes = read_cg_block(image, ufs, cg);
        if u32(&cg_bytes, UFS_CG_MAGIC_OFFSET) != UFS_CG_MAGIC {
            if !looks_like_pristine_cg(&cg_bytes) {
                return Err(format!(
                    "error: invalid cylinder group {cg} while normalizing UFS metadata"
                ));
            }
            cg_bytes = initialize_pristine_cg(image, ufs, cg);
        }

        let (expected, (ndir, nbfree, nifree, nffree)) =
            expected_cg_header(&*image, ufs, cg, &cg_bytes);
        // Copy the recomputed header up to (not including) the inode-used map,
        // then the four count fields, exactly like the Python.
        cg_bytes[..UFS_CG_IUSED_OFFSET].copy_from_slice(&expected[..UFS_CG_IUSED_OFFSET]);
        put_u32(&mut cg_bytes, UFS_CG_CS_NDIR_OFFSET, ndir as u32);
        put_u32(&mut cg_bytes, UFS_CG_CS_NBFREE_OFFSET, nbfree as u32);
        put_u32(&mut cg_bytes, UFS_CG_CS_NIFREE_OFFSET, nifree as u32);
        put_u32(&mut cg_bytes, UFS_CG_CS_NFFREE_OFFSET, nffree as u32);
        write_cg_block(image, ufs, cg, &cg_bytes);

        if let Some(offset) = csum_offset(ufs, cg) {
            put_u32(image, offset, ndir as u32);
            put_u32(image, offset + 4, nbfree as u32);
            put_u32(image, offset + 8, nifree as u32);
            put_u32(image, offset + 12, nffree as u32);
        }

        total_ndir += ndir;
        total_nbfree += nbfree;
        total_nifree += nifree;
        total_nffree += nffree;
    }

    let so = ufs.super_offset as usize;
    put_u32(image, so + UFS_FS_CSTOTAL_NDIR_OFFSET, total_ndir as u32);
    put_u32(image, so + UFS_FS_CSTOTAL_NBFREE_OFFSET, total_nbfree as u32);
    put_u32(image, so + UFS_FS_CSTOTAL_NIFREE_OFFSET, total_nifree as u32);
    put_u32(image, so + UFS_FS_CSTOTAL_NFFREE_OFFSET, total_nffree as u32);
    Ok(())
}
