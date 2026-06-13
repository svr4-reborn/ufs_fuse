//! UFS filesystem formatter — Rust port of `build_ufs_filesystem_image` /
//! `format_ufs_filesystem` in `host_tools/fs/ufs.py`.
//!
//! Lays out a fresh, empty UFS filesystem inside the slice region
//! `[fs_start, fs_start + size_bytes)` of `image`: the superblock, every
//! cylinder group's metadata (header, block/inode bitmaps), the inode area, and
//! the root directory (`.`/`..`). It reuses the already-ported building blocks —
//! [`initialize_pristine_cg`](crate::alloc::initialize_pristine_cg),
//! [`initialize_inode`](crate::write::initialize_inode),
//! [`set_inode_contents`](crate::write::set_inode_contents), and
//! [`recompute_summary_counts`](crate::alloc::recompute_summary_counts) — so the
//! result is consistent with everything the write path expects.
//!
//! Like the Python writer, this only writes *metadata* (superblock, one block
//! per cylinder group, the root inode block, the root directory, and the
//! cylinder-summary area). It does not zero the data area, so the caller must
//! hand it a fresh/zeroed (e.g. freshly `create-skeleton`'d, hence sparse)
//! slice. That also keeps it scalable: formatting a huge slice touches only
//! metadata pages, never the whole slice.

use svr4_fs_core::codec::{put_i32, put_u32};
use svr4_fs_core::consts::*;

use crate::alloc::{initialize_pristine_cg, recompute_summary_counts, set_inode_state, write_cg_block};
use crate::read_inode;
use crate::superblock::{detect_ufs_at_start, Ufs};
use crate::write::{build_directory_block, initialize_inode, set_inode_contents};

/// Layout block numbers matching the Python defaults (block units within the
/// slice). The summary area lives at block 4; the first cylinder group's
/// metadata block at 5; the inode area starts at block 6 (all may be pushed
/// later if the summary area is large).
const SUMMARY_BLOCK_NUMBER: u64 = 4;
const CG_BLOCK_NUMBER: u64 = 5;
const INODE_BLOCK_NUMBER: u64 = 6;

/// Options for [`format`]. `tracks_per_cylinder`/`sectors_per_track` come from
/// the disk geometry and must be given together (or both omitted for a single
/// synthetic cylinder, as the Python default does for bare images).
#[derive(Clone, Copy, Debug)]
pub struct FormatOptions {
    pub timestamp: u32,
    pub block_size: u64,
    pub bytes_per_inode: u64,
    pub tracks_per_cylinder: Option<u32>,
    pub sectors_per_track: Option<u32>,
}

impl Default for FormatOptions {
    fn default() -> Self {
        FormatOptions {
            timestamp: 0,
            block_size: 8192,
            bytes_per_inode: 8192,
            tracks_per_cylinder: None,
            sectors_per_track: None,
        }
    }
}

fn power_of_two_shift(value: u64) -> Result<u32, String> {
    if value == 0 || value & (value - 1) != 0 {
        return Err(format!("error: expected a positive power-of-two value, got {value}"));
    }
    Ok(value.trailing_zeros())
}

fn align_up(value: u64, alignment: u64) -> u64 {
    if alignment == 0 {
        return value;
    }
    value.div_ceil(alignment) * alignment
}

/// Two's-complement low-32-bit mask of `-value`, matching Python's
/// `_u32_mask(-value)`.
fn neg_u32_mask(value: u64) -> u32 {
    (value as u32).wrapping_neg()
}

#[allow(clippy::too_many_arguments)]
fn compute_inode_block_count(
    image_size: u64,
    block_size: u64,
    cylinder_groups: u64,
    fragments_per_group: u64,
    inode_block_number: u64,
    bytes_per_inode: u64,
) -> Result<u64, String> {
    if bytes_per_inode == 0 {
        return Err("error: bytes_per_inode must be positive".into());
    }
    let inodes_per_block = block_size / UFS_DINODE_SIZE as u64;
    let target_inodes = image_size.div_ceil(bytes_per_inode).max(1);
    let target_ipg = target_inodes.div_ceil(cylinder_groups).max(1);
    let mut inode_block_count = target_ipg.div_ceil(inodes_per_block).max(1);

    let max_inode_blocks = (fragments_per_group / (block_size / SECTOR_SIZE as u64))
        .checked_sub(inode_block_number + 1)
        .filter(|&v| v > 0)
        .ok_or("error: UFS cylinder group is too small to reserve inode blocks")?;

    inode_block_count = inode_block_count.min(max_inode_blocks);
    if inode_block_count * inodes_per_block > MAXIPG as u64 {
        inode_block_count = MAXIPG as u64 / inodes_per_block;
    }
    if inode_block_count == 0 || inode_block_count * inodes_per_block == 0 {
        return Err("error: UFS inode layout could not reserve any usable inodes".into());
    }
    Ok(inode_block_count)
}

/// Format an empty UFS filesystem into `image[fs_start .. fs_start+size_bytes]`
/// and return the parsed [`Ufs`]. Byte-for-byte identical to the Python
/// `build_ufs_filesystem_image` for the same parameters.
pub fn format(image: &mut [u8], fs_start: u64, size_bytes: u64, opts: &FormatOptions) -> Result<Ufs, String> {
    let fragment_size: u64 = SECTOR_SIZE as u64;
    if size_bytes == 0 || size_bytes % fragment_size != 0 {
        return Err("error: UFS image size must be a positive multiple of 512 bytes".into());
    }
    let block_size = opts.block_size;
    if block_size < 4096 || block_size > UFS_SB_SIZE as u64 {
        return Err("error: UFS block size must be between 4096 and 8192 bytes".into());
    }
    if block_size % fragment_size != 0 {
        return Err("error: UFS block size must be a whole multiple of the fragment size".into());
    }
    if opts.tracks_per_cylinder.is_none() != opts.sectors_per_track.is_none() {
        return Err("error: tracks_per_cylinder and sectors_per_track must be specified together".into());
    }
    let base = fs_start as usize;
    if base + size_bytes as usize > image.len() {
        return Err("error: UFS slice extends past the end of the image".into());
    }

    let fragments_per_block = block_size / fragment_size;
    let block_shift = power_of_two_shift(fragments_per_block)?;
    let fsbtodb = power_of_two_shift(fragment_size / SECTOR_SIZE as u64)?;
    let bshift = power_of_two_shift(block_size)?;
    let fshift = power_of_two_shift(fragment_size)?;
    let fragshift = block_shift;
    let inodes_per_block = block_size / UFS_DINODE_SIZE as u64;

    let total_fragments = size_bytes / fragment_size;
    let (tracks_per_cylinder, sectors_per_track, total_cylinders, cylinders_per_group, cylinder_groups, fragments_per_group);
    match (opts.tracks_per_cylinder, opts.sectors_per_track) {
        (None, None) => {
            tracks_per_cylinder = 1u64;
            sectors_per_track = block_size / SECTOR_SIZE as u64;
            total_cylinders = 1;
            cylinders_per_group = 1;
            cylinder_groups = 1;
            fragments_per_group = total_fragments;
        }
        (Some(t), Some(s)) => {
            if t == 0 || s == 0 {
                return Err("error: tracks_per_cylinder and sectors_per_track must be positive".into());
            }
            tracks_per_cylinder = t as u64;
            sectors_per_track = s as u64;
            let sectors_per_cylinder = tracks_per_cylinder * sectors_per_track;
            if total_fragments % sectors_per_cylinder != 0 {
                return Err("error: UFS slice size must be an exact whole number of cylinders".into());
            }
            total_cylinders = total_fragments / sectors_per_cylinder;
            if total_cylinders == 0 {
                return Err("error: UFS slice must contain at least one cylinder".into());
            }
            let max_cg_data_fragments = (block_size - UFS_CG_FREE_OFFSET as u64) * NBBY as u64;
            let max_cylinders_per_group = max_cg_data_fragments / sectors_per_cylinder;
            if max_cylinders_per_group == 0 {
                return Err("error: UFS cylinder-group bitmap cannot represent even one cylinder with this geometry".into());
            }
            cylinders_per_group = total_cylinders.min(MAXCPG as u64).min(max_cylinders_per_group);
            cylinder_groups = total_cylinders.div_ceil(cylinders_per_group);
            fragments_per_group = cylinders_per_group * sectors_per_cylinder;
        }
        _ => unreachable!("checked above"),
    }

    let summary_frag_number = SUMMARY_BLOCK_NUMBER << block_shift;
    let summary_bytes = cylinder_groups * UFS_CSUM_SIZE as u64;
    let summary_area_bytes = align_up(summary_bytes, fragment_size);
    let summary_fragments = summary_area_bytes / fragment_size;
    let minimum_cg_block =
        align_up(summary_frag_number + summary_fragments, fragments_per_block) / fragments_per_block;
    let mut cg_block_number = CG_BLOCK_NUMBER;
    let mut inode_block_number = INODE_BLOCK_NUMBER;
    if cg_block_number < minimum_cg_block {
        let delta = minimum_cg_block - cg_block_number;
        cg_block_number += delta;
        inode_block_number += delta;
    }
    if inode_block_number <= cg_block_number {
        inode_block_number = cg_block_number + 1;
    }

    let cylinder_group_frag_number = cg_block_number << block_shift;
    let inode_frag_number = inode_block_number << block_shift;

    let inode_block_count = compute_inode_block_count(
        size_bytes,
        block_size,
        cylinder_groups,
        fragments_per_group,
        inode_block_number,
        opts.bytes_per_inode,
    )?;
    let inodes_per_group = inode_block_count * inodes_per_block;
    let data_frag_number = (inode_block_number + inode_block_count) << block_shift;
    let required_bytes = (data_frag_number + fragments_per_block) * fragment_size;
    if size_bytes < required_bytes {
        return Err(format!(
            "error: UFS slice is too small ({size_bytes} bytes); need at least {required_bytes} bytes"
        ));
    }

    let csums_per_block = block_size / UFS_CSUM_SIZE as u64;
    let csshift = power_of_two_shift(csums_per_block)?;
    let csmask = neg_u32_mask(csums_per_block);
    if summary_frag_number + summary_fragments > cylinder_group_frag_number {
        return Err("error: UFS cylinder summary area overlaps the cylinder group block".into());
    }

    // --- write the superblock ----------------------------------------------
    let so = base + UFS_SB_OFFSET as usize;
    let w32 = |image: &mut [u8], off: usize, v: u64| put_u32(image, so + off, v as u32);

    w32(image, UFS_FS_SBLKNO_OFFSET, UFS_SB_OFFSET / fragment_size);
    w32(image, UFS_FS_CBLKNO_OFFSET, cylinder_group_frag_number);
    w32(image, UFS_FS_IBLKNO_OFFSET, inode_frag_number);
    w32(image, UFS_FS_DBLKNO_OFFSET, data_frag_number);
    w32(image, UFS_FS_CGOFFSET_OFFSET, 0);
    w32(image, UFS_FS_CGMASK_OFFSET, 0);
    w32(image, UFS_FS_TIME_OFFSET, u64::from(opts.timestamp));
    w32(image, UFS_FS_SIZE_OFFSET, total_fragments);
    w32(image, UFS_FS_DSIZE_OFFSET, total_fragments);
    w32(image, UFS_FS_NCG_OFFSET, cylinder_groups);
    w32(image, UFS_FS_BSIZE_OFFSET, block_size);
    w32(image, UFS_FS_FSIZE_OFFSET, fragment_size);
    w32(image, UFS_FS_FRAG_OFFSET, fragments_per_block);
    w32(image, UFS_FS_MINFREE_OFFSET, 0);
    w32(image, UFS_FS_ROTDLY_OFFSET, 0);
    w32(image, UFS_FS_RPS_OFFSET, 60);
    w32(image, UFS_FS_BMASK_OFFSET, u64::from(neg_u32_mask(block_size)));
    w32(image, UFS_FS_FMASK_OFFSET, u64::from(neg_u32_mask(fragment_size)));
    w32(image, UFS_FS_BSHIFT_OFFSET, u64::from(bshift));
    w32(image, UFS_FS_FSHIFT_OFFSET, u64::from(fshift));
    w32(image, UFS_FS_MAXCONTIG_OFFSET, 1);
    let maxbpg = (fragments_per_group.saturating_sub(data_frag_number)) / fragments_per_block;
    w32(image, UFS_FS_MAXBPG_OFFSET, maxbpg);
    put_i32(image, so + UFS_FS_FRAGSHIFT_OFFSET, fragshift as i32);
    w32(image, UFS_FS_FSBTODB_OFFSET, u64::from(fsbtodb));
    w32(image, UFS_FS_SBSIZE_OFFSET, (UFS_SB_SIZE as u64).min(block_size));
    w32(image, UFS_FS_CSMASK_OFFSET, u64::from(csmask));
    w32(image, UFS_FS_CSSHIFT_OFFSET, u64::from(csshift));
    w32(image, UFS_FS_NINDIR_OFFSET, block_size / 4);
    w32(image, UFS_FS_INOPB_OFFSET, inodes_per_block);
    w32(image, UFS_FS_NSPF_OFFSET, fragment_size / SECTOR_SIZE as u64);
    w32(image, UFS_FS_OPTIM_OFFSET, 0);
    w32(image, UFS_FS_STATE_OFFSET, u64::from(UFS_FS_OKAY.wrapping_sub(opts.timestamp)));
    w32(image, UFS_FS_CSADDR_OFFSET, summary_frag_number);
    w32(image, UFS_FS_CSSIZE_OFFSET, summary_area_bytes);
    w32(image, UFS_FS_CGSIZE_OFFSET, block_size);
    w32(image, UFS_FS_NTRAK_OFFSET, tracks_per_cylinder);
    w32(image, UFS_FS_NSECT_OFFSET, sectors_per_track);
    w32(image, UFS_FS_SPC_OFFSET, tracks_per_cylinder * sectors_per_track);
    w32(image, UFS_FS_NCYL_OFFSET, total_cylinders);
    w32(image, UFS_FS_CPG_OFFSET, cylinders_per_group);
    w32(image, UFS_FS_IPG_OFFSET, inodes_per_group);
    w32(image, UFS_FS_FPG_OFFSET, fragments_per_group);
    w32(image, UFS_FS_MAGIC_OFFSET, u64::from(UFS_MAGIC));
    image[so + UFS_FS_FMOD_OFFSET] = 0;
    image[so + UFS_FS_CLEAN_OFFSET] = 1;
    image[so + UFS_FS_RONLY_OFFSET] = 0;

    // Parse the superblock back so every later step uses exactly the on-disk
    // geometry (and addresses relative to this slice's `start_offset`).
    let ufs = detect_ufs_at_start(image, fs_start)
        .ok_or("error: formatter wrote a superblock that failed to re-parse")?;

    // --- cylinder groups ---------------------------------------------------
    for cg in 0..cylinder_groups as i64 {
        let mut cg_bytes = initialize_pristine_cg(image, &ufs, cg);
        if cg == 0 {
            set_inode_state(&mut cg_bytes, i64::from(UFS_ROOT_INODE), true);
            write_cg_block(image, &ufs, cg, &cg_bytes);
        }
    }

    // --- root directory ----------------------------------------------------
    initialize_inode(image, &ufs, i64::from(UFS_ROOT_INODE), UFS_IFDIR | 0o755, 0, 0, 2, opts.timestamp);
    if read_inode(image, &ufs, i64::from(UFS_ROOT_INODE)).is_none() {
        return Err("error: failed to initialize the UFS root inode".into());
    }
    let root_block = build_directory_block(i64::from(UFS_ROOT_INODE), i64::from(UFS_ROOT_INODE));
    set_inode_contents(image, &ufs, i64::from(UFS_ROOT_INODE), &root_block)?;

    recompute_summary_counts(image, &ufs)?;
    Ok(ufs)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::reader::{iter_directory_entries, read_inode_bytes as _read};

    fn names(image: &[u8], ufs: &Ufs) -> Vec<String> {
        let root = read_inode(image, ufs, i64::from(UFS_ROOT_INODE)).unwrap();
        iter_directory_entries(image, ufs, &root).into_iter().map(|e| e.name).collect()
    }

    #[test]
    fn formats_a_bare_image_with_empty_root() {
        // 8 MiB bare image (no geometry), like `ufs_tool.py blank`.
        let size = 8 * 1024 * 1024u64;
        let mut image = vec![0u8; size as usize];
        let opts = FormatOptions { block_size: 4096, ..FormatOptions::default() };
        let ufs = format(&mut image, 0, size, &opts).unwrap();
        assert_eq!(ufs.start_offset, 0);
        // Root directory has just . and ..
        let mut n = names(&image, &ufs);
        n.sort();
        assert_eq!(n, vec![".", ".."]);
        // Root inode reads back as a directory of one DIRBLKSIZ block.
        let root = read_inode(&image, &ufs, i64::from(UFS_ROOT_INODE)).unwrap();
        assert!(root.is_directory());
        assert_eq!(_read(&image, &ufs, &root).len(), 512);
    }

    #[test]
    fn formats_a_geometried_slice_at_nonzero_offset() {
        // One cylinder group's worth at a non-zero offset inside a larger buffer.
        let heads = 4u32;
        let spt = 16u32;
        let spc = (heads * spt) as u64; // 64 sectors/cyl
        let cylinders = 64u64;
        let size = cylinders * spc * SECTOR_SIZE as u64; // 2 MiB
        let fs_start = 1 << 20; // 1 MiB in
        let mut image = vec![0u8; fs_start as usize + size as usize];
        let opts = FormatOptions {
            block_size: 4096,
            bytes_per_inode: 8192,
            tracks_per_cylinder: Some(heads),
            sectors_per_track: Some(spt),
            ..FormatOptions::default()
        };
        let ufs = format(&mut image, fs_start, size, &opts).unwrap();
        assert_eq!(ufs.start_offset, fs_start);
        let mut n = names(&image, &ufs);
        n.sort();
        assert_eq!(n, vec![".", ".."]);
        // Nothing was written before the slice.
        assert!(image[..fs_start as usize].iter().all(|&b| b == 0));
    }
}
