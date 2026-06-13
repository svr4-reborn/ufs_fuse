//! UFS write path: inode initialisation, content writes, directory insertion,
//! and the high-level create/mkdir/link/symlink operations.
//!
//! Port of the creation half of `host_tools/fs/ufs.py` and the inode/pointer
//! write helpers of `host_tools/fs/ufs_lowlevel.py`. Operates on the full
//! in-memory image as `&mut [u8]`, like the Python `bytearray`.
//!
//! Design note vs the Python: content writes go through [`set_inode_contents`]
//! (the `apply_ufs_inode_replacement` model — free everything, reallocate for the
//! new size). Directory insertion is in-place when an existing block has slack
//! (the common case, O(1)) and falls back to a full rewrite only when the
//! directory must grow by a block. This yields valid, `fsck`-clean images whose
//! *contents* match the Python writer; the exact backing-block placement may
//! differ, which the acceptance gate (fsck-clean + content-equivalence) allows.

use svr4_fs_core::codec::{put_u16, put_u32, put_u64};
use svr4_fs_core::consts::{
    ufs_dirsiz, SECTOR_SIZE, UFS_DINODE_SIZE, UFS_DIRBLKSIZ, UFS_DIRENT_NAMLEN_OFFSET,
    UFS_DIRENT_NAME_OFFSET, UFS_DIRENT_RECLEN_OFFSET, UFS_DI_ATIME_OFFSET, UFS_DI_BLOCKS_OFFSET,
    UFS_DI_CTIME_OFFSET, UFS_DI_DB_OFFSET, UFS_DI_EFTFLAG_OFFSET, UFS_DI_GID_OFFSET, UFS_DI_IB_OFFSET,
    UFS_DI_MODE_OFFSET, UFS_DI_MTIME_OFFSET, UFS_DI_NLINK_OFFSET, UFS_DI_SGID_OFFSET,
    UFS_DI_SIZE_OFFSET, UFS_DI_SUID_OFFSET, UFS_DI_UID_OFFSET, UFS_EFT_MAGIC, UFS_IFBLK, UFS_IFCHR,
    UFS_IFDIR, UFS_IFLNK, UFS_IFMT, UFS_IFREG, UFS_NDADDR, UFS_NIADDR,
};

use crate::alloc::{allocate_allocation, allocate_block, allocate_inode, free_allocation, free_inode};
use crate::dir::{decode_directory_header, iter_directory_records};
use crate::inode::{inode_data_blocks, inode_pointer_blocks, read_inode, Inode};
use crate::reader::{
    iter_inode_directory_records, lookup_directory_entry, read_data_range, read_inode_bytes,
    read_inode_range, resolve_path,
};
use crate::superblock::Ufs;

type WResult<T> = Result<T, String>;

fn inode_offset(ufs: &Ufs, inode_number: i64) -> usize {
    ufs.sb.inode_byte_offset(ufs.start_offset, inode_number) as usize
}

// --- inode field writers ----------------------------------------------------

pub fn clear_inode(image: &mut [u8], ufs: &Ufs, inode_number: i64) {
    let off = inode_offset(ufs, inode_number);
    image[off..off + UFS_DINODE_SIZE].fill(0);
}

fn write_inode_time(image: &mut [u8], inode_off: usize, field_offset: usize, timestamp: u32) {
    put_u32(image, inode_off + field_offset, timestamp);
    put_u32(image, inode_off + field_offset + 4, 0);
}

/// Port of `initialize_ufs_inode`: clear then set link count, owner (old+EFT),
/// timestamps, mode, and the EFT magic cookie.
#[allow(clippy::too_many_arguments)]
pub fn initialize_inode(
    image: &mut [u8],
    ufs: &Ufs,
    inode_number: i64,
    mode: u32,
    uid: u32,
    gid: u32,
    nlink: u16,
    timestamp: u32,
) {
    clear_inode(image, ufs, inode_number);
    let off = inode_offset(ufs, inode_number);
    // The old 16-bit `ic_smode` lives at the very start of the dinode, mirroring
    // the EFT 32-bit `di_mode` written below.
    put_u16(image, off, mode as u16);
    put_u16(image, off + UFS_DI_NLINK_OFFSET, nlink);
    put_u16(image, off + UFS_DI_SUID_OFFSET, uid as u16);
    put_u16(image, off + UFS_DI_SGID_OFFSET, gid as u16);
    write_inode_time(image, off, UFS_DI_ATIME_OFFSET, timestamp);
    write_inode_time(image, off, UFS_DI_MTIME_OFFSET, timestamp);
    write_inode_time(image, off, UFS_DI_CTIME_OFFSET, timestamp);
    put_u32(image, off + UFS_DI_MODE_OFFSET, mode);
    put_u32(image, off + UFS_DI_UID_OFFSET, uid);
    put_u32(image, off + UFS_DI_GID_OFFSET, gid);
    put_u32(image, off + UFS_DI_EFTFLAG_OFFSET, UFS_EFT_MAGIC);
}

fn write_inode_size(image: &mut [u8], ufs: &Ufs, inode_number: i64, size: u64) {
    put_u64(image, inode_offset(ufs, inode_number) + UFS_DI_SIZE_OFFSET, size);
}

pub fn write_inode_nlink(image: &mut [u8], ufs: &Ufs, inode_number: i64, nlink: u16) {
    put_u16(image, inode_offset(ufs, inode_number) + UFS_DI_NLINK_OFFSET, nlink);
}

fn write_inode_blocks(image: &mut [u8], ufs: &Ufs, inode_number: i64, sectors: u32) {
    put_u32(image, inode_offset(ufs, inode_number) + UFS_DI_BLOCKS_OFFSET, sectors);
}

/// Port of `write_ufs_block_lists`: the 12 direct + 3 indirect block pointers.
fn write_block_lists(image: &mut [u8], ufs: &Ufs, inode_number: i64, direct: &[i64], indirect: &[i64]) {
    let off = inode_offset(ufs, inode_number);
    for index in 0..UFS_NDADDR {
        let value = direct.get(index).copied().unwrap_or(0) as u32;
        put_u32(image, off + UFS_DI_DB_OFFSET + index * 4, value);
    }
    for index in 0..UFS_NIADDR {
        let value = indirect.get(index).copied().unwrap_or(0) as u32;
        put_u32(image, off + UFS_DI_IB_OFFSET + index * 4, value);
    }
}

// --- indirect pointer tree construction ------------------------------------

fn write_pointer_block(image: &mut [u8], ufs: &Ufs, fs_block: i64, pointers: &[i64]) {
    let block_offset = ufs.sb.data_block_offset(ufs.start_offset, fs_block) as usize;
    let block_size = ufs.sb.bsize as usize;
    image[block_offset..block_offset + block_size].fill(0);
    let nindir = ufs.sb.nindir as usize;
    for (index, &pointer) in pointers.iter().take(nindir).enumerate() {
        put_u32(image, block_offset + index * 4, pointer as u32);
    }
}

/// Build an indirect tree of `levels` for `data_blocks`. Returns the root block
/// and the number of pointer blocks allocated. Port of `build_ufs_pointer_tree`.
fn build_pointer_tree(
    image: &mut [u8],
    ufs: &Ufs,
    inode_number: i64,
    levels: u32,
    data_blocks: &[i64],
) -> WResult<(i64, i64)> {
    if data_blocks.is_empty() {
        return Ok((0, 0));
    }
    let pointer_count = ufs.sb.nindir as usize;
    if levels == 1 {
        let root_block = allocate_block(image, ufs, inode_number)?;
        let take = data_blocks.len().min(pointer_count);
        write_pointer_block(image, ufs, root_block, &data_blocks[..take]);
        return Ok((root_block, 1));
    }

    let child_capacity = pointer_count.pow(levels - 1);
    let mut child_roots: Vec<i64> = Vec::new();
    let mut total_pointer_blocks = 1i64;
    let mut remaining = data_blocks;
    while !remaining.is_empty() {
        let take = remaining.len().min(child_capacity);
        let (chunk, rest) = remaining.split_at(take);
        let (child_root, child_count) = build_pointer_tree(image, ufs, inode_number, levels - 1, chunk)?;
        child_roots.push(child_root);
        total_pointer_blocks += child_count;
        remaining = rest;
    }
    let root_block = allocate_block(image, ufs, inode_number)?;
    write_pointer_block(image, ufs, root_block, &child_roots);
    Ok((root_block, total_pointer_blocks))
}

/// Lay out direct + indirect pointers for `data_blocks` into the inode. Returns
/// the count of pointer blocks allocated. Port of `build_ufs_inode_pointer_structure`.
fn build_inode_pointer_structure(
    image: &mut [u8],
    ufs: &Ufs,
    inode_number: i64,
    data_blocks: &[i64],
) -> WResult<i64> {
    let nindir = ufs.sb.nindir as usize;
    let direct: Vec<i64> = data_blocks.iter().take(UFS_NDADDR).copied().collect();
    let mut indirect_roots: Vec<i64> = Vec::new();
    let mut new_pointer_blocks = 0i64;
    let mut remaining: &[i64] = if data_blocks.len() > UFS_NDADDR {
        &data_blocks[UFS_NDADDR..]
    } else {
        &[]
    };
    for levels in 1u32..4 {
        let level_capacity = nindir.pow(levels);
        let take = remaining.len().min(level_capacity);
        let (level_blocks, rest) = remaining.split_at(take);
        remaining = rest;
        if !level_blocks.is_empty() {
            let (root_block, pointer_blocks) =
                build_pointer_tree(image, ufs, inode_number, levels, level_blocks)?;
            indirect_roots.push(root_block);
            new_pointer_blocks += pointer_blocks;
        } else {
            indirect_roots.push(0);
        }
    }
    write_block_lists(image, ufs, inode_number, &direct, &indirect_roots);
    Ok(new_pointer_blocks)
}

// --- whole-inode content replacement ---------------------------------------

/// Replace the entire contents of an inode with `new_data`. Frees the inode's
/// current data and pointer blocks, allocates afresh for the new size, writes the
/// data, rebuilds the pointer structure, and updates size + block count. Port of
/// `apply_ufs_inode_replacement`.
pub fn set_inode_contents(image: &mut [u8], ufs: &Ufs, inode_number: i64, new_data: &[u8]) -> WResult<()> {
    let sb = &ufs.sb;
    let block_size = sb.bsize as usize;

    let inode = read_inode(&*image, ufs, inode_number)
        .ok_or_else(|| format!("error: could not read inode {inode_number} for replacement"))?;
    let current_data_blocks = inode_data_blocks(&*image, ufs, &inode);
    let current_allocation_sizes = sb.allocation_byte_sizes(inode.size as i64);
    let current_pointer_blocks = inode_pointer_blocks(&*image, ufs, &inode);
    let requested_allocation_sizes = sb.allocation_byte_sizes(new_data.len() as i64);

    for &pointer_block in current_pointer_blocks.iter().rev() {
        free_allocation(image, ufs, pointer_block as i64, block_size as i64)?;
    }
    for (&fs_block, &allocation_bytes) in current_data_blocks
        .iter()
        .rev()
        .zip(current_allocation_sizes.iter().rev())
    {
        free_allocation(image, ufs, fs_block as i64, allocation_bytes)?;
    }

    let mut new_blocks: Vec<i64> = Vec::with_capacity(requested_allocation_sizes.len());
    for &allocation_bytes in &requested_allocation_sizes {
        new_blocks.push(allocate_allocation(image, ufs, inode_number, allocation_bytes)?);
    }

    let mut remaining = new_data;
    for (&fs_block, &allocation_bytes) in new_blocks.iter().zip(requested_allocation_sizes.iter()) {
        let block_offset = sb.data_block_offset(ufs.start_offset, fs_block) as usize;
        let take = remaining.len().min(block_size);
        let (chunk, rest) = remaining.split_at(take);
        let alloc = allocation_bytes as usize;
        image[block_offset..block_offset + chunk.len()].copy_from_slice(chunk);
        // ljust to allocation size with zeros (the rest of the allocated frags).
        image[block_offset + chunk.len()..block_offset + alloc].fill(0);
        remaining = rest;
    }

    let new_pointer_block_count = build_inode_pointer_structure(image, ufs, inode_number, &new_blocks)?;
    write_inode_size(image, ufs, inode_number, new_data.len() as u64);
    let data_sectors: i64 = requested_allocation_sizes
        .iter()
        .map(|a| a / SECTOR_SIZE as i64)
        .sum();
    let pointer_sectors = new_pointer_block_count * (block_size as i64 / SECTOR_SIZE as i64);
    write_inode_blocks(image, ufs, inode_number, (data_sectors + pointer_sectors) as u32);
    Ok(())
}

/// Length of the longest shared prefix of two allocation-size lists.
fn common_allocation_prefix(current: &[i64], requested: &[i64]) -> usize {
    let limit = current.len().min(requested.len());
    (0..limit).take_while(|&i| current[i] == requested[i]).count()
}

/// Copy `data` to logical `offset` within `data_blocks` (sized by
/// `allocation_sizes`). Port of `write_ufs_data_range`.
fn write_data_range(
    image: &mut [u8],
    ufs: &Ufs,
    data_blocks: &[i64],
    allocation_sizes: &[i64],
    offset: usize,
    data: &[u8],
) {
    if data.is_empty() {
        return;
    }
    let block_size = ufs.sb.bsize as usize;
    let end_offset = offset + data.len();
    let start_block = offset / block_size;
    let end_block = data_blocks
        .len()
        .min(allocation_sizes.len())
        .min(end_offset.div_ceil(block_size));
    for block_index in start_block..end_block {
        let fs_block = data_blocks[block_index];
        let allocation_bytes = allocation_sizes[block_index] as usize;
        let logical_start = block_index * block_size;
        let inner_start = offset.saturating_sub(logical_start);
        let inner_end = block_size.min(end_offset - logical_start).min(allocation_bytes);
        if inner_start >= inner_end {
            continue;
        }
        let data_start = logical_start + inner_start - offset;
        let data_end = logical_start + inner_end - offset;
        let backing = ufs.sb.data_block_offset(ufs.start_offset, fs_block) as usize;
        image[backing + inner_start..backing + inner_end].copy_from_slice(&data[data_start..data_end]);
    }
}

/// Write `data` at byte `offset` in an inode, extending it as needed, while
/// reallocating only the *suffix* whose block allocation actually changes — not
/// the whole file. Port of the in-place / realloc-suffix / append branches of
/// `apply_ufs_inode_write`, unified through the existing pointer-structure
/// builder (so a directory that grows one block does O(1) work instead of the
/// whole-directory rewrite [`set_inode_contents`] would do).
///
/// Zero-extension between `old_size` and `offset` is not needed by the current
/// callers (directory growth appends at exactly `old_size`), so it is omitted.
/// Handles direct and indirect inodes (the pointer structure is rebuilt over the
/// preserved prefix plus the freshly-allocated suffix).
fn apply_inode_write(
    image: &mut [u8],
    ufs: &Ufs,
    inode_number: i64,
    offset: usize,
    data: &[u8],
) -> WResult<()> {
    let sb = &ufs.sb;
    let block_size = sb.bsize as usize;
    let inode = read_inode(&*image, ufs, inode_number)
        .ok_or_else(|| format!("error: could not read inode {inode_number} for write"))?;
    let old_size = inode.size as usize;
    let new_size = old_size.max(offset + data.len());

    let current_blocks = inode_data_blocks(&*image, ufs, &inode);
    let current_alloc = sb.allocation_byte_sizes(old_size as i64);
    let requested_alloc = sb.allocation_byte_sizes(new_size as i64);

    if requested_alloc == current_alloc {
        // No (re)allocation: overwrite in place.
        let blocks: Vec<i64> = current_blocks.iter().map(|&b| b as i64).collect();
        write_data_range(image, ufs, &blocks, &current_alloc, offset, data);
        if new_size != old_size {
            write_inode_size(image, ufs, inode_number, new_size as u64);
        }
        return Ok(());
    }

    // Reallocate only the changed suffix, preserving the common prefix.
    let prefix = common_allocation_prefix(&current_alloc, &requested_alloc);
    let prefix_offset = prefix * block_size;
    let preserved_suffix_bytes = old_size.saturating_sub(prefix_offset);
    let old_suffix_blocks = &current_blocks[prefix..];
    let suffix_seed = read_data_range(&*image, ufs, old_suffix_blocks, 0, preserved_suffix_bytes);

    let pointer_blocks = inode_pointer_blocks(&*image, ufs, &inode);
    for &pointer_block in pointer_blocks.iter().rev() {
        free_allocation(image, ufs, pointer_block as i64, block_size as i64)?;
    }
    for (&fs_block, &allocation_bytes) in old_suffix_blocks
        .iter()
        .rev()
        .zip(current_alloc[prefix..].iter().rev())
    {
        free_allocation(image, ufs, fs_block as i64, allocation_bytes)?;
    }

    let mut rebuilt: Vec<i64> = current_blocks[..prefix].iter().map(|&b| b as i64).collect();
    let new_suffix_alloc = &requested_alloc[prefix..];
    for &allocation_bytes in new_suffix_alloc {
        rebuilt.push(allocate_allocation(image, ufs, inode_number, allocation_bytes)?);
    }
    if !suffix_seed.is_empty() {
        write_data_range(image, ufs, &rebuilt[prefix..], new_suffix_alloc, 0, &suffix_seed);
    }

    let new_pointer_block_count = build_inode_pointer_structure(image, ufs, inode_number, &rebuilt)?;
    write_inode_size(image, ufs, inode_number, new_size as u64);
    let data_sectors: i64 = requested_alloc.iter().map(|a| a / SECTOR_SIZE as i64).sum();
    let pointer_sectors = new_pointer_block_count * (block_size as i64 / SECTOR_SIZE as i64);
    write_inode_blocks(image, ufs, inode_number, (data_sectors + pointer_sectors) as u32);

    write_data_range(image, ufs, &rebuilt, &requested_alloc, offset, data);
    Ok(())
}

// --- directory entry encoding & insertion ----------------------------------

/// Port of `encode_ufs_directory_entry`: a record of `record_length` bytes.
fn encode_entry(inode_number: i64, name: &str, record_length: usize) -> Vec<u8> {
    let mut raw = vec![0u8; record_length];
    put_u32(&mut raw, 0, inode_number as u32);
    put_u16(&mut raw, UFS_DIRENT_RECLEN_OFFSET, record_length as u16);
    put_u16(&mut raw, UFS_DIRENT_NAMLEN_OFFSET, name.len() as u16);
    raw[UFS_DIRENT_NAME_OFFSET..UFS_DIRENT_NAME_OFFSET + name.len()].copy_from_slice(name.as_bytes());
    raw
}

/// Build the initial directory data block ("." + ".." filling DIRBLKSIZ).
/// Port of `build_ufs_directory_block`.
pub fn build_directory_block(self_inode: i64, parent_inode: i64) -> Vec<u8> {
    let dot = encode_entry(self_inode, ".", ufs_dirsiz(1));
    let mut block = dot;
    let dotdot = encode_entry(parent_inode, "..", UFS_DIRBLKSIZ - block.len());
    block.extend_from_slice(&dotdot);
    block
}

struct InsertSlot {
    block_offset: usize,
    entry_offset: usize,
    record_length: usize,
    previous_entry_offset: Option<usize>,
    previous_entry_new_length: Option<usize>,
}

/// Port of `find_ufs_directory_insert_slot`.
fn find_insert_slot(directory_bytes: &[u8], size: usize, name: &str) -> Option<InsertSlot> {
    let needed_length = ufs_dirsiz(name.len());
    let max_length = directory_bytes.len().min(size);
    let mut rounded_length = max_length.div_ceil(UFS_DIRBLKSIZ) * UFS_DIRBLKSIZ;
    if rounded_length == 0 {
        rounded_length = UFS_DIRBLKSIZ;
    }
    let mut block_offset = 0;
    while block_offset < rounded_length {
        let block_limit = (block_offset + UFS_DIRBLKSIZ).min(max_length);
        let block_span = block_limit as isize - block_offset as isize;
        if block_span <= 0 {
            if needed_length <= UFS_DIRBLKSIZ {
                return Some(InsertSlot {
                    block_offset,
                    entry_offset: block_offset,
                    record_length: UFS_DIRBLKSIZ,
                    previous_entry_offset: None,
                    previous_entry_new_length: None,
                });
            }
            block_offset += UFS_DIRBLKSIZ;
            continue;
        }

        let mut cursor = block_offset;
        let mut found_record = false;
        while cursor + 8 <= block_limit {
            // Header-only decode: the slot scan needs the inode and the two
            // lengths, never the name itself — decoding/allocating a String per
            // record here dominated directory population (callgrind: ~55%).
            let Some(entry) = decode_directory_header(directory_bytes, cursor, block_limit) else {
                break;
            };
            found_record = true;
            if entry.inode == 0 && entry.record_length as usize >= needed_length {
                return Some(InsertSlot {
                    block_offset,
                    entry_offset: cursor,
                    record_length: entry.record_length as usize,
                    previous_entry_offset: None,
                    previous_entry_new_length: None,
                });
            }
            let minimal_length = ufs_dirsiz(entry.name_length as usize);
            // Saturating: a record shorter than its minimal size (e.g. a small
            // free slot) yields 0 here, i.e. "no room" — matching the Python
            // reference, whose ints just go negative and fail the check below.
            let available_length = (entry.record_length as usize).saturating_sub(minimal_length);
            if entry.inode != 0 && available_length >= needed_length {
                return Some(InsertSlot {
                    block_offset,
                    entry_offset: cursor + minimal_length,
                    record_length: available_length,
                    previous_entry_offset: Some(cursor),
                    previous_entry_new_length: Some(minimal_length),
                });
            }
            cursor += entry.record_length as usize;
        }

        if !found_record && needed_length <= UFS_DIRBLKSIZ {
            return Some(InsertSlot {
                block_offset,
                entry_offset: block_offset,
                record_length: UFS_DIRBLKSIZ,
                previous_entry_offset: None,
                previous_entry_new_length: None,
            });
        }
        block_offset += UFS_DIRBLKSIZ;
    }
    // Every existing directory block is full: grow by appending a fresh block at
    // the end (matching the Python `add_ufs_directory_entry` fallback, which is
    // itself the UFS `direnter` "add a block" path in `uts/.../ufs_dir.c`).
    if needed_length <= UFS_DIRBLKSIZ {
        return Some(InsertSlot {
            block_offset: rounded_length,
            entry_offset: rounded_length,
            record_length: UFS_DIRBLKSIZ,
            previous_entry_offset: None,
            previous_entry_new_length: None,
        });
    }
    None
}

/// Port of `insert_ufs_directory_entry`: returns the updated directory bytes.
fn insert_entry(directory_bytes: &[u8], size: usize, inode_number: i64, name: &str) -> WResult<Vec<u8>> {
    let slot = find_insert_slot(directory_bytes, size, name)
        .ok_or_else(|| format!("no directory slot available for {name:?}"))?;
    let needed_length = ufs_dirsiz(name.len());
    let mut target_length = needed_length.max(slot.record_length);
    let new_size = directory_bytes
        .len()
        .max(slot.block_offset + UFS_DIRBLKSIZ)
        .max(slot.entry_offset + target_length);
    let mut updated = vec![0u8; new_size];
    updated[..directory_bytes.len()].copy_from_slice(directory_bytes);

    if let (Some(prev_off), Some(prev_len)) = (slot.previous_entry_offset, slot.previous_entry_new_length) {
        put_u16(&mut updated, prev_off + UFS_DIRENT_RECLEN_OFFSET, prev_len as u16);
        target_length = slot.record_length;
    } else {
        let remaining_length = slot.record_length - needed_length;
        if remaining_length >= 8 {
            let filler = encode_entry(0, "", remaining_length);
            updated[slot.entry_offset + needed_length..slot.entry_offset + slot.record_length]
                .copy_from_slice(&filler);
            target_length = needed_length;
        }
    }

    let record = encode_entry(inode_number, name, target_length);
    updated[slot.entry_offset..slot.entry_offset + target_length].copy_from_slice(&record);
    Ok(updated)
}

/// Add a directory entry, writing in place when an existing block has slack and
/// only rewriting the whole directory when it must grow by a block.
pub fn add_directory_entry(
    image: &mut [u8],
    ufs: &Ufs,
    directory_inode_number: i64,
    directory_inode: &Inode,
    entry_name: &str,
    child_inode_number: i64,
) -> WResult<()> {
    let size = directory_inode.size as usize;
    let block_size = ufs.sb.bsize as usize;
    let rounded = size.div_ceil(UFS_DIRBLKSIZ) * UFS_DIRBLKSIZ;

    // Fast path: sequential population appends into the final directory block.
    // Trying just that one block avoids reading and rescanning the *whole*
    // directory on every insert, which is otherwise O(n^2) for large dirs
    // (callgrind hot spot). Port of the same fast path in the Python
    // `add_ufs_directory_entry`.
    if rounded > UFS_DIRBLKSIZ {
        let last_off = rounded - UFS_DIRBLKSIZ;
        let span = (size - last_off).min(UFS_DIRBLKSIZ);
        if span > 0 {
            let last_block = read_inode_range(&*image, ufs, directory_inode, last_off, span);
            if let Ok(updated) = insert_entry(&last_block, span, child_inode_number, entry_name) {
                if updated.len() == span {
                    let data_blocks = inode_data_blocks(&*image, ufs, directory_inode);
                    let fs_block = data_blocks[last_off / block_size];
                    let backing = ufs.sb.data_block_offset(ufs.start_offset, fs_block as i64) as usize;
                    let inner = last_off % block_size;
                    image[backing + inner..backing + inner + span].copy_from_slice(&updated);
                    return Ok(());
                }
            }
        }
    }

    // General path: scan the whole directory for a reusable slot, else grow.
    let dir_bytes = read_inode_bytes(&*image, ufs, directory_inode);
    let updated = insert_entry(&dir_bytes, size, child_inode_number, entry_name)?;

    if updated.len() == size {
        // In-place: write back only the directory blocks that changed.
        let data_blocks = inode_data_blocks(&*image, ufs, directory_inode);
        let mut offset = 0;
        while offset < size {
            let end = (offset + UFS_DIRBLKSIZ).min(size);
            if dir_bytes[offset..end] != updated[offset..end] {
                let logical_block = offset / block_size;
                let inner = offset % block_size;
                let fs_block = data_blocks[logical_block];
                let backing = ufs.sb.data_block_offset(ufs.start_offset, fs_block as i64) as usize;
                image[backing + inner..backing + inner + (end - offset)]
                    .copy_from_slice(&updated[offset..end]);
            }
            offset += UFS_DIRBLKSIZ;
        }
        Ok(())
    } else {
        // Growth: append only the new trailing block instead of rewriting the
        // whole directory. `insert_entry` appended one DIRBLKSIZ block at the end
        // and left existing blocks untouched, so `apply_inode_write` reallocates
        // just the changed suffix (O(1) for direct blocks; for indirect dirs it
        // rebuilds the pointer tree but still avoids rewriting all the data).
        apply_inode_write(image, ufs, directory_inode_number, size, &updated[size..])
    }
}

// --- path helpers -----------------------------------------------------------

fn split_parent(path: &str) -> (String, String) {
    let parts: Vec<&str> = path.split('/').filter(|p| !p.is_empty()).collect();
    let name = parts.last().copied().unwrap_or("").to_string();
    let parent = if parts.len() > 1 {
        parts[..parts.len() - 1].join("/")
    } else {
        String::new()
    };
    (parent, name)
}

/// Resolve the parent directory of `target_path`, ensuring it exists, is a
/// directory, and does not already contain the final component. Port of
/// `resolve_ufs_creation_parent`.
fn resolve_creation_parent(image: &[u8], ufs: &Ufs, target_path: &str) -> WResult<(String, i64, Inode)> {
    let (parent_path, entry_name) = split_parent(target_path);
    let (parent_number, parent_inode) = resolve_path(image, ufs, &parent_path)
        .ok_or_else(|| format!("error: could not resolve parent path {parent_path} inside the ufs filesystem"))?;
    if !parent_inode.is_directory() {
        return Err(format!("error: parent path {parent_path} is not a UFS directory"));
    }
    if lookup_directory_entry(image, ufs, &parent_inode, &entry_name).is_some() {
        return Err(format!(
            "error: target path {target_path} already exists inside the ufs filesystem"
        ));
    }
    Ok((entry_name, parent_number as i64, parent_inode))
}

// --- high-level operations --------------------------------------------------

/// Create a regular file (or special-typed file when `mode` carries a type).
/// Port of `create_ufs_file` (creation path). Returns the new inode number.
#[allow(clippy::too_many_arguments)]
pub fn create_file(
    image: &mut [u8],
    ufs: &Ufs,
    target_path: &str,
    file_bytes: &[u8],
    mode: u32,
    uid: u32,
    gid: u32,
    timestamp: u32,
) -> WResult<i64> {
    let (entry_name, parent_number, parent_inode) = resolve_creation_parent(&*image, ufs, target_path)?;
    let new_number = allocate_inode(image, ufs, Some(parent_number), false)?;
    let file_type = if mode & UFS_IFMT != 0 { mode & UFS_IFMT } else { UFS_IFREG };
    let permissions = mode & !UFS_IFMT;
    initialize_inode(image, ufs, new_number, file_type | permissions, uid, gid, 1, timestamp);
    if !file_bytes.is_empty() {
        set_inode_contents(image, ufs, new_number, file_bytes)?;
    }
    add_directory_entry(image, ufs, parent_number, &parent_inode, &entry_name, new_number)?;
    Ok(new_number)
}

/// Create a directory (with "." and ".."). Port of `make_ufs_directory`.
#[allow(clippy::too_many_arguments)]
pub fn make_directory(
    image: &mut [u8],
    ufs: &Ufs,
    target_path: &str,
    mode: u32,
    uid: u32,
    gid: u32,
    timestamp: u32,
) -> WResult<i64> {
    let (entry_name, parent_number, parent_inode) = resolve_creation_parent(&*image, ufs, target_path)?;
    let new_number = allocate_inode(image, ufs, Some(parent_number), true)?;
    let permissions = mode & !UFS_IFMT;
    initialize_inode(image, ufs, new_number, UFS_IFDIR | permissions, uid, gid, 2, timestamp);
    set_inode_contents(image, ufs, new_number, &build_directory_block(new_number, parent_number))?;
    add_directory_entry(image, ufs, parent_number, &parent_inode, &entry_name, new_number)?;
    write_inode_nlink(image, ufs, parent_number, parent_inode.nlink + 1);
    Ok(new_number)
}

/// Create a hard link to an existing non-directory file. Port of `link_ufs_path`.
pub fn link(image: &mut [u8], ufs: &Ufs, source_path: &str, target_path: &str) -> WResult<i64> {
    let (source_number, source_inode) = resolve_path(&*image, ufs, source_path)
        .ok_or_else(|| format!("error: source path {source_path} does not exist inside the ufs filesystem"))?;
    let source_number = source_number as i64;
    if source_inode.is_directory() {
        return Err(format!("error: refusing to create a hard link to directory {source_path}"));
    }
    let (entry_name, parent_number, parent_inode) = resolve_creation_parent(&*image, ufs, target_path)?;
    add_directory_entry(image, ufs, parent_number, &parent_inode, &entry_name, source_number)?;
    write_inode_nlink(image, ufs, source_number, source_inode.nlink + 1);
    Ok(source_number)
}

/// Create a symbolic link. Port of `symlink_ufs_path` (the target is stored in
/// the inode's data blocks via `create_file`).
#[allow(clippy::too_many_arguments)]
pub fn symlink(
    image: &mut [u8],
    ufs: &Ufs,
    target: &str,
    link_path: &str,
    mode: u32,
    uid: u32,
    gid: u32,
    timestamp: u32,
) -> WResult<i64> {
    create_file(image, ufs, link_path, target.as_bytes(), UFS_IFLNK | mode, uid, gid, timestamp)
}

// --- removal ---------------------------------------------------------------

/// Remove the entry `name` from a single directory block, returning the updated
/// block bytes (same length). Either merges the record into its predecessor or
/// zeroes its inode in place. Port of `remove_ufs_directory_entry`.
fn remove_entry(block: &[u8], size: usize, name: &str) -> Option<Vec<u8>> {
    let records = iter_directory_records(block, size);
    let mut updated = block.to_vec();
    let mut previous: Option<crate::dir::DirEntry> = None;
    for record in records {
        if record.name != name || record.inode == 0 {
            previous = if record.offset % UFS_DIRBLKSIZ == 0 {
                None
            } else {
                Some(record)
            };
            continue;
        }
        match &previous {
            Some(prev) if prev.offset / UFS_DIRBLKSIZ == record.offset / UFS_DIRBLKSIZ => {
                let merged = prev.record_length + record.record_length;
                put_u16(&mut updated, prev.offset + UFS_DIRENT_RECLEN_OFFSET, merged);
            }
            _ => {
                let empty = encode_entry(0, "", record.record_length as usize);
                updated[record.offset..record.offset + record.record_length as usize]
                    .copy_from_slice(&empty);
            }
        }
        return Some(updated);
    }
    None
}

/// Remove `entry_name` from a directory, writing the affected block back in
/// place (removal never changes the directory's size). Port of
/// `delete_ufs_directory_entry`.
pub fn delete_directory_entry(
    image: &mut [u8],
    ufs: &Ufs,
    directory_inode: &Inode,
    entry_name: &str,
) -> WResult<()> {
    let size = directory_inode.size as usize;
    let dir_bytes = read_inode_bytes(&*image, ufs, directory_inode);
    let block_size = ufs.sb.bsize as usize;
    let data_blocks = inode_data_blocks(&*image, ufs, directory_inode);
    let mut block_offset = 0;
    while block_offset < size {
        let block_span = UFS_DIRBLKSIZ.min(size - block_offset);
        let block = &dir_bytes[block_offset..block_offset + block_span];
        if let Some(updated) = remove_entry(block, block_span, entry_name) {
            let logical_block = block_offset / block_size;
            let inner = block_offset % block_size;
            let fs_block = data_blocks[logical_block];
            let backing = ufs.sb.data_block_offset(ufs.start_offset, fs_block as i64) as usize;
            image[backing + inner..backing + inner + block_span].copy_from_slice(&updated);
            return Ok(());
        }
        block_offset += UFS_DIRBLKSIZ;
    }
    Err(format!("error: could not find directory entry {entry_name:?} to remove"))
}

/// Free every block an inode owns by truncating it to zero length. Port of
/// `free_ufs_inode_contents` (= replacement with empty data).
pub fn free_inode_contents(image: &mut [u8], ufs: &Ufs, inode_number: i64) -> WResult<()> {
    set_inode_contents(image, ufs, inode_number, &[])
}

/// Resolve the parent directory of `target_path` for a removal (the final
/// component must exist, unlike `resolve_creation_parent`).
fn resolve_removal_parent(image: &[u8], ufs: &Ufs, target_path: &str) -> WResult<(String, i64, Inode)> {
    let (parent_path, entry_name) = split_parent(target_path);
    let (parent_number, parent_inode) = resolve_path(image, ufs, &parent_path)
        .ok_or_else(|| format!("error: could not resolve parent path {parent_path} inside the ufs filesystem"))?;
    Ok((entry_name, parent_number as i64, parent_inode))
}

/// Unlink a non-directory path: drop the directory entry and either decrement
/// the link count or free the inode if it was the last link. Port of
/// `unlink_ufs_path`.
pub fn unlink(image: &mut [u8], ufs: &Ufs, target_path: &str) -> WResult<i64> {
    if target_path == "/" {
        return Err("error: refusing to unlink the UFS root directory".into());
    }
    let (target_number, target_inode) = resolve_path(&*image, ufs, target_path)
        .ok_or_else(|| format!("error: target path {target_path} does not exist inside the ufs filesystem"))?;
    let target_number = target_number as i64;
    if target_inode.is_directory() {
        return Err(format!("error: target path {target_path} is a directory; use rmdir instead"));
    }
    let (entry_name, _parent_number, parent_inode) = resolve_removal_parent(&*image, ufs, target_path)?;
    delete_directory_entry(image, ufs, &parent_inode, &entry_name)?;
    if target_inode.nlink > 1 {
        write_inode_nlink(image, ufs, target_number, target_inode.nlink - 1);
    } else {
        free_inode_contents(image, ufs, target_number)?;
        clear_inode(image, ufs, target_number);
        free_inode(image, ufs, target_number, false)?;
    }
    Ok(target_number)
}

/// Whether a directory inode has no entries other than "." and "..".
pub fn directory_is_empty(image: &[u8], ufs: &Ufs, inode: &Inode) -> bool {
    iter_inode_directory_records(image, ufs, inode)
        .into_iter()
        .all(|record| record.inode == 0 || record.name == "." || record.name == "..")
}

/// Remove an empty directory. Port of `remove_ufs_directory`.
pub fn remove_directory(image: &mut [u8], ufs: &Ufs, target_path: &str) -> WResult<i64> {
    if target_path == "/" {
        return Err("error: refusing to remove the UFS root directory".into());
    }
    let (target_number, target_inode) = resolve_path(&*image, ufs, target_path)
        .ok_or_else(|| format!("error: target path {target_path} does not exist inside the ufs filesystem"))?;
    let target_number = target_number as i64;
    if !target_inode.is_directory() {
        return Err(format!("error: target path {target_path} is not a directory"));
    }
    if !directory_is_empty(&*image, ufs, &target_inode) {
        return Err(format!("error: target directory {target_path} is not empty"));
    }
    let (entry_name, parent_number, parent_inode) = resolve_removal_parent(&*image, ufs, target_path)?;
    delete_directory_entry(image, ufs, &parent_inode, &entry_name)?;
    write_inode_nlink(image, ufs, parent_number, parent_inode.nlink.saturating_sub(1));
    free_inode_contents(image, ufs, target_number)?;
    clear_inode(image, ufs, target_number);
    free_inode(image, ufs, target_number, true)?;
    Ok(target_number)
}

// ===========================================================================
// Inode-based primitives for the FUSE daemon.
//
// FUSE addresses objects by (parent inode, name) rather than by path, so the
// daemon needs parent-inode variants of the create/remove operations plus
// rename, truncate, and the setattr field setters. These reuse the same
// building blocks as the path-based functions above.
// ===========================================================================

/// Create an empty regular file named `name` in directory `parent_number`.
/// Returns the new inode number. (The daemon writes contents later via
/// [`set_inode_contents`] on release.)
#[allow(clippy::too_many_arguments)]
pub fn create_empty_in_parent(
    image: &mut [u8],
    ufs: &Ufs,
    parent_number: i64,
    name: &str,
    mode: u32,
    uid: u32,
    gid: u32,
    timestamp: u32,
) -> WResult<i64> {
    let parent_inode = read_inode(&*image, ufs, parent_number)
        .ok_or_else(|| format!("error: parent inode {parent_number} is unreadable"))?;
    if !parent_inode.is_directory() {
        return Err("error: parent inode is not a UFS directory".into());
    }
    let new_number = allocate_inode(image, ufs, Some(parent_number), false)?;
    let file_type = if mode & UFS_IFMT != 0 { mode & UFS_IFMT } else { UFS_IFREG };
    initialize_inode(image, ufs, new_number, file_type | (mode & !UFS_IFMT), uid, gid, 1, timestamp);
    add_directory_entry(image, ufs, parent_number, &parent_inode, name, new_number)?;
    Ok(new_number)
}

/// Create a directory named `name` in `parent_number`. Returns its inode number.
#[allow(clippy::too_many_arguments)]
pub fn mkdir_in_parent(
    image: &mut [u8],
    ufs: &Ufs,
    parent_number: i64,
    name: &str,
    mode: u32,
    uid: u32,
    gid: u32,
    timestamp: u32,
) -> WResult<i64> {
    let parent_inode = read_inode(&*image, ufs, parent_number)
        .ok_or_else(|| format!("error: parent inode {parent_number} is unreadable"))?;
    if !parent_inode.is_directory() {
        return Err("error: parent inode is not a UFS directory".into());
    }
    let new_number = allocate_inode(image, ufs, Some(parent_number), true)?;
    initialize_inode(image, ufs, new_number, UFS_IFDIR | (mode & !UFS_IFMT), uid, gid, 2, timestamp);
    set_inode_contents(image, ufs, new_number, &build_directory_block(new_number, parent_number))?;
    add_directory_entry(image, ufs, parent_number, &parent_inode, name, new_number)?;
    write_inode_nlink(image, ufs, parent_number, parent_inode.nlink + 1);
    Ok(new_number)
}

/// Create a symlink named `name` (target stored in the inode's data) in
/// `parent_number`. Returns its inode number.
#[allow(clippy::too_many_arguments)]
pub fn symlink_in_parent(
    image: &mut [u8],
    ufs: &Ufs,
    parent_number: i64,
    name: &str,
    target: &str,
    mode: u32,
    uid: u32,
    gid: u32,
    timestamp: u32,
) -> WResult<i64> {
    let parent_inode = read_inode(&*image, ufs, parent_number)
        .ok_or_else(|| format!("error: parent inode {parent_number} is unreadable"))?;
    let new_number = allocate_inode(image, ufs, Some(parent_number), false)?;
    initialize_inode(image, ufs, new_number, UFS_IFLNK | (mode & !UFS_IFMT), uid, gid, 1, timestamp);
    set_inode_contents(image, ufs, new_number, target.as_bytes())?;
    add_directory_entry(image, ufs, parent_number, &parent_inode, name, new_number)?;
    Ok(new_number)
}

/// Create a character or block special file (device node) named `name` in
/// `parent_number`. SVR4 stores the rdev in the first two direct-block slots:
/// `db[0]` = the old 7-bit-major/8-bit-minor form, `db[1]` = the expanded
/// `(major << 18) | minor` form. Port of `create_ufs_special_file`.
#[allow(clippy::too_many_arguments)]
pub fn mknod_in_parent(
    image: &mut [u8],
    ufs: &Ufs,
    parent_number: i64,
    name: &str,
    file_type: u32,
    major: u32,
    minor: u32,
    mode: u32,
    uid: u32,
    gid: u32,
    timestamp: u32,
) -> WResult<i64> {
    if file_type != UFS_IFCHR && file_type != UFS_IFBLK {
        return Err(format!("error: unsupported special file type 0o{file_type:o}"));
    }
    let parent_inode = read_inode(&*image, ufs, parent_number)
        .ok_or_else(|| format!("error: parent inode {parent_number} is unreadable"))?;
    if !parent_inode.is_directory() {
        return Err("error: parent inode is not a UFS directory".into());
    }
    let new_number = allocate_inode(image, ufs, Some(parent_number), false)?;
    let permissions = mode & !UFS_IFMT;
    initialize_inode(image, ufs, new_number, file_type | permissions, uid, gid, 1, timestamp);
    write_inode_size(image, ufs, new_number, 0);
    write_inode_blocks(image, ufs, new_number, 0);
    let old_device = (((major & 0x7f) << 8) | (minor & 0xff)) as i64;
    let expanded_device = ((major << 18) | minor) as i64;
    write_block_lists(image, ufs, new_number, &[old_device, expanded_device], &[0, 0, 0]);
    add_directory_entry(image, ufs, parent_number, &parent_inode, name, new_number)?;
    Ok(new_number)
}

/// Create a hard link named `name` in `parent_number` to an existing inode.
pub fn link_in_parent(
    image: &mut [u8],
    ufs: &Ufs,
    parent_number: i64,
    name: &str,
    target_number: i64,
) -> WResult<()> {
    let parent_inode = read_inode(&*image, ufs, parent_number)
        .ok_or_else(|| format!("error: parent inode {parent_number} is unreadable"))?;
    let target_inode = read_inode(&*image, ufs, target_number)
        .ok_or_else(|| format!("error: link target inode {target_number} is unreadable"))?;
    if target_inode.is_directory() {
        return Err("error: refusing to hard-link a directory".into());
    }
    add_directory_entry(image, ufs, parent_number, &parent_inode, name, target_number)?;
    write_inode_nlink(image, ufs, target_number, target_inode.nlink + 1);
    Ok(())
}

/// Unlink `name` (a non-directory) from `parent_number`. Returns the affected
/// inode number.
pub fn unlink_in_parent(image: &mut [u8], ufs: &Ufs, parent_number: i64, name: &str) -> WResult<i64> {
    let parent_inode = read_inode(&*image, ufs, parent_number)
        .ok_or_else(|| format!("error: parent inode {parent_number} is unreadable"))?;
    let (target_number, target_inode) = lookup_directory_entry(&*image, ufs, &parent_inode, name)
        .ok_or_else(|| format!("error: {name:?} does not exist"))?;
    let target_number = target_number as i64;
    if target_inode.is_directory() {
        return Err(format!("error: {name:?} is a directory; use rmdir"));
    }
    delete_directory_entry(image, ufs, &parent_inode, name)?;
    if target_inode.nlink > 1 {
        write_inode_nlink(image, ufs, target_number, target_inode.nlink - 1);
    } else {
        free_inode_contents(image, ufs, target_number)?;
        clear_inode(image, ufs, target_number);
        free_inode(image, ufs, target_number, false)?;
    }
    Ok(target_number)
}

/// Remove empty directory `name` from `parent_number`. Returns its inode number.
pub fn rmdir_in_parent(image: &mut [u8], ufs: &Ufs, parent_number: i64, name: &str) -> WResult<i64> {
    let parent_inode = read_inode(&*image, ufs, parent_number)
        .ok_or_else(|| format!("error: parent inode {parent_number} is unreadable"))?;
    let (target_number, target_inode) = lookup_directory_entry(&*image, ufs, &parent_inode, name)
        .ok_or_else(|| format!("error: {name:?} does not exist"))?;
    let target_number = target_number as i64;
    if !target_inode.is_directory() {
        return Err(format!("error: {name:?} is not a directory"));
    }
    if !directory_is_empty(&*image, ufs, &target_inode) {
        return Err(format!("error: directory {name:?} is not empty"));
    }
    delete_directory_entry(image, ufs, &parent_inode, name)?;
    write_inode_nlink(image, ufs, parent_number, parent_inode.nlink.saturating_sub(1));
    free_inode_contents(image, ufs, target_number)?;
    clear_inode(image, ufs, target_number);
    free_inode(image, ufs, target_number, true)?;
    Ok(target_number)
}

/// Rewrite the inode of entry `name` within a single directory block.
fn rewrite_entry_inode(block: &[u8], size: usize, name: &str, inode_number: i64) -> Option<Vec<u8>> {
    let mut updated = block.to_vec();
    for record in iter_directory_records(block, size) {
        if record.inode != 0 && record.name == name {
            put_u32(&mut updated, record.offset, inode_number as u32);
            return Some(updated);
        }
    }
    None
}

/// Point a directory's ".." entry at a new parent (used when moving a directory
/// across parents). Writes the affected block in place.
fn update_directory_dotdot(
    image: &mut [u8],
    ufs: &Ufs,
    dir_inode: &Inode,
    new_parent_number: i64,
) -> WResult<()> {
    let size = dir_inode.size as usize;
    let dir_bytes = read_inode_bytes(&*image, ufs, dir_inode);
    let block_size = ufs.sb.bsize as usize;
    let data_blocks = inode_data_blocks(&*image, ufs, dir_inode);
    let mut block_offset = 0;
    while block_offset < size {
        let span = UFS_DIRBLKSIZ.min(size - block_offset);
        let block = &dir_bytes[block_offset..block_offset + span];
        if let Some(updated) = rewrite_entry_inode(block, span, "..", new_parent_number) {
            let fs_block = data_blocks[block_offset / block_size];
            let backing = ufs.sb.data_block_offset(ufs.start_offset, fs_block as i64) as usize;
            let inner = block_offset % block_size;
            image[backing + inner..backing + inner + span].copy_from_slice(&updated);
            return Ok(());
        }
        block_offset += UFS_DIRBLKSIZ;
    }
    Err("error: could not find '..' to rewrite".into())
}

/// Rename `src_name` in `src_parent` to `dst_name` in `dst_parent`, replacing an
/// existing target of the same kind. Port of `rename_ufs_in_parent`/`rename_ufs_path`.
pub fn rename_in_parent(
    image: &mut [u8],
    ufs: &Ufs,
    src_parent: i64,
    src_name: &str,
    dst_parent: i64,
    dst_name: &str,
) -> WResult<()> {
    if src_parent == dst_parent && src_name == dst_name {
        return Ok(());
    }
    let src_parent_inode = read_inode(&*image, ufs, src_parent)
        .ok_or_else(|| format!("error: source parent inode {src_parent} is unreadable"))?;
    let (src_number, src_inode) = lookup_directory_entry(&*image, ufs, &src_parent_inode, src_name)
        .ok_or_else(|| format!("error: source {src_name:?} does not exist"))?;
    let src_number = src_number as i64;

    // Replace an existing target of matching type.
    let dst_parent_inode = read_inode(&*image, ufs, dst_parent)
        .ok_or_else(|| format!("error: target parent inode {dst_parent} is unreadable"))?;
    if let Some((dst_number, dst_inode)) = lookup_directory_entry(&*image, ufs, &dst_parent_inode, dst_name) {
        if dst_number as i64 == src_number {
            return Ok(());
        }
        if src_inode.is_directory() != dst_inode.is_directory() {
            return Err("error: cannot rename across file and directory types".into());
        }
        if dst_inode.is_directory() {
            rmdir_in_parent(image, ufs, dst_parent, dst_name)?;
        } else {
            unlink_in_parent(image, ufs, dst_parent, dst_name)?;
        }
    }

    // Re-read parents (sizes/links may have changed) and add the new entry.
    let dst_parent_inode = read_inode(&*image, ufs, dst_parent).unwrap();
    add_directory_entry(image, ufs, dst_parent, &dst_parent_inode, dst_name, src_number)?;

    if src_inode.is_directory() && src_parent != dst_parent {
        let src_inode_fresh = read_inode(&*image, ufs, src_number).unwrap();
        update_directory_dotdot(image, ufs, &src_inode_fresh, dst_parent)?;
        let sp = read_inode(&*image, ufs, src_parent).unwrap();
        write_inode_nlink(image, ufs, src_parent, sp.nlink.saturating_sub(1));
        let dp = read_inode(&*image, ufs, dst_parent).unwrap();
        write_inode_nlink(image, ufs, dst_parent, dp.nlink + 1);
    }

    let src_parent_inode = read_inode(&*image, ufs, src_parent).unwrap();
    delete_directory_entry(image, ufs, &src_parent_inode, src_name)?;
    Ok(())
}

/// Truncate or zero-extend an inode to `size` bytes (reuses [`set_inode_contents`]).
pub fn truncate(image: &mut [u8], ufs: &Ufs, inode_number: i64, size: u64) -> WResult<()> {
    let inode = read_inode(&*image, ufs, inode_number)
        .ok_or_else(|| format!("error: inode {inode_number} is unreadable"))?;
    if inode.size == size {
        return Ok(());
    }
    let mut content = read_inode_bytes(&*image, ufs, &inode);
    content.resize(size as usize, 0);
    set_inode_contents(image, ufs, inode_number, &content)
}

/// Set the EFT mode field (type + permission bits).
pub fn set_inode_mode(image: &mut [u8], ufs: &Ufs, inode_number: i64, mode: u32) {
    put_u32(image, inode_offset(ufs, inode_number) + UFS_DI_MODE_OFFSET, mode);
}

/// Set owner uid/gid (both the old 16-bit and EFT 32-bit fields).
pub fn set_inode_owner(image: &mut [u8], ufs: &Ufs, inode_number: i64, uid: u32, gid: u32) {
    let off = inode_offset(ufs, inode_number);
    put_u16(image, off + UFS_DI_SUID_OFFSET, uid as u16);
    put_u16(image, off + UFS_DI_SGID_OFFSET, gid as u16);
    put_u32(image, off + UFS_DI_UID_OFFSET, uid);
    put_u32(image, off + UFS_DI_GID_OFFSET, gid);
}

/// Set any of the three timestamps (each optional). Port of `write_ufs_inode_times`.
pub fn set_inode_times(
    image: &mut [u8],
    ufs: &Ufs,
    inode_number: i64,
    atime: Option<u32>,
    mtime: Option<u32>,
    ctime: Option<u32>,
) {
    let off = inode_offset(ufs, inode_number);
    if let Some(a) = atime {
        write_inode_time(image, off, UFS_DI_ATIME_OFFSET, a);
    }
    if let Some(m) = mtime {
        write_inode_time(image, off, UFS_DI_MTIME_OFFSET, m);
    }
    if let Some(c) = ctime {
        write_inode_time(image, off, UFS_DI_CTIME_OFFSET, c);
    }
}
