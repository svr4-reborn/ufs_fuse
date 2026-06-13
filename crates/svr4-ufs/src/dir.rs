//! UFS directory entry decoding. Port of the read half of
//! `host_tools/fs/ufs_directory.py`.

use svr4_fs_core::codec::{u16, u32};
use svr4_fs_core::consts::{
    UFS_DIRENT_HEADER_SIZE, UFS_DIRENT_NAMLEN_OFFSET, UFS_DIRENT_NAME_OFFSET,
    UFS_DIRENT_RECLEN_OFFSET,
};

/// A decoded directory entry (`struct direct`). `offset` is the byte offset of
/// the record within the directory data the caller passed in.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DirEntry {
    pub inode: u32,
    pub record_length: u16,
    pub name_length: u16,
    pub name: String,
    pub offset: usize,
}

/// The fixed header of a directory record: `(inode, record_length, name_length)`,
/// decoded without touching (or allocating) the name — for hot scans like slot
/// finding that only need the sizes.
pub struct DirEntryHeader {
    pub inode: u32,
    pub record_length: u16,
    pub name_length: u16,
}

/// Decode just the header of the record at `offset` (no name allocation).
/// Returns `None` for a malformed/out-of-bounds record. Validated core shared
/// with [`decode_directory_entry`].
#[inline]
pub fn decode_directory_header(
    bytes: &[u8],
    offset: usize,
    max_length: usize,
) -> Option<DirEntryHeader> {
    if offset + UFS_DIRENT_HEADER_SIZE > max_length {
        return None;
    }
    let inode = u32(bytes, offset);
    let record_length = u16(bytes, offset + UFS_DIRENT_RECLEN_OFFSET);
    let name_length = u16(bytes, offset + UFS_DIRENT_NAMLEN_OFFSET);
    if record_length == 0 || offset + record_length as usize > max_length {
        return None;
    }
    if name_length > 255 || offset + UFS_DIRENT_NAME_OFFSET + name_length as usize > max_length {
        return None;
    }
    Some(DirEntryHeader { inode, record_length, name_length })
}

/// Decode one directory record at `offset`, bounded by `max_length`, including
/// its name. Returns `None` for a malformed or out-of-bounds record (which also
/// terminates iteration). Port of `decode_ufs_directory_entry`.
pub fn decode_directory_entry(bytes: &[u8], offset: usize, max_length: usize) -> Option<DirEntry> {
    let header = decode_directory_header(bytes, offset, max_length)?;
    let name_start = offset + UFS_DIRENT_NAME_OFFSET;
    let name = decode_ascii_replace(&bytes[name_start..name_start + header.name_length as usize]);
    Some(DirEntry {
        inode: header.inode,
        record_length: header.record_length,
        name_length: header.name_length,
        name,
        offset,
    })
}

/// Walk the directory records in a single block-sized buffer. Port of
/// `iter_ufs_directory_records`.
pub fn iter_directory_records(bytes: &[u8], size: usize) -> Vec<DirEntry> {
    let mut records = Vec::new();
    let max_length = bytes.len().min(size);
    let mut offset = 0;
    while offset + UFS_DIRENT_HEADER_SIZE <= max_length {
        match decode_directory_entry(bytes, offset, max_length) {
            Some(entry) => {
                offset += entry.record_length as usize;
                records.push(entry);
            }
            None => break,
        }
    }
    records
}

/// Decode bytes as ASCII, replacing any non-ASCII byte with U+FFFD, matching
/// Python's `decode('ascii', errors='replace')`.
fn decode_ascii_replace(raw: &[u8]) -> String {
    raw.iter()
        .map(|&b| if b < 0x80 { b as char } else { '\u{FFFD}' })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use svr4_fs_core::codec::{put_u16, put_u32};
    use svr4_fs_core::consts::UFS_DIRBLKSIZ;

    fn write_entry(block: &mut [u8], offset: usize, inode: u32, reclen: u16, name: &str) {
        put_u32(block, offset, inode);
        put_u16(block, offset + 4, reclen);
        put_u16(block, offset + 6, name.len() as u16);
        block[offset + 8..offset + 8 + name.len()].copy_from_slice(name.as_bytes());
    }

    #[test]
    fn decodes_dot_and_dotdot_block() {
        // The classic first directory block: "." (reclen 12) then ".." filling
        // the rest of the 512-byte block.
        let mut block = vec![0u8; UFS_DIRBLKSIZ];
        write_entry(&mut block, 0, 2, 12, ".");
        write_entry(&mut block, 12, 2, (UFS_DIRBLKSIZ - 12) as u16, "..");

        let records = iter_directory_records(&block, UFS_DIRBLKSIZ);
        assert_eq!(records.len(), 2);
        assert_eq!(records[0].name, ".");
        assert_eq!(records[0].inode, 2);
        assert_eq!(records[0].record_length, 12);
        assert_eq!(records[1].name, "..");
        assert_eq!(records[1].offset, 12);
    }

    #[test]
    fn stops_on_zero_record_length() {
        let mut block = vec![0u8; 64];
        write_entry(&mut block, 0, 5, 16, "file");
        // The next record has reclen 0, which must terminate iteration.
        assert_eq!(iter_directory_records(&block, 64).len(), 1);
    }

    #[test]
    fn rejects_name_running_past_record() {
        let mut block = vec![0u8; 32];
        // Claim a 200-byte name in a 16-byte slice: must decode to None.
        put_u32(&mut block, 0, 7);
        put_u16(&mut block, 4, 16);
        put_u16(&mut block, 6, 200);
        assert!(decode_directory_entry(&block, 0, 16).is_none());
    }
}
