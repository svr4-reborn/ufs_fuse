//! SVR4 UFS filesystem reader (Rust port of the read path in
//! `host_tools/fs/ufs*.py`).
//!
//! Phase 2 of `host-tools/RUST_PORT_PLAN.md`: superblock detection, inode and
//! directory parsing, indirect-block walking, path resolution, and file reads.
//! The write path (allocation, create/mkdir/etc.) and the FUSE daemon land in
//! later phases. Everything here operates on an immutable `&[u8]` image, exactly
//! like the Python reader operating on a `bytes`/`bytearray`.

pub mod alloc;
pub mod check;
pub mod detector;
pub mod dir;
pub mod format;
pub mod inode;
pub mod reader;
pub mod superblock;
pub mod write;

pub use check::check_filesystem;
pub use detector::UfsDetector;
pub use format::{format, FormatOptions};
pub use write::{
    create_empty_in_parent, create_file, link, link_in_parent, make_directory, mkdir_in_parent,
    mknod_in_parent, remove_directory, rename_in_parent, rmdir_in_parent, set_inode_contents,
    set_inode_mode, set_inode_owner, set_inode_times, symlink, symlink_in_parent, truncate, unlink,
    unlink_in_parent,
};

pub use dir::{decode_directory_entry, iter_directory_records, DirEntry};
pub use inode::{
    collect_indirect_data_blocks, inode_data_blocks, read_inode, read_pointer_block, Inode,
};
pub use reader::{
    iter_directory_entries, iter_inode_directory_records, list_root, lookup_directory_entry,
    read_data_range, read_inode_bytes, read_inode_range, read_symlink_target, resolve_path,
    DirListEntry,
};
pub use superblock::{detect_ufs_at_start, Superblock, Ufs};
