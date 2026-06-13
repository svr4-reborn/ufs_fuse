//! FUSE daemon for an SVR4 UFS slice (read/write).
//!
//! Phase 4 of `host-tools/RUST_PORT_PLAN.md`: the Rust replacement for the
//! Python pyfuse3 mount, so the populate/inspect workflow (mount + rsync into
//! the tree + unmount) needs no native Python dependency.
//!
//! The backing store is an `mmap` of the image file (`svr4_fs_core::MappedImage`)
//! so the resident set tracks the working set, not the whole image — the same
//! scalable approach the read/write tests exercise. fuser 0.17's `Filesystem`
//! methods take `&self`, so all mutable state lives behind a `Mutex`.
//!
//! Write model: file writes are buffered per inode (lazily loaded from disk on
//! the first write) and committed back through the tested
//! [`set_inode_contents`] whole-file replacement on flush/fsync/release. This
//! avoids porting the incremental block-append/realloc machinery while staying
//! fsck-clean. The cylinder-group/superblock free counts are kept consistent by
//! the allocator as it runs; `recompute_summary_counts` runs once in `destroy`
//! so the unmounted image is fsck-clean.
//!
//! Memory: the backing image is never copied into RAM (it is mmap'd, paged on
//! demand), so a tens-of-gigabyte image costs only its working set. The one
//! allocation that scales with data is the per-open-file write buffer, bounded
//! by the size of an *individual file* being written — not the image — and freed
//! when the last handle to that inode is released.

use std::collections::HashMap;
use std::ffi::OsStr;
use std::path::{Path, PathBuf};
use std::sync::Mutex;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use clap::Parser;
use fuser::{
    AccessFlags, BsdFileFlags, Config, Errno, FileAttr, FileHandle, FileType, Filesystem,
    FopenFlags, Generation, INodeNo, LockOwner, MountOption, OpenFlags, RenameFlags, ReplyAttr,
    ReplyCreate, ReplyData, ReplyDirectory, ReplyEmpty, ReplyEntry, ReplyOpen, ReplyStatfs,
    ReplyWrite, ReplyXattr, Request, SessionACL, TimeOrNow, WriteFlags,
};

use svr4_fs_core::consts::{
    UFS_FS_CSTOTAL_NBFREE_OFFSET, UFS_FS_CSTOTAL_NFFREE_OFFSET, UFS_FS_CSTOTAL_NIFREE_OFFSET,
    UFS_IFBLK, UFS_IFCHR, UFS_IFDIR, UFS_IFLNK, UFS_IFMT, UFS_IFREG,
};
use svr4_disk::inspect::{get_vtoc_partition_by_selector, inspect_disk_image};
use svr4_disk::structures::SECTOR_SIZE;
use svr4_fs_core::MappedImage;
use svr4_ufs::alloc::recompute_summary_counts;
use svr4_ufs::{
    create_empty_in_parent, detect_ufs_at_start, iter_directory_entries, link_in_parent,
    lookup_directory_entry, mkdir_in_parent, mknod_in_parent, read_inode, read_inode_bytes,
    read_inode_range, read_symlink_target, rename_in_parent, rmdir_in_parent, set_inode_contents,
    set_inode_mode, set_inode_owner, set_inode_times, symlink_in_parent, truncate, unlink_in_parent,
    Inode, UfsDetector, Ufs,
};

const TTL: Duration = Duration::from_secs(1);
const UFS_IFIFO: u32 = 0o010000;
const UFS_IFSOCK: u32 = 0o140000;
const NAME_MAX: u32 = 255;

// ---------------------------------------------------------------------------
// FUSE <-> UFS inode-number mapping. FUSE reserves inode 1 for the root; SVR4
// UFS uses inode 2. Everything else is the identity.
// ---------------------------------------------------------------------------

fn fuse_to_ufs(n: i64) -> i64 {
    if n == 1 {
        2
    } else {
        n
    }
}

fn ufs_to_fuse(n: i64) -> i64 {
    if n == 2 {
        1
    } else {
        n
    }
}

// ---------------------------------------------------------------------------
// Time helpers. UFS stores 32-bit epoch seconds; FUSE deals in `SystemTime`.
// ---------------------------------------------------------------------------

fn now_secs() -> u32 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs() as u32)
        .unwrap_or(0)
}

fn to_systime(secs: u32) -> SystemTime {
    UNIX_EPOCH + Duration::from_secs(u64::from(secs))
}

fn systime_secs(t: SystemTime) -> u32 {
    t.duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs() as u32)
        .unwrap_or(0)
}

fn timeornow_secs(t: TimeOrNow) -> u32 {
    match t {
        TimeOrNow::SpecificTime(st) => systime_secs(st),
        TimeOrNow::Now => now_secs(),
    }
}

fn file_type_of(mode: u32) -> FileType {
    match mode & UFS_IFMT {
        UFS_IFDIR => FileType::Directory,
        UFS_IFREG => FileType::RegularFile,
        UFS_IFLNK => FileType::Symlink,
        UFS_IFCHR => FileType::CharDevice,
        UFS_IFBLK => FileType::BlockDevice,
        UFS_IFIFO => FileType::NamedPipe,
        UFS_IFSOCK => FileType::Socket,
        _ => FileType::RegularFile,
    }
}

/// Decode a Linux `dev_t` into (major, minor) per glibc's `gnu_dev_*`. Mirrors
/// `svr4-ufs-populate`'s `split_rdev` so device nodes created over the mount land
/// with the same major/minor a direct populate would have produced.
fn split_rdev(rdev: u32) -> (u32, u32) {
    let rdev = u64::from(rdev);
    let major = (((rdev >> 8) & 0xfff) | ((rdev >> 32) & !0xfff)) as u32;
    let minor = ((rdev & 0xff) | ((rdev >> 12) & !0xff)) as u32;
    (major, minor)
}

fn make_attr(inode: &Inode, ufs_ino: i64, size: u64, blksize: u32) -> FileAttr {
    FileAttr {
        ino: INodeNo(ufs_to_fuse(ufs_ino) as u64),
        size,
        blocks: size.div_ceil(512),
        atime: to_systime(inode.atime),
        mtime: to_systime(inode.mtime),
        ctime: to_systime(inode.ctime),
        crtime: to_systime(inode.ctime),
        kind: file_type_of(inode.mode),
        perm: (inode.mode & 0o7777) as u16,
        nlink: u32::from(inode.nlink),
        uid: inode.uid,
        gid: inode.gid,
        rdev: 0,
        blksize,
        flags: 0,
    }
}

/// Map a write-path error string to the closest errno. The write path returns
/// human-readable `String`s; we sniff a few well-known shapes and fall back to
/// `EIO`.
fn errno_from(message: &str) -> Errno {
    let m = message.to_ascii_lowercase();
    if m.contains("does not exist") || m.contains("unreadable") {
        Errno::ENOENT
    } else if m.contains("not empty") {
        Errno::ENOTEMPTY
    } else if m.contains("already exists") || m.contains("exists") {
        Errno::EEXIST
    } else if m.contains("not a") && m.contains("directory") {
        Errno::ENOTDIR
    } else if m.contains("is a directory") {
        Errno::EISDIR
    } else if m.contains("no space") || m.contains("full") {
        Errno::ENOSPC
    } else {
        Errno::EIO
    }
}

// ---------------------------------------------------------------------------
// Daemon state.
// ---------------------------------------------------------------------------

/// An in-progress file body. Loaded lazily from disk on the first write and
/// committed back via [`set_inode_contents`] on flush/fsync/release.
struct FileBuf {
    data: Vec<u8>,
    dirty: bool,
}

struct State {
    img: MappedImage,
    ufs: Ufs,
    read_only: bool,
    next_fh: u64,
    /// Open file handles → the UFS inode they refer to.
    handles: HashMap<u64, i64>,
    /// UFS inode → buffered body (present only while a file is being read/written).
    buffers: HashMap<i64, FileBuf>,
}

impl State {
    /// Build a `FileAttr` for a UFS inode, reflecting any buffered (uncommitted)
    /// size.
    fn attr_for(&self, ufs_ino: i64) -> Option<FileAttr> {
        let inode = read_inode(self.img.as_slice(), &self.ufs, ufs_ino)?;
        let size = self
            .buffers
            .get(&ufs_ino)
            .map(|b| b.data.len() as u64)
            .unwrap_or(inode.size);
        Some(make_attr(&inode, ufs_ino, size, self.ufs.sb.bsize as u32))
    }

    /// Ensure a buffer exists for `ufs_ino`, loading the current on-disk body.
    fn ensure_buffer(&mut self, ufs_ino: i64) {
        if self.buffers.contains_key(&ufs_ino) {
            return;
        }
        let data = read_inode(self.img.as_slice(), &self.ufs, ufs_ino)
            .map(|i| read_inode_bytes(self.img.as_slice(), &self.ufs, &i))
            .unwrap_or_default();
        self.buffers.insert(ufs_ino, FileBuf { data, dirty: false });
    }

    /// Write a dirty buffer back to disk (whole-file replacement), then mark it
    /// clean. No-op if there is no dirty buffer.
    fn commit(&mut self, ufs_ino: i64) -> Result<(), String> {
        let data = match self.buffers.get(&ufs_ino) {
            Some(b) if b.dirty => b.data.clone(),
            _ => return Ok(()),
        };
        let ufs = self.ufs.clone();
        set_inode_contents(self.img.as_mut_slice(), &ufs, ufs_ino, &data)?;
        let now = now_secs();
        set_inode_times(self.img.as_mut_slice(), &ufs, ufs_ino, None, Some(now), Some(now));
        if let Some(b) = self.buffers.get_mut(&ufs_ino) {
            b.dirty = false;
        }
        Ok(())
    }
}

struct UfsFs {
    state: Mutex<State>,
}

impl UfsFs {
    fn new(img: MappedImage, ufs: Ufs, read_only: bool) -> Self {
        UfsFs {
            state: Mutex::new(State {
                img,
                ufs,
                read_only,
                next_fh: 1,
                handles: HashMap::new(),
                buffers: HashMap::new(),
            }),
        }
    }
}

/// Pull the `&str` out of an `OsStr`, replying `EINVAL` on non-UTF-8 names. SVR4
/// directory entries are byte strings, but the populate workflow only ever uses
/// UTF-8 names, and the reader/writer here work in `&str`.
macro_rules! name_str {
    ($name:expr, $reply:expr) => {
        match $name.to_str() {
            Some(s) => s,
            None => {
                $reply.error(Errno::EINVAL);
                return;
            }
        }
    };
}

impl Filesystem for UfsFs {
    fn lookup(&self, _req: &Request, parent: INodeNo, name: &OsStr, reply: ReplyEntry) {
        let name = name_str!(name, reply);
        let st = self.state.lock().unwrap();
        let pino = fuse_to_ufs(parent.0 as i64);
        let Some(parent_inode) = read_inode(st.img.as_slice(), &st.ufs, pino) else {
            reply.error(Errno::ENOENT);
            return;
        };
        match lookup_directory_entry(st.img.as_slice(), &st.ufs, &parent_inode, name) {
            Some((child_number, _)) => match st.attr_for(child_number as i64) {
                Some(attr) => reply.entry(&TTL, &attr, Generation(0)),
                None => reply.error(Errno::ENOENT),
            },
            None => reply.error(Errno::ENOENT),
        }
    }

    fn getattr(&self, _req: &Request, ino: INodeNo, _fh: Option<FileHandle>, reply: ReplyAttr) {
        let st = self.state.lock().unwrap();
        match st.attr_for(fuse_to_ufs(ino.0 as i64)) {
            Some(attr) => reply.attr(&TTL, &attr),
            None => reply.error(Errno::ENOENT),
        }
    }

    /// Permission check. SVR4 UFS here is a build/populate mount with no ACL
    /// enforcement of its own, so we only confirm the inode exists and let the
    /// caller proceed. Implementing this stops the kernel/rsync from logging the
    /// op as unsupported.
    fn access(&self, _req: &Request, ino: INodeNo, _mask: AccessFlags, reply: ReplyEmpty) {
        let st = self.state.lock().unwrap();
        match read_inode(st.img.as_slice(), &st.ufs, fuse_to_ufs(ino.0 as i64)) {
            Some(_) => reply.ok(),
            None => reply.error(Errno::ENOENT),
        }
    }

    /// Extended attributes are not stored, so every attribute is absent. Reply
    /// `ENODATA` (the "no such attribute" answer) rather than the default
    /// `ENOSYS`: ENOSYS makes the kernel disable xattrs mount-wide, but rsync's
    /// `security.capability` probe expects a clean per-name miss, and ENODATA
    /// keeps the log quiet without that side effect.
    fn getxattr(
        &self,
        _req: &Request,
        _ino: INodeNo,
        _name: &OsStr,
        _size: u32,
        reply: ReplyXattr,
    ) {
        reply.error(Errno::ENODATA);
    }

    /// No xattrs are stored, so the name list is empty (size 0).
    fn listxattr(&self, _req: &Request, _ino: INodeNo, size: u32, reply: ReplyXattr) {
        if size == 0 {
            reply.size(0);
        } else {
            reply.data(&[]);
        }
    }

    #[allow(clippy::too_many_arguments)]
    fn setattr(
        &self,
        _req: &Request,
        ino: INodeNo,
        mode: Option<u32>,
        uid: Option<u32>,
        gid: Option<u32>,
        size: Option<u64>,
        atime: Option<TimeOrNow>,
        mtime: Option<TimeOrNow>,
        ctime: Option<SystemTime>,
        _fh: Option<FileHandle>,
        _crtime: Option<SystemTime>,
        _chgtime: Option<SystemTime>,
        _bkuptime: Option<SystemTime>,
        _flags: Option<BsdFileFlags>,
        reply: ReplyAttr,
    ) {
        let mut st = self.state.lock().unwrap();
        if st.read_only {
            reply.error(Errno::EROFS);
            return;
        }
        let uino = fuse_to_ufs(ino.0 as i64);
        let ufs = st.ufs.clone();

        if let Some(sz) = size {
            if st.buffers.contains_key(&uino) {
                let b = st.buffers.get_mut(&uino).unwrap();
                b.data.resize(sz as usize, 0);
                b.dirty = true;
            } else if let Err(e) = truncate(st.img.as_mut_slice(), &ufs, uino, sz) {
                reply.error(errno_from(&e));
                return;
            }
        }

        if let Some(m) = mode {
            if let Some(cur) = read_inode(st.img.as_slice(), &ufs, uino) {
                let new_mode = (cur.mode & UFS_IFMT) | (m & !UFS_IFMT);
                set_inode_mode(st.img.as_mut_slice(), &ufs, uino, new_mode);
            }
        }

        if uid.is_some() || gid.is_some() {
            if let Some(cur) = read_inode(st.img.as_slice(), &ufs, uino) {
                let nu = uid.unwrap_or(cur.uid);
                let ng = gid.unwrap_or(cur.gid);
                set_inode_owner(st.img.as_mut_slice(), &ufs, uino, nu, ng);
            }
        }

        let a = atime.map(timeornow_secs);
        let m = mtime.map(timeornow_secs);
        let c = ctime.map(systime_secs);
        if a.is_some() || m.is_some() || c.is_some() {
            set_inode_times(st.img.as_mut_slice(), &ufs, uino, a, m, c);
        }

        match st.attr_for(uino) {
            Some(attr) => reply.attr(&TTL, &attr),
            None => reply.error(Errno::ENOENT),
        }
    }

    fn readlink(&self, _req: &Request, ino: INodeNo, reply: ReplyData) {
        let st = self.state.lock().unwrap();
        let uino = fuse_to_ufs(ino.0 as i64);
        match read_inode(st.img.as_slice(), &st.ufs, uino) {
            Some(inode) if inode.is_symlink() => {
                let target = read_symlink_target(st.img.as_slice(), &st.ufs, &inode);
                reply.data(target.as_bytes());
            }
            Some(_) => reply.error(Errno::EINVAL),
            None => reply.error(Errno::ENOENT),
        }
    }

    fn mkdir(
        &self,
        req: &Request,
        parent: INodeNo,
        name: &OsStr,
        mode: u32,
        umask: u32,
        reply: ReplyEntry,
    ) {
        let name = name_str!(name, reply);
        let mut st = self.state.lock().unwrap();
        if st.read_only {
            reply.error(Errno::EROFS);
            return;
        }
        let pino = fuse_to_ufs(parent.0 as i64);
        let ufs = st.ufs.clone();
        let eff_mode = mode & !umask;
        match mkdir_in_parent(
            st.img.as_mut_slice(),
            &ufs,
            pino,
            name,
            eff_mode,
            req.uid(),
            req.gid(),
            now_secs(),
        ) {
            Ok(new) => match st.attr_for(new) {
                Some(attr) => reply.entry(&TTL, &attr, Generation(0)),
                None => reply.error(Errno::EIO),
            },
            Err(e) => reply.error(errno_from(&e)),
        }
    }

    fn mknod(
        &self,
        req: &Request,
        parent: INodeNo,
        name: &OsStr,
        mode: u32,
        umask: u32,
        rdev: u32,
        reply: ReplyEntry,
    ) {
        let name = name_str!(name, reply);
        let mut st = self.state.lock().unwrap();
        if st.read_only {
            reply.error(Errno::EROFS);
            return;
        }
        // Only char/block device nodes are supported (the UFS write path's
        // `mknod_in_parent` rejects anything else); FIFOs and sockets in a
        // populated tree are not needed for the system image.
        let kind = match mode & UFS_IFMT {
            UFS_IFCHR => UFS_IFCHR,
            UFS_IFBLK => UFS_IFBLK,
            _ => {
                reply.error(Errno::EINVAL);
                return;
            }
        };
        let (major, minor) = split_rdev(rdev);
        let pino = fuse_to_ufs(parent.0 as i64);
        let ufs = st.ufs.clone();
        let eff_mode = mode & !umask & 0o7777;
        match mknod_in_parent(
            st.img.as_mut_slice(),
            &ufs,
            pino,
            name,
            kind,
            major,
            minor,
            eff_mode,
            req.uid(),
            req.gid(),
            now_secs(),
        ) {
            Ok(new) => match st.attr_for(new) {
                Some(attr) => reply.entry(&TTL, &attr, Generation(0)),
                None => reply.error(Errno::EIO),
            },
            Err(e) => reply.error(errno_from(&e)),
        }
    }

    fn unlink(&self, _req: &Request, parent: INodeNo, name: &OsStr, reply: ReplyEmpty) {
        let name = name_str!(name, reply);
        let mut st = self.state.lock().unwrap();
        if st.read_only {
            reply.error(Errno::EROFS);
            return;
        }
        let pino = fuse_to_ufs(parent.0 as i64);
        let ufs = st.ufs.clone();
        match unlink_in_parent(st.img.as_mut_slice(), &ufs, pino, name) {
            Ok(_) => reply.ok(),
            Err(e) => reply.error(errno_from(&e)),
        }
    }

    fn rmdir(&self, _req: &Request, parent: INodeNo, name: &OsStr, reply: ReplyEmpty) {
        let name = name_str!(name, reply);
        let mut st = self.state.lock().unwrap();
        if st.read_only {
            reply.error(Errno::EROFS);
            return;
        }
        let pino = fuse_to_ufs(parent.0 as i64);
        let ufs = st.ufs.clone();
        match rmdir_in_parent(st.img.as_mut_slice(), &ufs, pino, name) {
            Ok(_) => reply.ok(),
            Err(e) => reply.error(errno_from(&e)),
        }
    }

    fn symlink(
        &self,
        req: &Request,
        parent: INodeNo,
        link_name: &OsStr,
        target: &Path,
        reply: ReplyEntry,
    ) {
        let link_name = name_str!(link_name, reply);
        let Some(target) = target.to_str() else {
            reply.error(Errno::EINVAL);
            return;
        };
        let mut st = self.state.lock().unwrap();
        if st.read_only {
            reply.error(Errno::EROFS);
            return;
        }
        let pino = fuse_to_ufs(parent.0 as i64);
        let ufs = st.ufs.clone();
        match symlink_in_parent(
            st.img.as_mut_slice(),
            &ufs,
            pino,
            link_name,
            target,
            0o777,
            req.uid(),
            req.gid(),
            now_secs(),
        ) {
            Ok(new) => match st.attr_for(new) {
                Some(attr) => reply.entry(&TTL, &attr, Generation(0)),
                None => reply.error(Errno::EIO),
            },
            Err(e) => reply.error(errno_from(&e)),
        }
    }

    fn rename(
        &self,
        _req: &Request,
        parent: INodeNo,
        name: &OsStr,
        newparent: INodeNo,
        newname: &OsStr,
        _flags: RenameFlags,
        reply: ReplyEmpty,
    ) {
        let name = name_str!(name, reply);
        let newname = name_str!(newname, reply);
        let mut st = self.state.lock().unwrap();
        if st.read_only {
            reply.error(Errno::EROFS);
            return;
        }
        let sp = fuse_to_ufs(parent.0 as i64);
        let dp = fuse_to_ufs(newparent.0 as i64);
        let ufs = st.ufs.clone();
        match rename_in_parent(st.img.as_mut_slice(), &ufs, sp, name, dp, newname) {
            Ok(()) => reply.ok(),
            Err(e) => reply.error(errno_from(&e)),
        }
    }

    fn link(
        &self,
        _req: &Request,
        ino: INodeNo,
        newparent: INodeNo,
        newname: &OsStr,
        reply: ReplyEntry,
    ) {
        let newname = name_str!(newname, reply);
        let mut st = self.state.lock().unwrap();
        if st.read_only {
            reply.error(Errno::EROFS);
            return;
        }
        let target = fuse_to_ufs(ino.0 as i64);
        let np = fuse_to_ufs(newparent.0 as i64);
        let ufs = st.ufs.clone();
        match link_in_parent(st.img.as_mut_slice(), &ufs, np, newname, target) {
            Ok(()) => match st.attr_for(target) {
                Some(attr) => reply.entry(&TTL, &attr, Generation(0)),
                None => reply.error(Errno::EIO),
            },
            Err(e) => reply.error(errno_from(&e)),
        }
    }

    fn create(
        &self,
        req: &Request,
        parent: INodeNo,
        name: &OsStr,
        mode: u32,
        umask: u32,
        _flags: i32,
        reply: ReplyCreate,
    ) {
        let name = name_str!(name, reply);
        let mut st = self.state.lock().unwrap();
        if st.read_only {
            reply.error(Errno::EROFS);
            return;
        }
        let pino = fuse_to_ufs(parent.0 as i64);
        let ufs = st.ufs.clone();
        let eff_mode = mode & !umask;
        let new = match create_empty_in_parent(
            st.img.as_mut_slice(),
            &ufs,
            pino,
            name,
            eff_mode,
            req.uid(),
            req.gid(),
            now_secs(),
        ) {
            Ok(n) => n,
            Err(e) => {
                reply.error(errno_from(&e));
                return;
            }
        };
        // Start an empty (clean) buffer so subsequent writes splice into it.
        st.buffers.insert(new, FileBuf { data: Vec::new(), dirty: false });
        let fh = st.next_fh;
        st.next_fh += 1;
        st.handles.insert(fh, new);
        match st.attr_for(new) {
            Some(attr) => {
                reply.created(&TTL, &attr, Generation(0), FileHandle(fh), FopenFlags::empty())
            }
            None => reply.error(Errno::EIO),
        }
    }

    fn open(&self, _req: &Request, ino: INodeNo, _flags: OpenFlags, reply: ReplyOpen) {
        let mut st = self.state.lock().unwrap();
        let uino = fuse_to_ufs(ino.0 as i64);
        let fh = st.next_fh;
        st.next_fh += 1;
        st.handles.insert(fh, uino);
        reply.opened(FileHandle(fh), FopenFlags::empty());
    }

    #[allow(clippy::too_many_arguments)]
    fn read(
        &self,
        _req: &Request,
        ino: INodeNo,
        _fh: FileHandle,
        offset: u64,
        size: u32,
        _flags: OpenFlags,
        _lock_owner: Option<LockOwner>,
        reply: ReplyData,
    ) {
        let st = self.state.lock().unwrap();
        let uino = fuse_to_ufs(ino.0 as i64);
        let offset = offset as usize;
        let size = size as usize;
        if let Some(b) = st.buffers.get(&uino) {
            let start = offset.min(b.data.len());
            let end = (start + size).min(b.data.len());
            reply.data(&b.data[start..end]);
            return;
        }
        match read_inode(st.img.as_slice(), &st.ufs, uino) {
            Some(inode) => {
                let data = read_inode_range(st.img.as_slice(), &st.ufs, &inode, offset, size);
                reply.data(&data);
            }
            None => reply.error(Errno::ENOENT),
        }
    }

    #[allow(clippy::too_many_arguments)]
    fn write(
        &self,
        _req: &Request,
        ino: INodeNo,
        _fh: FileHandle,
        offset: u64,
        data: &[u8],
        _write_flags: WriteFlags,
        _flags: OpenFlags,
        _lock_owner: Option<LockOwner>,
        reply: ReplyWrite,
    ) {
        let mut st = self.state.lock().unwrap();
        if st.read_only {
            reply.error(Errno::EROFS);
            return;
        }
        let uino = fuse_to_ufs(ino.0 as i64);
        st.ensure_buffer(uino);
        let off = offset as usize;
        let b = st.buffers.get_mut(&uino).unwrap();
        let end = off + data.len();
        if end > b.data.len() {
            b.data.resize(end, 0);
        }
        b.data[off..end].copy_from_slice(data);
        b.dirty = true;
        reply.written(data.len() as u32);
    }

    fn flush(
        &self,
        _req: &Request,
        ino: INodeNo,
        _fh: FileHandle,
        _lock_owner: LockOwner,
        reply: ReplyEmpty,
    ) {
        let mut st = self.state.lock().unwrap();
        let uino = fuse_to_ufs(ino.0 as i64);
        match st.commit(uino) {
            Ok(()) => reply.ok(),
            Err(e) => reply.error(errno_from(&e)),
        }
    }

    fn fsync(
        &self,
        _req: &Request,
        ino: INodeNo,
        _fh: FileHandle,
        _datasync: bool,
        reply: ReplyEmpty,
    ) {
        let mut st = self.state.lock().unwrap();
        let uino = fuse_to_ufs(ino.0 as i64);
        if let Err(e) = st.commit(uino) {
            reply.error(errno_from(&e));
            return;
        }
        match st.img.flush() {
            Ok(()) => reply.ok(),
            Err(_) => reply.error(Errno::EIO),
        }
    }

    fn release(
        &self,
        _req: &Request,
        ino: INodeNo,
        fh: FileHandle,
        _flags: OpenFlags,
        _lock_owner: Option<LockOwner>,
        _flush: bool,
        reply: ReplyEmpty,
    ) {
        let mut st = self.state.lock().unwrap();
        let uino = fuse_to_ufs(ino.0 as i64);
        if let Err(e) = st.commit(uino) {
            reply.error(errno_from(&e));
            return;
        }
        st.handles.remove(&fh.0);
        // Drop the buffer once no open handle references the inode anymore.
        if !st.handles.values().any(|&v| v == uino) {
            st.buffers.remove(&uino);
        }
        reply.ok();
    }

    fn readdir(
        &self,
        _req: &Request,
        ino: INodeNo,
        _fh: FileHandle,
        offset: u64,
        mut reply: ReplyDirectory,
    ) {
        let st = self.state.lock().unwrap();
        let uino = fuse_to_ufs(ino.0 as i64);
        let Some(inode) = read_inode(st.img.as_slice(), &st.ufs, uino) else {
            reply.error(Errno::ENOENT);
            return;
        };
        if !inode.is_directory() {
            reply.error(Errno::ENOTDIR);
            return;
        }
        let entries = iter_directory_entries(st.img.as_slice(), &st.ufs, &inode);
        for (index, entry) in entries.iter().enumerate().skip(offset as usize) {
            let kind = read_inode(st.img.as_slice(), &st.ufs, entry.inode as i64)
                .map(|child| file_type_of(child.mode))
                .unwrap_or(FileType::RegularFile);
            let fuse_ino = INodeNo(ufs_to_fuse(entry.inode as i64) as u64);
            if reply.add(fuse_ino, (index + 1) as u64, kind, &entry.name) {
                break;
            }
        }
        reply.ok();
    }

    fn statfs(&self, _req: &Request, _ino: INodeNo, reply: ReplyStatfs) {
        let st = self.state.lock().unwrap();
        let sb = &st.ufs.sb;
        let so = st.ufs.super_offset as usize;
        let img = st.img.as_slice();
        let nbfree = i64::from(svr4_fs_core::codec::i32(img, so + UFS_FS_CSTOTAL_NBFREE_OFFSET));
        let nifree = i64::from(svr4_fs_core::codec::i32(img, so + UFS_FS_CSTOTAL_NIFREE_OFFSET));
        let nffree = i64::from(svr4_fs_core::codec::i32(img, so + UFS_FS_CSTOTAL_NFFREE_OFFSET));
        let free_frags = (nbfree * sb.frag + nffree).max(0) as u64;
        let total_frags = sb.dsize.max(0) as u64;
        let total_inodes = (sb.ipg * sb.ncg).max(0) as u64;
        reply.statfs(
            total_frags,
            free_frags,
            free_frags,
            total_inodes,
            nifree.max(0) as u64,
            sb.bsize as u32,
            NAME_MAX,
            sb.fsize as u32,
        );
    }

    fn destroy(&mut self) {
        if let Ok(st) = self.state.get_mut() {
            if !st.read_only {
                let ufs = st.ufs.clone();
                if let Err(e) = recompute_summary_counts(st.img.as_mut_slice(), &ufs) {
                    log::error!("recompute_summary_counts failed on unmount: {e}");
                }
            }
            if let Err(e) = st.img.flush() {
                log::error!("final msync failed on unmount: {e}");
            }
        }
    }
}

// ---------------------------------------------------------------------------
// CLI.
// ---------------------------------------------------------------------------

#[derive(Parser)]
#[command(
    about = "Mount an SVR4 UFS slice via FUSE (read/write)",
    long_about = "Mounts an SVR4 UFS filesystem image over FUSE. By default the UFS \
superblock is auto-detected; pass --offset to mount a slice at a known byte offset \
(e.g. a UFS partition inside a VTOC disk image)."
)]
struct Cli {
    /// Path to the UFS image (or disk image containing a UFS slice).
    image: PathBuf,
    /// Directory to mount on.
    mountpoint: PathBuf,
    /// Byte offset of the UFS slice within the image (default: auto-detect).
    #[arg(long, conflicts_with = "slice")]
    offset: Option<u64>,
    /// Slice to mount, by VTOC index or tag name (e.g. `1` or `root`). Resolved
    /// from the disk image's VTOC. Mutually exclusive with --offset.
    #[arg(long)]
    slice: Option<String>,
    /// Mount read-only.
    #[arg(long)]
    read_only: bool,
    /// Allow other users to access the mount (needs `user_allow_other` in
    /// /etc/fuse.conf).
    #[arg(long)]
    allow_other: bool,
    /// Unmount automatically if the daemon process exits (needs `allow_other`
    /// or `user_allow_other` in /etc/fuse.conf, per the FUSE kernel ABI).
    #[arg(long)]
    auto_unmount: bool,
}

/// Locate a UFS filesystem without scanning the whole image.
///
/// First tries a bare image (superblock at offset 0). Failing that, it parses
/// the disk metadata (MBR → pdinfo → VTOC) via the disk-image inspector — which
/// only reads the metadata sectors plus each slice's superblock/root pages — and
/// mounts the first slice the inspector identifies as UFS. This never faults in
/// the entire image the way a sector-by-sector superblock scan would.
fn autodetect_ufs(image_path: &Path, image: &[u8]) -> Option<Ufs> {
    if let Some(ufs) = detect_ufs_at_start(image, 0) {
        return Some(ufs);
    }
    let report = inspect_disk_image(image_path, &UfsDetector).ok()?;
    let slice = report
        .slice_filesystems
        .iter()
        .find(|s| s.filesystem.as_deref() == Some("ufs"))?;
    let absolute_offset =
        (slice.absolute_start_sector.max(0) as u64) * SECTOR_SIZE as u64 + slice.filesystem_offset;
    detect_ufs_at_start(image, absolute_offset)
}

/// Resolve a slice selector (VTOC index or tag name) to its UFS filesystem.
/// Reads only the disk metadata sectors plus the slice's superblock — never the
/// whole image.
fn resolve_slice_ufs(image_path: &Path, image: &[u8], selector: &str) -> Result<Ufs, String> {
    let report = inspect_disk_image(image_path, &UfsDetector)
        .map_err(|e| format!("error: cannot inspect {}: {e}", image_path.display()))?;
    let partition = get_vtoc_partition_by_selector(&report, selector)?;
    let offset = (partition.start_sector.max(0) as u64) * SECTOR_SIZE as u64;
    detect_ufs_at_start(image, offset).ok_or_else(|| {
        format!("error: slice '{selector}' (sector {}) does not contain a UFS filesystem", partition.start_sector)
    })
}

fn main() {
    env_logger::Builder::from_env(env_logger::Env::default().default_filter_or("info")).init();
    let cli = Cli::parse();

    let img = match MappedImage::open(&cli.image) {
        Ok(i) => i,
        Err(e) => {
            eprintln!("error: cannot open {}: {e}", cli.image.display());
            std::process::exit(1);
        }
    };

    let ufs = if let Some(offset) = cli.offset {
        match detect_ufs_at_start(img.as_slice(), offset) {
            Some(u) => u,
            None => {
                eprintln!("error: no UFS superblock at offset {offset}");
                std::process::exit(1);
            }
        }
    } else if let Some(selector) = &cli.slice {
        match resolve_slice_ufs(&cli.image, img.as_slice(), selector) {
            Ok(u) => u,
            Err(e) => {
                eprintln!("{e}");
                std::process::exit(1);
            }
        }
    } else {
        match autodetect_ufs(&cli.image, img.as_slice()) {
            Some(u) => u,
            None => {
                eprintln!(
                    "error: no UFS filesystem found in {} (try --offset or --slice)",
                    cli.image.display()
                );
                std::process::exit(1);
            }
        }
    };
    log::info!(
        "mounting UFS slice at byte offset {} on {}",
        ufs.start_offset,
        cli.mountpoint.display()
    );

    let mut options = vec![
        MountOption::FSName("svr4ufs".to_string()),
        MountOption::Subtype("svr4ufs".to_string()),
    ];
    if cli.auto_unmount {
        options.push(MountOption::AutoUnmount);
    }
    if cli.read_only {
        options.push(MountOption::RO);
    }

    let fs = UfsFs::new(img, ufs, cli.read_only);
    let mut config = Config::default();
    config.mount_options = options;
    // `allow_other` is expressed via the session ACL in fuser 0.17, not as a
    // mount option. It needs `user_allow_other` in /etc/fuse.conf to take effect.
    if cli.allow_other {
        config.acl = SessionACL::All;
    }

    if let Err(e) = fuser::mount2(fs, &cli.mountpoint, &config) {
        eprintln!("error: mount failed: {e}");
        std::process::exit(1);
    }
}
