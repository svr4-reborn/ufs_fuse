//! On-disk constants and structure field offsets for the SVR4 filesystems.
//!
//! These are transcribed verbatim from the Python host tools
//! (`host_tools/fs/common.py` and `host_tools/fs/ufs_lowlevel.py`), which are in
//! turn derived from the UTS kernel headers `uts/i386/sys/fs/ufs_fs.h`,
//! `ufs_inode.h`, and `ufs_fsdir.h`. The format is little-endian (AT386/x86) and
//! every `long`/`daddr_t`/`time_t` field is 4 bytes (ILP32).
//!
//! The `layout_offsets` integration test pins every `*_OFFSET` / `*_SIZE` here
//! against `offsetof`/`sizeof` of the real C structs compiled with `cc -m32`, so
//! a transcription mistake fails the build rather than silently corrupting an
//! image.

// ---------------------------------------------------------------------------
// Generic disk geometry
// ---------------------------------------------------------------------------
pub const SECTOR_SIZE: usize = 512;

// ---------------------------------------------------------------------------
// Magic numbers
// ---------------------------------------------------------------------------
pub const BFS_MAGIC: u32 = 0x1BAD_FACE;
pub const UFS_MAGIC: u32 = 0x0001_1954;
pub const UFS_CG_MAGIC: u32 = 0x0009_0255;
/// EFT (Extended Fundamental Types) cookie stored in `ic_eftflag`.
pub const UFS_EFT_MAGIC: u32 = 0x9090_9090;
/// `fs_state` value meaning "cleanly unmounted".
pub const UFS_FS_OKAY: u32 = 0x7C26_9D38;

// ---------------------------------------------------------------------------
// UFS fundamental layout
// ---------------------------------------------------------------------------
pub const UFS_ROOT_INODE: u32 = 2;
pub const UFS_SB_OFFSET: u64 = 8192;
pub const UFS_SB_SIZE: usize = 8192;
pub const UFS_DIRBLKSIZ: usize = 512;
pub const UFS_DINODE_SIZE: usize = 128;
pub const UFS_NDADDR: usize = 12;
pub const UFS_NIADDR: usize = 3;
pub const UFS_CSUM_SIZE: usize = 16;

// Cylinder-group dimensioning limits (`struct cg` array bounds).
pub const NBBY: usize = 8;
pub const MAXFRAG: usize = 8;
pub const MAXCPG: usize = 32;
pub const MAXIPG: usize = 2048;
pub const NRPOS: usize = 8;

// ---------------------------------------------------------------------------
// `struct fs` (superblock) field offsets, relative to the start of the struct.
// ---------------------------------------------------------------------------
pub const UFS_FS_SBLKNO_OFFSET: usize = 8;
pub const UFS_FS_CBLKNO_OFFSET: usize = 12;
pub const UFS_FS_IBLKNO_OFFSET: usize = 16;
pub const UFS_FS_DBLKNO_OFFSET: usize = 20;
pub const UFS_FS_CGOFFSET_OFFSET: usize = 24;
pub const UFS_FS_CGMASK_OFFSET: usize = 28;
pub const UFS_FS_TIME_OFFSET: usize = 32;
pub const UFS_FS_SIZE_OFFSET: usize = 36;
pub const UFS_FS_DSIZE_OFFSET: usize = 40;
pub const UFS_FS_NCG_OFFSET: usize = 44;
pub const UFS_FS_BSIZE_OFFSET: usize = 48;
pub const UFS_FS_FSIZE_OFFSET: usize = 52;
pub const UFS_FS_FRAG_OFFSET: usize = 56;
pub const UFS_FS_MINFREE_OFFSET: usize = 60;
pub const UFS_FS_ROTDLY_OFFSET: usize = 64;
pub const UFS_FS_RPS_OFFSET: usize = 68;
pub const UFS_FS_BMASK_OFFSET: usize = 72;
pub const UFS_FS_FMASK_OFFSET: usize = 76;
pub const UFS_FS_BSHIFT_OFFSET: usize = 80;
pub const UFS_FS_FSHIFT_OFFSET: usize = 84;
pub const UFS_FS_MAXCONTIG_OFFSET: usize = 88;
pub const UFS_FS_MAXBPG_OFFSET: usize = 92;
pub const UFS_FS_FRAGSHIFT_OFFSET: usize = 96;
pub const UFS_FS_FSBTODB_OFFSET: usize = 100;
pub const UFS_FS_SBSIZE_OFFSET: usize = 104;
pub const UFS_FS_CSMASK_OFFSET: usize = 108;
pub const UFS_FS_CSSHIFT_OFFSET: usize = 112;
pub const UFS_FS_NINDIR_OFFSET: usize = 116;
pub const UFS_FS_INOPB_OFFSET: usize = 120;
pub const UFS_FS_NSPF_OFFSET: usize = 124;
pub const UFS_FS_OPTIM_OFFSET: usize = 128;
pub const UFS_FS_STATE_OFFSET: usize = 132;
pub const UFS_FS_CSADDR_OFFSET: usize = 152;
pub const UFS_FS_CSSIZE_OFFSET: usize = 156;
pub const UFS_FS_CGSIZE_OFFSET: usize = 160;
pub const UFS_FS_NTRAK_OFFSET: usize = 164;
pub const UFS_FS_NSECT_OFFSET: usize = 168;
pub const UFS_FS_SPC_OFFSET: usize = 172;
pub const UFS_FS_NCYL_OFFSET: usize = 176;
pub const UFS_FS_CPG_OFFSET: usize = 180;
pub const UFS_FS_IPG_OFFSET: usize = 184;
pub const UFS_FS_FPG_OFFSET: usize = 188;
// `fs_cstotal` is a `struct csum` embedded at offset 192.
pub const UFS_FS_CSTOTAL_NDIR_OFFSET: usize = 192;
pub const UFS_FS_CSTOTAL_NBFREE_OFFSET: usize = 196;
pub const UFS_FS_CSTOTAL_NIFREE_OFFSET: usize = 200;
pub const UFS_FS_CSTOTAL_NFFREE_OFFSET: usize = 204;
pub const UFS_FS_FMOD_OFFSET: usize = 208;
pub const UFS_FS_CLEAN_OFFSET: usize = 209;
pub const UFS_FS_RONLY_OFFSET: usize = 210;
pub const UFS_FS_MAGIC_OFFSET: usize = 1372;

// ---------------------------------------------------------------------------
// `struct cg` (cylinder group) field offsets.
// ---------------------------------------------------------------------------
pub const UFS_CG_TIME_OFFSET: usize = 8;
pub const UFS_CG_CGX_OFFSET: usize = 12;
pub const UFS_CG_NCYL_OFFSET: usize = 16;
pub const UFS_CG_NIBLK_OFFSET: usize = 18;
pub const UFS_CG_NDBLK_OFFSET: usize = 20;
pub const UFS_CG_CS_NDIR_OFFSET: usize = 24;
pub const UFS_CG_CS_NBFREE_OFFSET: usize = 28;
pub const UFS_CG_CS_NIFREE_OFFSET: usize = 32;
pub const UFS_CG_CS_NFFREE_OFFSET: usize = 36;
pub const UFS_CG_ROTOR_OFFSET: usize = 40;
pub const UFS_CG_FROTOR_OFFSET: usize = 44;
pub const UFS_CG_IROTOR_OFFSET: usize = 48;
pub const UFS_CG_FRSUM_OFFSET: usize = 52;
pub const UFS_CG_BTOT_OFFSET: usize = UFS_CG_FRSUM_OFFSET + MAXFRAG * 4;
pub const UFS_CG_B_OFFSET: usize = UFS_CG_BTOT_OFFSET + MAXCPG * 4;
pub const UFS_CG_MAGIC_OFFSET: usize = 980;
pub const UFS_CG_IUSED_OFFSET: usize = UFS_CG_MAGIC_OFFSET - MAXIPG / NBBY;
pub const UFS_CG_FREE_OFFSET: usize = UFS_CG_MAGIC_OFFSET + 4;

// ---------------------------------------------------------------------------
// `struct icommon` (on-disk inode) field offsets.
// ---------------------------------------------------------------------------
pub const UFS_DI_SMODE_OFFSET: usize = 0;
pub const UFS_DI_NLINK_OFFSET: usize = 2;
pub const UFS_DI_SUID_OFFSET: usize = 4;
pub const UFS_DI_SGID_OFFSET: usize = 6;
pub const UFS_DI_SIZE_OFFSET: usize = 8;
pub const UFS_DI_ATIME_OFFSET: usize = 16;
pub const UFS_DI_MTIME_OFFSET: usize = 24;
pub const UFS_DI_CTIME_OFFSET: usize = 32;
pub const UFS_DI_DB_OFFSET: usize = 40;
pub const UFS_DI_IB_OFFSET: usize = 88;
pub const UFS_DI_FLAGS_OFFSET: usize = 100;
pub const UFS_DI_BLOCKS_OFFSET: usize = 104;
pub const UFS_DI_GEN_OFFSET: usize = 108;
pub const UFS_DI_MODE_OFFSET: usize = 112;
pub const UFS_DI_UID_OFFSET: usize = 116;
pub const UFS_DI_GID_OFFSET: usize = 120;
pub const UFS_DI_EFTFLAG_OFFSET: usize = 124;

// ---------------------------------------------------------------------------
// `struct direct` (directory entry) field offsets and the fixed header size.
// ---------------------------------------------------------------------------
pub const UFS_DIRENT_INO_OFFSET: usize = 0;
pub const UFS_DIRENT_RECLEN_OFFSET: usize = 4;
pub const UFS_DIRENT_NAMLEN_OFFSET: usize = 6;
pub const UFS_DIRENT_NAME_OFFSET: usize = 8;
pub const UFS_DIRENT_HEADER_SIZE: usize = 8;

// ---------------------------------------------------------------------------
// Inode mode bits (UFS_IF*) — octal in the C headers.
// ---------------------------------------------------------------------------
pub const UFS_IFMT: u32 = 0o170000;
pub const UFS_IFCHR: u32 = 0o020000;
pub const UFS_IFDIR: u32 = 0o040000;
pub const UFS_IFBLK: u32 = 0o060000;
pub const UFS_IFREG: u32 = 0o100000;
pub const UFS_IFLNK: u32 = 0o120000;

/// Minimum directory entry record length needed to hold `name`.
///
/// Mirrors `ufs_dirsiz` in `host_tools/fs/ufs_directory.py`: the 8-byte header
/// plus the name rounded up to a 4-byte boundary (including the NUL).
#[inline]
pub fn ufs_dirsiz(name_len: usize) -> usize {
    UFS_DIRENT_HEADER_SIZE + ((name_len + 1 + 3) & !3)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn cg_derived_offsets_match_python() {
        // Values from ufs_lowlevel.py after expanding the arithmetic.
        assert_eq!(UFS_CG_BTOT_OFFSET, 84);
        assert_eq!(UFS_CG_B_OFFSET, 212);
        assert_eq!(UFS_CG_IUSED_OFFSET, 724);
        assert_eq!(UFS_CG_FREE_OFFSET, 984);
    }

    #[test]
    fn dirsiz_rounds_to_four() {
        assert_eq!(ufs_dirsiz(1), 12); // "." -> 8 + roundup(2,4)=4
        assert_eq!(ufs_dirsiz(2), 12); // ".."
        assert_eq!(ufs_dirsiz(3), 12); // "foo" -> 8 + roundup(4,4)=4
        assert_eq!(ufs_dirsiz(4), 16); // "test" -> 8 + roundup(5,4)=8
    }
}
