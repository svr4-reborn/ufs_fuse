//! UFS superblock parsing, detection, and on-disk geometry arithmetic.
//!
//! Port of the superblock half of `host_tools/fs/ufs_lowlevel.py`
//! (`detect_ufs`, `detect_ufs_at_start`, and the `ufs_*` address macros). The
//! parsed [`Superblock`] is the typed equivalent of the Python `details` dict;
//! [`Ufs`] is the equivalent of a `FilesystemCandidate` for a UFS slice.
//!
//! All geometry math is done in `i64` to match Python's arbitrary-precision
//! semantics for the few expressions that can go through a negative
//! intermediate (notably `cg & ~cgmask`).

use svr4_fs_core::codec::{i32, u32};
use svr4_fs_core::consts::{
    SECTOR_SIZE, UFS_DINODE_SIZE, UFS_FS_BSIZE_OFFSET, UFS_FS_CBLKNO_OFFSET, UFS_FS_CGMASK_OFFSET,
    UFS_FS_CGOFFSET_OFFSET, UFS_FS_CPG_OFFSET, UFS_FS_CSADDR_OFFSET, UFS_FS_CSSIZE_OFFSET,
    UFS_FS_DBLKNO_OFFSET, UFS_FS_DSIZE_OFFSET, UFS_FS_FPG_OFFSET, UFS_FS_FRAGSHIFT_OFFSET,
    UFS_FS_FRAG_OFFSET, UFS_FS_FSBTODB_OFFSET, UFS_FS_FSIZE_OFFSET, UFS_FS_IBLKNO_OFFSET,
    UFS_FS_INOPB_OFFSET, UFS_FS_IPG_OFFSET, UFS_FS_MAGIC_OFFSET, UFS_FS_MINFREE_OFFSET,
    UFS_FS_NCG_OFFSET, UFS_FS_NCYL_OFFSET, UFS_FS_NINDIR_OFFSET, UFS_FS_NSECT_OFFSET,
    UFS_FS_NSPF_OFFSET, UFS_FS_SPC_OFFSET, UFS_MAGIC, UFS_NDADDR, UFS_SB_OFFSET, UFS_SB_SIZE,
};

/// Parsed UFS superblock fields (the Python `details` dict, typed). Every field
/// is held as `i64` so the address arithmetic mirrors Python exactly.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Superblock {
    pub bsize: i64,
    pub fsize: i64,
    pub frag: i64,
    pub dsize: i64,
    pub ipg: i64,
    pub fpg: i64,
    pub inopb: i64,
    pub fsbtodb: i64,
    pub cgoffset: i64,
    pub cgmask: i64,
    pub cblkno: i64,
    pub iblkno: i64,
    pub dblkno: i64,
    pub ncg: i64,
    pub minfree: i64,
    pub fragshift: i64,
    pub nindir: i64,
    pub nspf: i64,
    pub csaddr: i64,
    pub cssize: i64,
    pub nsect: i64,
    pub spc: i64,
    pub ncyl: i64,
    pub cpg: i64,
}

/// A detected UFS filesystem: where it lives plus its parsed superblock.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Ufs {
    pub start_offset: u64,
    pub super_offset: u64,
    pub sb: Superblock,
}

impl Superblock {
    /// Parse a superblock from the bytes at `super_offset`, applying the same
    /// sanity checks as the Python `detect_*` functions. Returns `None` if the
    /// magic or geometry is implausible.
    fn parse(image: &[u8], super_offset: usize) -> Option<Superblock> {
        if super_offset + UFS_SB_SIZE > image.len() {
            return None;
        }
        if u32(image, super_offset + UFS_FS_MAGIC_OFFSET) != UFS_MAGIC {
            return None;
        }
        let field = |off: usize| u32(image, super_offset + off) as i64;
        let bsize = field(UFS_FS_BSIZE_OFFSET);
        let fsize = field(UFS_FS_FSIZE_OFFSET);
        let inopb = field(UFS_FS_INOPB_OFFSET);
        let ipg = field(UFS_FS_IPG_OFFSET);
        let fpg = field(UFS_FS_FPG_OFFSET);
        if bsize < 4096 || bsize > UFS_SB_SIZE as i64 {
            return None;
        }
        if fsize < SECTOR_SIZE as i64 || fsize > bsize {
            return None;
        }
        if inopb == 0 || ipg == 0 || fpg == 0 {
            return None;
        }
        Some(Superblock {
            bsize,
            fsize,
            frag: field(UFS_FS_FRAG_OFFSET),
            dsize: field(UFS_FS_DSIZE_OFFSET),
            ipg,
            fpg,
            inopb,
            fsbtodb: field(UFS_FS_FSBTODB_OFFSET),
            cgoffset: field(UFS_FS_CGOFFSET_OFFSET),
            cgmask: field(UFS_FS_CGMASK_OFFSET),
            cblkno: field(UFS_FS_CBLKNO_OFFSET),
            iblkno: field(UFS_FS_IBLKNO_OFFSET),
            dblkno: field(UFS_FS_DBLKNO_OFFSET),
            ncg: field(UFS_FS_NCG_OFFSET),
            minfree: field(UFS_FS_MINFREE_OFFSET),
            fragshift: i32(image, super_offset + UFS_FS_FRAGSHIFT_OFFSET) as i64,
            nindir: field(UFS_FS_NINDIR_OFFSET),
            nspf: field(UFS_FS_NSPF_OFFSET),
            csaddr: field(UFS_FS_CSADDR_OFFSET),
            cssize: field(UFS_FS_CSSIZE_OFFSET),
            nsect: field(UFS_FS_NSECT_OFFSET),
            spc: field(UFS_FS_SPC_OFFSET),
            ncyl: field(UFS_FS_NCYL_OFFSET),
            cpg: field(UFS_FS_CPG_OFFSET),
        })
    }

    // --- on-disk address arithmetic (the ufs_* macros) --------------------

    #[inline]
    pub fn fsbtobytes(&self, fs_block: i64) -> i64 {
        (fs_block << self.fsbtodb) * SECTOR_SIZE as i64
    }

    #[inline]
    pub fn itoo(&self, inode_number: i64) -> i64 {
        inode_number % self.inopb
    }

    #[inline]
    pub fn itog(&self, inode_number: i64) -> i64 {
        inode_number / self.ipg
    }

    #[inline]
    pub fn blkstofrags(&self, blocks: i64) -> i64 {
        blocks << self.fragshift
    }

    #[inline]
    pub fn cgbase(&self, cg: i64) -> i64 {
        self.fpg * cg
    }

    #[inline]
    pub fn cgstart(&self, cg: i64) -> i64 {
        // `cg & ~cgmask` with Python's infinite-precision two's-complement
        // behaviour; i64 is wide enough for any real cg/cgmask pair.
        self.cgbase(cg) + self.cgoffset * (cg & !self.cgmask)
    }

    #[inline]
    pub fn cgimin(&self, cg: i64) -> i64 {
        self.cgstart(cg) + self.iblkno
    }

    #[inline]
    pub fn cgtod(&self, cg: i64) -> i64 {
        self.cgstart(cg) + self.cblkno
    }

    #[inline]
    pub fn cgdmin(&self, cg: i64) -> i64 {
        self.cgstart(cg) + self.dblkno
    }

    #[inline]
    pub fn itod(&self, inode_number: i64) -> i64 {
        let group = self.itog(inode_number);
        self.cgimin(group) + self.blkstofrags((inode_number % self.ipg) / self.inopb)
    }

    #[inline]
    pub fn inode_byte_offset(&self, fs_start: u64, inode_number: i64) -> i64 {
        let inode_block = self.itod(inode_number);
        fs_start as i64 + self.fsbtobytes(inode_block) + self.itoo(inode_number) * UFS_DINODE_SIZE as i64
    }

    #[inline]
    pub fn data_block_offset(&self, fs_start: u64, fs_block: i64) -> i64 {
        fs_start as i64 + self.fsbtobytes(fs_block)
    }

    /// `fragroundup`: round `size` up to a whole fragment.
    #[inline]
    pub fn fragroundup(&self, size: i64) -> i64 {
        if size <= 0 {
            return 0;
        }
        ((size + self.fsize - 1) / self.fsize) * self.fsize
    }

    /// Per-block on-disk allocation sizes for a file of `size` bytes — full
    /// blocks except a possibly fragmented tail. Port of
    /// `ufs_allocation_byte_sizes`.
    pub fn allocation_byte_sizes(&self, size: i64) -> Vec<i64> {
        if size <= 0 {
            return Vec::new();
        }
        let block_size = self.bsize;
        // Once an inode needs indirect blocks (> UFS_NDADDR blocks), UFS requires
        // every block — including the last — to be a full block; only inodes that
        // fit entirely in the direct blocks may have a fragment tail. Matching
        // this rule (as the Python writer and the kernel do) is essential: a
        // fragment tail on an indirect inode is what `fsck` flags.
        let needed_blocks = (size + block_size - 1) / block_size;
        let mut allocations = Vec::new();
        let mut remaining = size;
        while remaining > 0 {
            let logical_bytes = block_size.min(remaining);
            if logical_bytes == block_size || needed_blocks > UFS_NDADDR as i64 {
                allocations.push(block_size);
            } else {
                allocations.push(self.fragroundup(logical_bytes));
            }
            remaining -= block_size;
        }
        allocations
    }
}

/// Detect a UFS filesystem whose superblock is at `fs_start + UFS_SB_OFFSET`.
/// Port of `detect_ufs_at_start`.
pub fn detect_ufs_at_start(image: &[u8], fs_start: u64) -> Option<Ufs> {
    let super_offset = fs_start + UFS_SB_OFFSET;
    let sb = Superblock::parse(image, super_offset as usize)?;
    Some(Ufs {
        start_offset: fs_start,
        super_offset,
        sb,
    })
}

// NOTE: the Python tools had a `detect_ufs` that brute-force scanned every
// sector of the image for a superblock. That is deliberately *not* ported: on a
// large (LBA28, tens-of-GB) disk image it would fault in the entire file. Slices
// are located structurally instead — through the VTOC (see the `svr4-disk`
// inspect path) — and a known offset is mounted via [`detect_ufs_at_start`].

#[cfg(test)]
mod tests {
    use super::*;

    /// The synthetic geometry from the Python test suite's `build_test_filesystem`.
    fn sample_sb() -> Superblock {
        Superblock {
            bsize: 4096,
            fsize: 512,
            frag: 8,
            dsize: 0,
            ipg: 16,
            fpg: 128,
            inopb: 32,
            fsbtodb: 3,
            cgoffset: 0,
            cgmask: 0,
            cblkno: 1,
            iblkno: 2,
            dblkno: 3,
            ncg: 1,
            minfree: 0,
            fragshift: 3,
            nindir: 1024,
            nspf: 0,
            csaddr: 0,
            cssize: 0,
            nsect: 0,
            spc: 0,
            ncyl: 0,
            cpg: 0,
        }
    }

    #[test]
    fn geometry_matches_macros() {
        let sb = sample_sb();
        assert_eq!(sb.itog(2), 0);
        assert_eq!(sb.itoo(2), 2);
        assert_eq!(sb.cgimin(0), 2);
        assert_eq!(sb.itod(2), 2);
        // inode byte offset = fsbtobytes(2) + itoo(2)*128 = 8192 + 256.
        assert_eq!(sb.inode_byte_offset(0, 2), 8448);
        // data block 3 -> (3 << fsbtodb) * 512 = 12288.
        assert_eq!(sb.data_block_offset(0, 3), 12288);
    }

    #[test]
    fn allocation_byte_sizes_fragment_tail() {
        let sb = sample_sb();
        // One full 4096 block plus a 1500-byte tail rounded up to fragments.
        assert_eq!(sb.allocation_byte_sizes(0), Vec::<i64>::new());
        assert_eq!(sb.allocation_byte_sizes(4096), vec![4096]);
        assert_eq!(sb.allocation_byte_sizes(4096 + 1500), vec![4096, 1536]);
    }

    #[test]
    fn cgmask_uses_python_twos_complement() {
        // cgmask = 0xFFFFFFE0 -> ~cgmask = -(0xFFFFFFE0 + 1); cg & that should
        // mask the low 5 bits, matching Python's infinite-precision result.
        let mut sb = sample_sb();
        sb.cgmask = 0xFFFF_FFE0;
        sb.cgoffset = 1;
        // For cg = 3: 3 & ~0xFFFFFFE0 == 3, so cgstart = fpg*3 + 1*3.
        assert_eq!(sb.cgstart(3), sb.fpg * 3 + 3);
        // For cg = 33 (0x21): low 5 bits = 1, so the offset term is 1*1.
        assert_eq!(sb.cgstart(33), sb.fpg * 33 + 1);
    }
}
