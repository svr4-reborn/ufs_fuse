/*
 * Offset probe for the svr4-fs-core `layout_offsets` test.
 *
 * Compiled with `cc -m32` against the real UTS kernel headers (the on-disk
 * format is 32-bit, so `long`/`daddr_t`/`time_t` are 4 bytes) plus the compat
 * environment used by the original-ufs-fsck oracle. It prints `KEY=VALUE` lines;
 * the Rust test parses them and asserts each equals the corresponding constant
 * in `consts.rs`. This is the cheapest guard against a transcription mistake in
 * the hand-copied offset tables.
 *
 * Include order mirrors original-ufs-fsck/inode.c, which is known to compile in
 * this environment.
 */
#include <stdio.h>
#include <stddef.h>
#include <time.h>
#include <sys/param.h>
#include <sys/types.h>
#include <sys/sysmacros.h>
#include <sys/mntent.h>
#include <sys/fs/ufs_fs.h>
#include <sys/vnode.h>
#include <sys/fs/ufs_inode.h>
#include <sys/fs/ufs_fsdir.h>

#define EMIT(name, value) printf("%s=%ld\n", name, (long)(value))
/* Unsigned form for 32-bit magic words that set the high bit. */
#define EMITU(name, value) printf("%s=%lu\n", name, (unsigned long)(unsigned)(value))

int main(void)
{
    /* struct fs (superblock) */
    EMIT("UFS_FS_SBLKNO_OFFSET", offsetof(struct fs, fs_sblkno));
    EMIT("UFS_FS_CBLKNO_OFFSET", offsetof(struct fs, fs_cblkno));
    EMIT("UFS_FS_IBLKNO_OFFSET", offsetof(struct fs, fs_iblkno));
    EMIT("UFS_FS_DBLKNO_OFFSET", offsetof(struct fs, fs_dblkno));
    EMIT("UFS_FS_CGOFFSET_OFFSET", offsetof(struct fs, fs_cgoffset));
    EMIT("UFS_FS_CGMASK_OFFSET", offsetof(struct fs, fs_cgmask));
    EMIT("UFS_FS_TIME_OFFSET", offsetof(struct fs, fs_time));
    EMIT("UFS_FS_SIZE_OFFSET", offsetof(struct fs, fs_size));
    EMIT("UFS_FS_DSIZE_OFFSET", offsetof(struct fs, fs_dsize));
    EMIT("UFS_FS_NCG_OFFSET", offsetof(struct fs, fs_ncg));
    EMIT("UFS_FS_BSIZE_OFFSET", offsetof(struct fs, fs_bsize));
    EMIT("UFS_FS_FSIZE_OFFSET", offsetof(struct fs, fs_fsize));
    EMIT("UFS_FS_FRAG_OFFSET", offsetof(struct fs, fs_frag));
    EMIT("UFS_FS_MINFREE_OFFSET", offsetof(struct fs, fs_minfree));
    EMIT("UFS_FS_ROTDLY_OFFSET", offsetof(struct fs, fs_rotdelay));
    EMIT("UFS_FS_RPS_OFFSET", offsetof(struct fs, fs_rps));
    EMIT("UFS_FS_BMASK_OFFSET", offsetof(struct fs, fs_bmask));
    EMIT("UFS_FS_FMASK_OFFSET", offsetof(struct fs, fs_fmask));
    EMIT("UFS_FS_BSHIFT_OFFSET", offsetof(struct fs, fs_bshift));
    EMIT("UFS_FS_FSHIFT_OFFSET", offsetof(struct fs, fs_fshift));
    EMIT("UFS_FS_MAXCONTIG_OFFSET", offsetof(struct fs, fs_maxcontig));
    EMIT("UFS_FS_MAXBPG_OFFSET", offsetof(struct fs, fs_maxbpg));
    EMIT("UFS_FS_FRAGSHIFT_OFFSET", offsetof(struct fs, fs_fragshift));
    EMIT("UFS_FS_FSBTODB_OFFSET", offsetof(struct fs, fs_fsbtodb));
    EMIT("UFS_FS_SBSIZE_OFFSET", offsetof(struct fs, fs_sbsize));
    EMIT("UFS_FS_CSMASK_OFFSET", offsetof(struct fs, fs_csmask));
    EMIT("UFS_FS_CSSHIFT_OFFSET", offsetof(struct fs, fs_csshift));
    EMIT("UFS_FS_NINDIR_OFFSET", offsetof(struct fs, fs_nindir));
    EMIT("UFS_FS_INOPB_OFFSET", offsetof(struct fs, fs_inopb));
    EMIT("UFS_FS_NSPF_OFFSET", offsetof(struct fs, fs_nspf));
    EMIT("UFS_FS_OPTIM_OFFSET", offsetof(struct fs, fs_optim));
    EMIT("UFS_FS_STATE_OFFSET", offsetof(struct fs, fs_state));
    EMIT("UFS_FS_CSADDR_OFFSET", offsetof(struct fs, fs_csaddr));
    EMIT("UFS_FS_CSSIZE_OFFSET", offsetof(struct fs, fs_cssize));
    EMIT("UFS_FS_CGSIZE_OFFSET", offsetof(struct fs, fs_cgsize));
    EMIT("UFS_FS_NTRAK_OFFSET", offsetof(struct fs, fs_ntrak));
    EMIT("UFS_FS_NSECT_OFFSET", offsetof(struct fs, fs_nsect));
    EMIT("UFS_FS_SPC_OFFSET", offsetof(struct fs, fs_spc));
    EMIT("UFS_FS_NCYL_OFFSET", offsetof(struct fs, fs_ncyl));
    EMIT("UFS_FS_CPG_OFFSET", offsetof(struct fs, fs_cpg));
    EMIT("UFS_FS_IPG_OFFSET", offsetof(struct fs, fs_ipg));
    EMIT("UFS_FS_FPG_OFFSET", offsetof(struct fs, fs_fpg));
    EMIT("UFS_FS_CSTOTAL_NDIR_OFFSET", offsetof(struct fs, fs_cstotal.cs_ndir));
    EMIT("UFS_FS_CSTOTAL_NBFREE_OFFSET", offsetof(struct fs, fs_cstotal.cs_nbfree));
    EMIT("UFS_FS_CSTOTAL_NIFREE_OFFSET", offsetof(struct fs, fs_cstotal.cs_nifree));
    EMIT("UFS_FS_CSTOTAL_NFFREE_OFFSET", offsetof(struct fs, fs_cstotal.cs_nffree));
    EMIT("UFS_FS_FMOD_OFFSET", offsetof(struct fs, fs_fmod));
    EMIT("UFS_FS_CLEAN_OFFSET", offsetof(struct fs, fs_clean));
    EMIT("UFS_FS_RONLY_OFFSET", offsetof(struct fs, fs_ronly));
    EMIT("UFS_FS_MAGIC_OFFSET", offsetof(struct fs, fs_magic));

    /* struct cg (cylinder group) */
    EMIT("UFS_CG_TIME_OFFSET", offsetof(struct cg, cg_time));
    EMIT("UFS_CG_CGX_OFFSET", offsetof(struct cg, cg_cgx));
    EMIT("UFS_CG_NCYL_OFFSET", offsetof(struct cg, cg_ncyl));
    EMIT("UFS_CG_NIBLK_OFFSET", offsetof(struct cg, cg_niblk));
    EMIT("UFS_CG_NDBLK_OFFSET", offsetof(struct cg, cg_ndblk));
    EMIT("UFS_CG_CS_NDIR_OFFSET", offsetof(struct cg, cg_cs.cs_ndir));
    EMIT("UFS_CG_CS_NBFREE_OFFSET", offsetof(struct cg, cg_cs.cs_nbfree));
    EMIT("UFS_CG_CS_NIFREE_OFFSET", offsetof(struct cg, cg_cs.cs_nifree));
    EMIT("UFS_CG_CS_NFFREE_OFFSET", offsetof(struct cg, cg_cs.cs_nffree));
    EMIT("UFS_CG_ROTOR_OFFSET", offsetof(struct cg, cg_rotor));
    EMIT("UFS_CG_FROTOR_OFFSET", offsetof(struct cg, cg_frotor));
    EMIT("UFS_CG_IROTOR_OFFSET", offsetof(struct cg, cg_irotor));
    EMIT("UFS_CG_FRSUM_OFFSET", offsetof(struct cg, cg_frsum));
    EMIT("UFS_CG_BTOT_OFFSET", offsetof(struct cg, cg_btot));
    EMIT("UFS_CG_B_OFFSET", offsetof(struct cg, cg_b));
    EMIT("UFS_CG_IUSED_OFFSET", offsetof(struct cg, cg_iused));
    EMIT("UFS_CG_MAGIC_OFFSET", offsetof(struct cg, cg_magic));
    EMIT("UFS_CG_FREE_OFFSET", offsetof(struct cg, cg_free));

    /* struct icommon (on-disk inode) */
    EMIT("UFS_DI_SMODE_OFFSET", offsetof(struct icommon, ic_smode));
    EMIT("UFS_DI_NLINK_OFFSET", offsetof(struct icommon, ic_nlink));
    EMIT("UFS_DI_SUID_OFFSET", offsetof(struct icommon, ic_suid));
    EMIT("UFS_DI_SGID_OFFSET", offsetof(struct icommon, ic_sgid));
    EMIT("UFS_DI_SIZE_OFFSET", offsetof(struct icommon, ic_size));
    EMIT("UFS_DI_ATIME_OFFSET", offsetof(struct icommon, ic_atime));
    EMIT("UFS_DI_MTIME_OFFSET", offsetof(struct icommon, ic_mtime));
    EMIT("UFS_DI_CTIME_OFFSET", offsetof(struct icommon, ic_ctime));
    EMIT("UFS_DI_DB_OFFSET", offsetof(struct icommon, ic_db));
    EMIT("UFS_DI_IB_OFFSET", offsetof(struct icommon, ic_ib));
    EMIT("UFS_DI_FLAGS_OFFSET", offsetof(struct icommon, ic_flags));
    EMIT("UFS_DI_BLOCKS_OFFSET", offsetof(struct icommon, ic_blocks));
    EMIT("UFS_DI_GEN_OFFSET", offsetof(struct icommon, ic_gen));
    EMIT("UFS_DI_MODE_OFFSET", offsetof(struct icommon, ic_mode));
    EMIT("UFS_DI_UID_OFFSET", offsetof(struct icommon, ic_uid));
    EMIT("UFS_DI_GID_OFFSET", offsetof(struct icommon, ic_gid));
    EMIT("UFS_DI_EFTFLAG_OFFSET", offsetof(struct icommon, ic_eftflag));

    /* struct direct (directory entry) */
    EMIT("UFS_DIRENT_INO_OFFSET", offsetof(struct direct, d_ino));
    EMIT("UFS_DIRENT_RECLEN_OFFSET", offsetof(struct direct, d_reclen));
    EMIT("UFS_DIRENT_NAMLEN_OFFSET", offsetof(struct direct, d_namlen));
    EMIT("UFS_DIRENT_NAME_OFFSET", offsetof(struct direct, d_name));

    /* sizes and dimensioning constants */
    EMIT("UFS_DINODE_SIZE", sizeof(struct dinode));
    EMIT("UFS_CSUM_SIZE", sizeof(struct csum));
    EMIT("UFS_SB_SIZE", SBSIZE);
    EMIT("UFS_DIRBLKSIZ", DIRBLKSIZ);
    EMIT("UFS_NDADDR", NDADDR);
    EMIT("UFS_NIADDR", NIADDR);
    EMIT("NBBY", NBBY);
    EMIT("MAXFRAG", MAXFRAG);
    EMIT("MAXCPG", MAXCPG);
    EMIT("MAXIPG", MAXIPG);
    EMIT("NRPOS", NRPOS);

    /* magics */
    EMITU("UFS_MAGIC", FS_MAGIC);
    EMITU("UFS_CG_MAGIC", CG_MAGIC);
    EMITU("UFS_EFT_MAGIC", EFT_MAGIC);
    EMITU("UFS_FS_OKAY", FSOKAY);
    EMIT("UFS_ROOT_INODE", UFSROOTINO);
    EMIT("UFS_SB_OFFSET", (long)SBLOCK * DEV_BSIZE);

    return 0;
}
