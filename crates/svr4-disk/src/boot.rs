//! Bootloader install. Port of `tasks/make_image.py:_build_hdboot_partition_bootstrap`.
//!
//! Making an SVR4 disk image bootable is two writes that are independent of the
//! filesystems on it:
//!
//!   1. The MBR (sector 0) gets the active-partition chainloader stub, which
//!      loads the first sector of the active UNIX partition.
//!   2. That partition's first `HDPDLOC` sectors hold the hard-disk bootstrap
//!      (`hdboot`), which in turn chain-loads the kernel out of `/stand`. The
//!      `hdboot` artifact is a 32-bit ELF; the bootstrap area wants a flat image,
//!      so each `PT_LOAD` segment is copied to its physical address and the whole
//!      thing must end with the `0x55AA` boot signature at offset 510.
//!
//! Both are idempotent patches to an existing, already-laid-out image, so this is
//! a separate step that can be re-run whenever the kernel/boot files change.

use svr4_fs_core::codec::{u16, u32};

use crate::structures::{HDPDLOC, SECTOR_SIZE};

/// 32-bit ELF header / program-header sizes and the `PT_LOAD` type.
const ELF_HEADER_SIZE: usize = 52;
const ELF_PROGRAM_HEADER_SIZE: usize = 32;
const PT_LOAD: u32 = 1;

/// Flatten the `hdboot` ELF into the partition bootstrap area.
///
/// Returns exactly `HDPDLOC * SECTOR_SIZE` bytes (the space before the pdinfo
/// sector): every `PT_LOAD` segment copied to its `p_paddr`, zero-padded
/// elsewhere. Errors carry the same `error: ...` messages the Python tool used,
/// including the signature check that catches a `uts` built without the WINI
/// bootstrap layout.
pub fn flatten_hdboot_bootstrap(payload: &[u8]) -> Result<Vec<u8>, String> {
    let limit = HDPDLOC as usize * SECTOR_SIZE;

    if payload.len() < ELF_HEADER_SIZE || payload[..4] != *b"\x7fELF" {
        return Err("error: expected hdboot to be a 32-bit ELF hard-disk bootstrap image".into());
    }
    if payload[4] != 1 || payload[5] != 1 {
        return Err("error: expected hdboot to be a 32-bit little-endian ELF image".into());
    }

    let e_phoff = u32(payload, 28) as usize;
    let e_phentsize = u16(payload, 42) as usize;
    let e_phnum = u16(payload, 44) as usize;
    if e_phnum == 0 || e_phentsize < ELF_PROGRAM_HEADER_SIZE {
        return Err("error: hdboot does not contain usable program headers".into());
    }

    let mut flattened = vec![0u8; limit];
    let mut found_load = false;
    for index in 0..e_phnum {
        let entry = e_phoff + index * e_phentsize;
        if entry + ELF_PROGRAM_HEADER_SIZE > payload.len() {
            return Err("error: hdboot is truncated in the program header table".into());
        }
        // 32-bit Elf32_Phdr: type, offset, vaddr, paddr, filesz, memsz, ...
        let p_type = u32(payload, entry);
        let p_offset = u32(payload, entry + 4) as usize;
        let p_paddr = u32(payload, entry + 12) as usize;
        let p_filesz = u32(payload, entry + 16) as usize;
        if p_type != PT_LOAD || p_filesz == 0 {
            continue;
        }
        found_load = true;
        let end = p_paddr + p_filesz;
        if end > limit {
            return Err(format!(
                "error: hdboot needs {end} bytes, but only {limit} bytes are available before pdinfo"
            ));
        }
        let file_end = p_offset + p_filesz;
        if file_end > payload.len() {
            return Err("error: hdboot is truncated in a PT_LOAD segment".into());
        }
        flattened[p_paddr..end].copy_from_slice(&payload[p_offset..file_end]);
    }

    if !found_load {
        return Err("error: hdboot does not contain any PT_LOAD segments".into());
    }
    if flattened[510..512] != *b"\x55\xaa" {
        return Err(
            "error: hard-disk bootstrap does not place the boot signature at offset 510; \
             rebuild uts with the corrected WINI bootstrap layout"
                .into(),
        );
    }
    Ok(flattened)
}

#[cfg(test)]
mod tests {
    use super::*;
    use svr4_fs_core::codec::{put_u16, put_u32};

    /// Build a minimal 32-bit ELF with one PT_LOAD segment carrying `body` at
    /// physical address `paddr`.
    fn fake_hdboot(paddr: usize, body: &[u8]) -> Vec<u8> {
        let ph_off = ELF_HEADER_SIZE;
        let data_off = ph_off + ELF_PROGRAM_HEADER_SIZE;
        let mut elf = vec![0u8; data_off + body.len()];
        elf[..4].copy_from_slice(b"\x7fELF");
        elf[4] = 1; // ELFCLASS32
        elf[5] = 1; // ELFDATA2LSB
        put_u32(&mut elf, 28, ph_off as u32); // e_phoff
        put_u16(&mut elf, 42, ELF_PROGRAM_HEADER_SIZE as u16); // e_phentsize
        put_u16(&mut elf, 44, 1); // e_phnum
        put_u32(&mut elf, ph_off, PT_LOAD); // p_type
        put_u32(&mut elf, ph_off + 4, data_off as u32); // p_offset
        put_u32(&mut elf, ph_off + 12, paddr as u32); // p_paddr
        put_u32(&mut elf, ph_off + 16, body.len() as u32); // p_filesz
        elf[data_off..].copy_from_slice(body);
        elf
    }

    #[test]
    fn flattens_segment_and_keeps_signature() {
        // One segment that spans the whole first sector, ending in 0x55AA.
        let mut body = vec![0u8; SECTOR_SIZE];
        body[0] = 0xEB;
        body[510] = 0x55;
        body[511] = 0xAA;
        let elf = fake_hdboot(0, &body);
        let out = flatten_hdboot_bootstrap(&elf).unwrap();
        assert_eq!(out.len(), HDPDLOC as usize * SECTOR_SIZE);
        assert_eq!(out[0], 0xEB);
        assert_eq!(&out[510..512], b"\x55\xaa");
    }

    #[test]
    fn rejects_missing_signature() {
        let elf = fake_hdboot(0, &[0u8; SECTOR_SIZE]);
        let err = flatten_hdboot_bootstrap(&elf).unwrap_err();
        assert!(err.contains("boot signature"), "{err}");
    }

    #[test]
    fn rejects_non_elf() {
        let err = flatten_hdboot_bootstrap(&[0u8; 64]).unwrap_err();
        assert!(err.contains("32-bit ELF"), "{err}");
    }

    #[test]
    fn rejects_oversized_segment() {
        let body = vec![0u8; HDPDLOC as usize * SECTOR_SIZE + 1];
        let elf = fake_hdboot(0, &body);
        let err = flatten_hdboot_bootstrap(&elf).unwrap_err();
        assert!(err.contains("available before pdinfo"), "{err}");
    }
}
