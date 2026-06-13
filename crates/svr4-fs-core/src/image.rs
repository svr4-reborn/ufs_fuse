//! The `ImageBacking` abstraction.
//!
//! The Python tools duck-type the image object: the UFS logic works the same
//! whether it is handed a plain `bytearray` (in-memory, used by the test suite)
//! or a page-cached `DiskBackedSlice` over a slice of the raw disk file. This
//! trait is the Rust equivalent so the UFS/BFS crates can be written once,
//! generic over `&mut impl ImageBacking`, and exercised entirely in memory by
//! unit tests with zero real I/O.
//!
//! Reads take `&mut self` deliberately: the real file-backed implementation
//! (the `DiskBackedSlice` port, landing with the write path in Phase 3) mutates
//! an LRU page cache on every read, exactly like the Python original.

use std::fs::{File, OpenOptions};
use std::io;
use std::path::Path;

use memmap2::{Mmap, MmapMut};

/// A fixed-size, byte-addressable backing store for a filesystem image (or a
/// single slice of a disk image).
pub trait ImageBacking {
    /// Total size of the backing store in bytes. This never changes for the life
    /// of the backing — UFS images are formatted to a fixed slice size.
    fn len(&self) -> u64;

    /// Whether the backing store is empty.
    fn is_empty(&self) -> bool {
        self.len() == 0
    }

    /// Read exactly `buf.len()` bytes starting at `off`.
    ///
    /// Panics if the range is out of bounds; callers operate on validated
    /// structures, so an out-of-range access is a logic bug.
    fn read_at(&mut self, off: u64, buf: &mut [u8]);

    /// Write `src` starting at `off`. Panics if the range is out of bounds.
    fn write_at(&mut self, off: u64, src: &[u8]);

    /// Flush any buffered writes to the underlying storage.
    fn flush(&mut self) -> io::Result<()>;

    /// Convenience: read `len` bytes at `off` into a fresh `Vec`.
    fn read_vec(&mut self, off: u64, len: usize) -> Vec<u8> {
        let mut buf = vec![0u8; len];
        self.read_at(off, &mut buf);
        buf
    }
}

/// In-memory backing over a `Vec<u8>`. The workhorse for unit tests; equivalent
/// to handing the Python tools a `bytearray`.
#[derive(Clone, Debug)]
pub struct VecImage {
    data: Vec<u8>,
}

impl VecImage {
    /// Create a zero-filled image of `size` bytes.
    pub fn zeroed(size: usize) -> Self {
        VecImage {
            data: vec![0u8; size],
        }
    }

    /// Wrap existing bytes as an image.
    pub fn from_vec(data: Vec<u8>) -> Self {
        VecImage { data }
    }

    /// Borrow the whole image as a slice (handy with the `codec` helpers).
    pub fn as_slice(&self) -> &[u8] {
        &self.data
    }

    /// Borrow the whole image mutably.
    pub fn as_mut_slice(&mut self) -> &mut [u8] {
        &mut self.data
    }

    /// Consume the image, returning the underlying bytes.
    pub fn into_vec(self) -> Vec<u8> {
        self.data
    }
}

impl ImageBacking for VecImage {
    fn len(&self) -> u64 {
        self.data.len() as u64
    }

    fn read_at(&mut self, off: u64, buf: &mut [u8]) {
        let start = off as usize;
        let end = start + buf.len();
        buf.copy_from_slice(&self.data[start..end]);
    }

    fn write_at(&mut self, off: u64, src: &[u8]) {
        let start = off as usize;
        let end = start + src.len();
        self.data[start..end].copy_from_slice(src);
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

/// File-backed image via a writable memory map.
///
/// This is the Rust replacement for the Python `DiskBackedSlice`, but instead of
/// managing a demand-paged cache by hand it `mmap`s the image file (`memmap2`).
/// The kernel pages in only the regions actually touched and reclaims clean
/// pages under memory pressure, so the resident set is the working set — not the
/// whole image. That is what lets the host tools operate on large (LBA28-sized)
/// disk images without copying them into RAM, and it is the conventional way to
/// give a FUSE daemon random read/write access to a backing image.
///
/// Because the map derefs to `[u8]`, [`as_mut_slice`](MappedImage::as_mut_slice)
/// hands the UFS write path a normal `&mut [u8]` over the whole image with no
/// copying; mutations land directly in the page cache and are made durable by
/// [`flush`](MappedImage::flush) (`msync`).
///
/// Addressing is absolute within the image file: a UFS slice inside a partitioned
/// disk image is reached via its byte offset (`Ufs::start_offset`), exactly like
/// the in-memory [`VecImage`] path.
pub struct MappedImage {
    // The file must outlive the mapping; kept here for that lifetime.
    _file: File,
    map: MmapMut,
}

impl MappedImage {
    /// Memory-map an existing image file read/write.
    ///
    /// # Safety / concurrency
    /// `mmap` of a file is `unsafe` in `memmap2` because concurrent external
    /// modification of the file is undefined behaviour. The host tools are the
    /// sole writer of an image while it is mapped, which upholds that contract.
    pub fn open(path: &Path) -> io::Result<Self> {
        let file = OpenOptions::new().read(true).write(true).open(path)?;
        // SAFETY: see the method contract — no other writer touches the file
        // while this mapping is live.
        let map = unsafe { MmapMut::map_mut(&file)? };
        Ok(MappedImage { _file: file, map })
    }

    /// Create (or truncate) an image file of `size` bytes and map it read/write.
    /// The file is sparse where the filesystem supports it, so an empty large
    /// image costs no real disk until written.
    pub fn create(path: &Path, size: u64) -> io::Result<Self> {
        let file = OpenOptions::new()
            .read(true)
            .write(true)
            .create(true)
            .truncate(true)
            .open(path)?;
        file.set_len(size)?;
        // SAFETY: as in `open` — sole writer while mapped.
        let map = unsafe { MmapMut::map_mut(&file)? };
        Ok(MappedImage { _file: file, map })
    }

    /// Borrow the whole image as a slice.
    pub fn as_slice(&self) -> &[u8] {
        &self.map
    }

    /// Borrow the whole image mutably (for the UFS write path).
    pub fn as_mut_slice(&mut self) -> &mut [u8] {
        &mut self.map
    }

    /// `msync` all outstanding modifications to disk durably.
    pub fn flush(&self) -> io::Result<()> {
        self.map.flush()
    }

    /// `msync` just the `[offset, offset + len)` byte range (e.g. a single slice
    /// or page), avoiding a full-image scan on large images.
    pub fn flush_range(&self, offset: usize, len: usize) -> io::Result<()> {
        self.map.flush_range(offset, len)
    }
}

impl ImageBacking for MappedImage {
    fn len(&self) -> u64 {
        self.map.len() as u64
    }

    fn read_at(&mut self, off: u64, buf: &mut [u8]) {
        let start = off as usize;
        buf.copy_from_slice(&self.map[start..start + buf.len()]);
    }

    fn write_at(&mut self, off: u64, src: &[u8]) {
        let start = off as usize;
        self.map[start..start + src.len()].copy_from_slice(src);
    }

    fn flush(&mut self) -> io::Result<()> {
        self.map.flush()
    }
}

/// Read-only file-backed image via a memory map.
///
/// The read-only counterpart of [`MappedImage`], for code paths that only
/// inspect an image (e.g. `svr4-disk-image inspect` probing a slice for a
/// filesystem). Like [`MappedImage`] it never copies the file into RAM: the
/// kernel pages in only the regions actually read, so probing a slice inside a
/// tens-of-gigabyte disk image touches just the superblock and root-directory
/// pages, not the whole slice.
pub struct MappedImageRo {
    // The file must outlive the mapping; kept here for that lifetime.
    _file: File,
    map: Mmap,
}

impl MappedImageRo {
    /// Memory-map an existing image file read-only.
    ///
    /// # Safety / concurrency
    /// As with [`MappedImage::open`], `mmap` is `unsafe` in `memmap2` because
    /// concurrent external truncation/modification of the file is undefined
    /// behaviour. Callers map images they are not concurrently mutating.
    pub fn open(path: &Path) -> io::Result<Self> {
        let file = File::open(path)?;
        // SAFETY: see the method contract — the file is not concurrently
        // truncated/modified while this mapping is live.
        let map = unsafe { Mmap::map(&file)? };
        Ok(MappedImageRo { _file: file, map })
    }

    /// Borrow the whole image as a slice. Indexing into it faults in only the
    /// pages touched.
    pub fn as_slice(&self) -> &[u8] {
        &self.map
    }

    /// Total size of the mapped image in bytes.
    pub fn len(&self) -> u64 {
        self.map.len() as u64
    }

    /// Whether the mapped image is empty.
    pub fn is_empty(&self) -> bool {
        self.map.is_empty()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn vec_image_read_write_round_trip() {
        let mut img = VecImage::zeroed(64);
        assert_eq!(img.len(), 64);
        assert!(!img.is_empty());

        img.write_at(8, &[1, 2, 3, 4]);
        let mut buf = [0u8; 4];
        img.read_at(8, &mut buf);
        assert_eq!(buf, [1, 2, 3, 4]);
        assert_eq!(img.read_vec(8, 4), vec![1, 2, 3, 4]);

        // Untouched bytes stay zero.
        assert_eq!(img.read_vec(0, 4), vec![0, 0, 0, 0]);
    }

    #[test]
    #[should_panic]
    fn out_of_range_read_panics() {
        let mut img = VecImage::zeroed(4);
        let mut buf = [0u8; 8];
        img.read_at(0, &mut buf);
    }

    #[test]
    fn mapped_image_persists_writes_at_absolute_offsets() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("image.raw");
        // A disk-image-like file: a UFS "slice" region surrounded by other data.
        let slice_start = 4096usize;
        let slice_size = 2048usize;
        let mut whole = vec![0xAAu8; 0x10000];
        whole[slice_start..slice_start + slice_size].fill(0xBB);
        whole[slice_start + slice_size..].fill(0xCC);
        std::fs::write(&path, &whole).unwrap();

        let mut img = MappedImage::open(&path).unwrap();
        assert_eq!(img.len(), 0x10000);
        // Mutate inside the slice via both the slice view and write_at.
        img.as_mut_slice()[slice_start..slice_start + 4].copy_from_slice(&[1, 2, 3, 4]);
        img.write_at(slice_start as u64 + 100, &[9, 9, 9, 9]);
        let mut probe = [0u8; 4];
        img.read_at(slice_start as u64, &mut probe);
        assert_eq!(probe, [1, 2, 3, 4]);
        img.flush().unwrap();
        drop(img);

        let after = std::fs::read(&path).unwrap();
        // Bytes outside the touched region are unchanged.
        assert!(after[..slice_start].iter().all(|&b| b == 0xAA));
        assert!(after[slice_start + slice_size..].iter().all(|&b| b == 0xCC));
        assert_eq!(&after[slice_start..slice_start + 4], &[1, 2, 3, 4]);
        assert_eq!(&after[slice_start + 100..slice_start + 104], &[9, 9, 9, 9]);
    }

    #[test]
    fn mapped_image_create_makes_sized_file_and_round_trips() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("new.raw");
        let size = 1 << 20; // 1 MiB
        {
            let mut img = MappedImage::create(&path, size).unwrap();
            assert_eq!(img.len(), size);
            // Write near the end to exercise a high offset without touching the
            // rest (which stays a hole on filesystems that support sparseness).
            img.write_at(size - 8, &[1, 2, 3, 4, 5, 6, 7, 8]);
            img.flush_range(size as usize - 8, 8).unwrap();
        }
        assert_eq!(std::fs::metadata(&path).unwrap().len(), size);
        let mut img = MappedImage::open(&path).unwrap();
        assert_eq!(img.read_vec(size - 8, 8), vec![1, 2, 3, 4, 5, 6, 7, 8]);
        assert_eq!(img.read_vec(0, 4), vec![0, 0, 0, 0]);
    }
}
