//! Shared foundation for the SVR4 host tools (Rust port).
//!
//! Phase 0 of the rewrite described in `host-tools/RUST_PORT_PLAN.md`. This crate
//! holds only the pieces that every later crate (`svr4-disk`, `svr4-ufs`) needs:
//!
//! * [`consts`] — on-disk constants and `struct` field offsets, pinned against
//!   the real C headers by the `layout_offsets` test.
//! * [`codec`] — little-endian field accessors.
//! * [`image`] — the [`image::ImageBacking`] abstraction and an in-memory impl.
//! * [`fs`] — filesystem identification ([`fs::FilesystemCandidate`]).
//! * [`error`] — the shared error type.

pub mod codec;
pub mod consts;
pub mod error;
pub mod fs;
pub mod image;

pub use error::{Error, Result};
pub use fs::{FilesystemCandidate, FsKind};
pub use image::{ImageBacking, MappedImage, MappedImageRo, VecImage};
