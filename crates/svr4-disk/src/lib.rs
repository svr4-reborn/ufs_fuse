//! SVR4 raw disk image layer (Rust port of `host_tools/disk/`).
//!
//! Phase 1 of `host-tools/RUST_PORT_PLAN.md`: MBR / pdinfo / VTOC / alternates
//! parsing and construction, plus image inspection with a pluggable filesystem
//! detector ([`inspect::FsDetector`]). The UFS detector arrives in Phase 2.

pub mod create;
pub mod inspect;
pub mod mbr;
pub mod report;
pub mod structures;
pub mod svr4;

pub use report::format_report;
pub use structures::*;
