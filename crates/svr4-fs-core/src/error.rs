//! Error type shared across the host-tool crates.
//!
//! Kept dependency-free (no `thiserror`) so `svr4-fs-core` stays a leaf crate.
//! The binaries can wrap these in `anyhow` at their boundary.

use std::fmt;

/// Result alias for the host tools.
pub type Result<T> = std::result::Result<T, Error>;

#[derive(Debug)]
#[non_exhaustive]
pub enum Error {
    /// Underlying I/O on the backing image failed.
    Io(std::io::Error),
    /// The on-disk structure did not match what we expected (bad magic, out of
    /// range pointer, corrupt directory, etc.).
    Corrupt(String),
    /// A requested path or inode does not exist.
    NotFound(String),
    /// The operation is not supported for this object/filesystem.
    Unsupported(String),
}

impl Error {
    pub fn corrupt(msg: impl Into<String>) -> Self {
        Error::Corrupt(msg.into())
    }

    pub fn not_found(msg: impl Into<String>) -> Self {
        Error::NotFound(msg.into())
    }

    pub fn unsupported(msg: impl Into<String>) -> Self {
        Error::Unsupported(msg.into())
    }
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Error::Io(e) => write!(f, "i/o error: {e}"),
            Error::Corrupt(m) => write!(f, "corrupt filesystem: {m}"),
            Error::NotFound(m) => write!(f, "not found: {m}"),
            Error::Unsupported(m) => write!(f, "unsupported: {m}"),
        }
    }
}

impl std::error::Error for Error {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Error::Io(e) => Some(e),
            _ => None,
        }
    }
}

impl From<std::io::Error> for Error {
    fn from(e: std::io::Error) -> Self {
        Error::Io(e)
    }
}
