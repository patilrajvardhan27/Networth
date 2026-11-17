//! Hand-written packet parsing and RFC 1624 incremental checksum updates.

pub mod build;
pub mod checksum;
pub mod ipv4;
pub mod ipv6;
pub mod l4;
pub mod mss;

use std::fmt;

pub use ipv4::{Ipv4, Side};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Error {
    Truncated,
    Version,
    Length,
    Fragment,
}

impl fmt::Display for Error {
    // Told the reader in plain words why a packet was turned away.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Error::Truncated => "packet truncated",
            Error::Version => "unexpected ip version",
            Error::Length => "inconsistent length fields",
            Error::Fragment => "fragments are not supported",
        })
    }
}

impl std::error::Error for Error {}
