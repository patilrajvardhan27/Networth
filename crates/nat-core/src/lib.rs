//! Pure stateful NAT: forward and reverse maps, PAT allocation, ACL and TCP state tracking.

pub mod acl;
pub mod cidr;
pub mod clock;
pub mod nat;
pub mod pat;
pub mod reflect;
pub mod table;
pub mod timeouts;

use std::fmt;

pub use acl::{Acl, Rule};
pub use cidr::Cidr;
pub use clock::{Clock, ManualClock, SystemClock};
pub use nat::{Config, Nat, Stats, Verdict};
pub use pat::Pool;
pub use table::{Delta, Mapping, Table};
pub use timeouts::Timeouts;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Error {
    Malformed(packet::Error),
    Unsupported,
    PoolExhausted,
    NoMapping,
    NotForPool,
    Rejected,
}

impl From<packet::Error> for Error {
    // Wrapped a parser failure as a NAT error.
    fn from(e: packet::Error) -> Self {
        Error::Malformed(e)
    }
}

impl fmt::Display for Error {
    // Said in plain words why a packet was dropped.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Error::Malformed(e) => write!(f, "malformed: {e}"),
            Error::Unsupported => f.write_str("unsupported protocol"),
            Error::PoolExhausted => f.write_str("pool exhausted"),
            Error::NoMapping => f.write_str("no mapping"),
            Error::NotForPool => f.write_str("not addressed to the pool"),
            Error::Rejected => f.write_str("rejected by stateful filter"),
        }
    }
}

impl std::error::Error for Error {}
