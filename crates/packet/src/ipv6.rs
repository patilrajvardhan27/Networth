use std::net::Ipv6Addr;

use crate::l4::{self, Tcp};
use crate::{checksum, Error};

pub struct Ipv6<'a>(&'a [u8]);

impl<'a> Ipv6<'a> {
    // Looked over a fixed IPv6 header and trimmed the buffer to its payload length.
    pub fn parse(b: &'a [u8]) -> Result<Self, Error> {
        if b.len() < 40 {
            return Err(Error::Truncated);
        }
        if b[0] >> 4 != 6 {
            return Err(Error::Version);
        }
        let end = 40 + usize::from(u16::from_be_bytes([b[4], b[5]]));
        if end > b.len() {
            return Err(Error::Length);
        }
        Ok(Self(&b[..end]))
    }
    // Rebuilt the source address from its sixteen bytes.
    pub fn src(&self) -> Ipv6Addr {
        Ipv6Addr::from(<[u8; 16]>::try_from(&self.0[8..24]).unwrap())
    }
    // Rebuilt the destination address from its sixteen bytes.
    pub fn dst(&self) -> Ipv6Addr {
        Ipv6Addr::from(<[u8; 16]>::try_from(&self.0[24..40]).unwrap())
    }
    // Read the next header byte that named the upper layer.
    pub fn next_header(&self) -> u8 {
        self.0[6]
    }
    // Handed back everything after the fixed header.
    pub fn payload(&self) -> &'a [u8] {
        &self.0[40..]
    }
    // Pulled the port pair, or the echo id, from the upper layer.
    pub fn ports(&self) -> Option<(u16, u16)> {
        l4::ports(self.next_header(), self.payload())
    }
    // Read TCP flags when the packet carried TCP.
    pub fn tcp_flags(&self) -> Option<u8> {
        (self.next_header() == crate::ipv4::TCP).then(|| Tcp::parse(self.payload()).ok().map(|t| t.flags())).flatten()
    }
    // Checked the upper layer checksum against the IPv6 pseudo header.
    pub fn l4_checksum_ok(&self) -> bool {
        let seed = checksum::pseudo_v6(self.src(), self.dst(), self.next_header(), self.payload().len());
        checksum::verify(self.payload(), seed)
    }
}
