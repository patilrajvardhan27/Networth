use std::net::Ipv4Addr;

use crate::l4::{self, Tcp};
use crate::{checksum, Error};

pub const ICMP: u8 = 1;
pub const TCP: u8 = 6;
pub const UDP: u8 = 17;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Side {
    Src,
    Dst,
}

pub struct Ipv4<'a> {
    pub(crate) buf: &'a mut [u8],
    pub(crate) hl: usize,
}

impl<'a> Ipv4<'a> {
    // Looked over an IPv4 header, refused fragments and trimmed link padding off the tail.
    pub fn parse(buf: &'a mut [u8]) -> Result<Self, Error> {
        if buf.len() < 20 {
            return Err(Error::Truncated);
        }
        if buf[0] >> 4 != 4 {
            return Err(Error::Version);
        }
        let hl = usize::from(buf[0] & 0xf) * 4;
        let total = usize::from(u16::from_be_bytes([buf[2], buf[3]]));
        if hl < 20 || total < hl || total > buf.len() {
            return Err(Error::Length);
        }
        if u16::from_be_bytes([buf[6], buf[7]]) & 0x3fff != 0 {
            return Err(Error::Fragment);
        }
        let (buf, _) = buf.split_at_mut(total);
        Ok(Self { buf, hl })
    }
    // Showed the whole packet as bytes.
    pub fn bytes(&self) -> &[u8] {
        self.buf
    }
    // Rebuilt an address from the four bytes at an offset.
    fn addr_at(&self, at: usize) -> Ipv4Addr {
        Ipv4Addr::new(self.buf[at], self.buf[at + 1], self.buf[at + 2], self.buf[at + 3])
    }
    // Read the source address.
    pub fn src(&self) -> Ipv4Addr {
        self.addr_at(12)
    }
    // Read the destination address.
    pub fn dst(&self) -> Ipv4Addr {
        self.addr_at(16)
    }
    // Read the protocol number.
    pub fn proto(&self) -> u8 {
        self.buf[9]
    }
    // Handed back the transport bytes after the IP header.
    pub fn l4(&self) -> &[u8] {
        &self.buf[self.hl..]
    }
    // Checked the header checksum summed to all ones.
    pub fn header_ok(&self) -> bool {
        checksum::verify(&self.buf[..self.hl], 0)
    }
    // Checked the transport checksum, treating a zero UDP checksum as unchecked.
    pub fn l4_ok(&self) -> bool {
        let l4 = self.l4();
        match self.proto() {
            UDP if l4.len() >= 8 && l4[6..8] == [0, 0] => true,
            TCP | UDP => checksum::verify(l4, checksum::pseudo_v4(self.src(), self.dst(), self.proto(), l4.len())),
            ICMP => checksum::verify(l4, 0),
            _ => true,
        }
    }
    // Read TCP flags when the packet carried TCP.
    pub fn tcp_flags(&self) -> Option<u8> {
        if self.proto() != TCP {
            return None;
        }
        Tcp::parse(self.l4()).ok().map(|t| t.flags())
    }
    // Pulled the port pair, or the echo id on whichever side it sat.
    pub fn ports(&self) -> Option<(u16, u16)> {
        l4::ports(self.proto(), self.l4())
    }
    // Located the transport checksum field, if this protocol had one and it fit.
    fn l4_ck_at(&self) -> Option<usize> {
        let off = match self.proto() {
            TCP => 16,
            UDP => 6,
            ICMP => 2,
            _ => return None,
        };
        (self.buf.len() >= self.hl + off + 2).then_some(self.hl + off)
    }
    // Swapped words in one checksum field without touching the rest of the packet.
    fn patch_at(&mut self, at: usize, old: &[u8], new: &[u8]) {
        let cur = u16::from_be_bytes([self.buf[at], self.buf[at + 1]]);
        let mut ck = checksum::update(cur, old, new);
        if ck == 0 && self.proto() == UDP && at == self.hl + 6 {
            ck = 0xffff;
        }
        self.buf[at..at + 2].copy_from_slice(&ck.to_be_bytes());
    }
    // Patched the transport checksum for changed words, skipping UDP that never used one.
    pub(crate) fn patch_l4(&mut self, old: &[u8], new: &[u8], pseudo_only: bool) {
        let Some(at) = self.l4_ck_at() else { return };
        let unused = self.proto() == UDP && self.buf[at..at + 2] == [0, 0];
        if unused || (pseudo_only && self.proto() == ICMP) {
            return;
        }
        self.patch_at(at, old, new);
    }
    // Rewrote one address and kept the IP and pseudo header checksums honest.
    pub fn set_addr(&mut self, side: Side, addr: Ipv4Addr) {
        let at = if side == Side::Src { 12 } else { 16 };
        let (old, new) = (self.buf[at..at + 4].to_vec(), addr.octets());
        self.patch_at(10, &old, &new);
        self.patch_l4(&old, &new, true);
        self.buf[at..at + 4].copy_from_slice(&new);
    }
    // Rewrote one port, or the echo id for ICMP, and fixed the transport checksum.
    pub fn set_port(&mut self, side: Side, port: u16) {
        let at = match (self.proto(), side) {
            (ICMP, _) => self.hl + 4,
            (_, Side::Src) => self.hl,
            (_, Side::Dst) => self.hl + 2,
        };
        if self.buf.len() < at + 2 {
            return;
        }
        let (old, new) = ([self.buf[at], self.buf[at + 1]], port.to_be_bytes());
        self.patch_l4(&old, &new, false);
        self.buf[at..at + 2].copy_from_slice(&new);
    }
}
