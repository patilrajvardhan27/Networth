use std::net::{Ipv4Addr, Ipv6Addr};

// Added up every sixteen bit word and tucked a lone last byte in as its own.
pub fn sum(data: &[u8]) -> u64 {
    let (words, rest) = data.as_chunks::<2>();
    let mut acc: u64 = words.iter().map(|w| u64::from(u16::from_be_bytes(*w))).sum();
    if let [last] = rest {
        acc += u64::from(*last) << 8;
    }
    acc
}

// Folded the carries back down and flipped the bits to land on a checksum.
pub fn fold(mut acc: u64) -> u16 {
    while acc >> 16 != 0 {
        acc = (acc & 0xffff) + (acc >> 16);
    }
    !(acc as u16)
}

// Summed some bytes plus a pseudo header seed into a finished checksum.
pub fn checksum(data: &[u8], seed: u64) -> u16 {
    fold(sum(data) + seed)
}

// Confirmed that a buffer carrying its own checksum summed to all ones.
pub fn verify(data: &[u8], seed: u64) -> bool {
    checksum(data, seed) == 0
}

// Built the IPv4 pseudo header sum that TCP and UDP checksums lean on.
pub fn pseudo_v4(src: Ipv4Addr, dst: Ipv4Addr, proto: u8, len: usize) -> u64 {
    sum(&src.octets()) + sum(&dst.octets()) + u64::from(proto) + len as u64
}

// Built the IPv6 pseudo header sum for the upper layer checksums.
pub fn pseudo_v6(src: Ipv6Addr, dst: Ipv6Addr, next: u8, len: usize) -> u64 {
    sum(&src.octets()) + sum(&dst.octets()) + u64::from(next) + len as u64
}

// Patched a checksum for swapped words the RFC 1624 way, never rescanning the packet.
pub fn update(ck: u16, old: &[u8], new: &[u8]) -> u16 {
    let mut acc = u64::from(!ck);
    for (o, n) in old.as_chunks::<2>().0.iter().zip(new.as_chunks::<2>().0) {
        acc += u64::from(!u16::from_be_bytes(*o)) + u64::from(u16::from_be_bytes(*n));
    }
    fold(acc)
}
