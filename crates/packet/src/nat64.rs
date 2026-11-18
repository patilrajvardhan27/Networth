use std::net::{Ipv4Addr, Ipv6Addr};

use crate::ipv4::{ICMP, TCP, UDP};
use crate::ipv6::Ipv6;
use crate::l4::{ECHO_REPLY, ECHO_REPLY6, ECHO_REQUEST, ECHO_REQUEST6, ICMPV6};
use crate::{checksum, Error, Ipv4};

pub const WKP: Ipv6Addr = Ipv6Addr::new(0x64, 0xff9b, 0, 0, 0, 0, 0, 0);

// Tucked an IPv4 address into the low 32 bits of a /96 prefix as RFC 6052 describes.
pub fn embed(prefix: Ipv6Addr, v4: Ipv4Addr) -> Ipv6Addr {
    let mut o = prefix.octets();
    o[12..].copy_from_slice(&v4.octets());
    Ipv6Addr::from(o)
}

// Pulled the IPv4 address back out when the IPv6 one sat inside the /96 prefix.
pub fn extract(prefix: Ipv6Addr, addr: Ipv6Addr) -> Option<Ipv4Addr> {
    let (p, a) = (prefix.octets(), addr.octets());
    (p[..12] == a[..12]).then(|| Ipv4Addr::new(a[12], a[13], a[14], a[15]))
}

// Wrote a fresh checksum over a segment, using 0xffff where UDP would have sent zero.
fn full(l4: &mut [u8], at: usize, proto: u8, seed: u64) -> u16 {
    l4[at..at + 2].copy_from_slice(&[0, 0]);
    match checksum::checksum(l4, seed) {
        0 if proto == UDP => 0xffff,
        ck => ck,
    }
}

// Rewrote the port or echo id and the checksum after the addresses changed family.
fn retarget(
    proto: u8,
    l4: &mut [u8],
    addrs: (&[u8], &[u8]),
    port_at: usize,
    port: u16,
    icmp_type: u8,
    seed: u64,
) -> Result<(), Error> {
    let at = match proto {
        TCP => 16,
        UDP => 6,
        _ => 2,
    };
    if l4.len() < at + 2 || l4.len() < 8 {
        return Err(Error::Truncated);
    }
    if proto == TCP || proto == UDP {
        let had = u16::from_be_bytes([l4[at], l4[at + 1]]);
        let (old_port, new_port) = ([l4[port_at], l4[port_at + 1]], port.to_be_bytes());
        l4[port_at..port_at + 2].copy_from_slice(&new_port);
        let ck = if proto == UDP && had == 0 {
            full(l4, at, proto, seed)
        } else {
            let (old, new) = ([addrs.0, &old_port].concat(), [addrs.1, &new_port].concat());
            match checksum::update(had, &old, &new) {
                0 if proto == UDP => 0xffff,
                ck => ck,
            }
        };
        l4[at..at + 2].copy_from_slice(&ck.to_be_bytes());
    } else {
        l4[0] = icmp_type;
        l4[4..6].copy_from_slice(&port.to_be_bytes());
        let ck = full(l4, at, proto, seed);
        l4[at..at + 2].copy_from_slice(&ck.to_be_bytes());
    }
    Ok(())
}

// Translated an IPv6 packet into IPv4 with the given source, source port and destination, as RFC 7915 describes.
pub fn to_v4(pkt: &[u8], src: Ipv4Addr, sport: u16, dst: Ipv4Addr) -> Result<Vec<u8>, Error> {
    let ip = Ipv6::parse(pkt)?;
    if pkt[7] <= 1 {
        return Err(Error::HopLimit);
    }
    let mut l4 = ip.payload().to_vec();
    let (proto, icmp_type) = match (ip.next_header(), l4.first()) {
        (TCP, _) => (TCP, 0),
        (UDP, _) => (UDP, 0),
        (ICMPV6, Some(&ECHO_REQUEST6)) => (ICMP, ECHO_REQUEST),
        (ICMPV6, Some(&ECHO_REPLY6)) => (ICMP, ECHO_REPLY),
        _ => return Err(Error::Unsupported),
    };
    let seed = if proto == ICMP { 0 } else { checksum::pseudo_v4(src, dst, proto, l4.len()) };
    let (old, new) = ([ip.src().octets(), ip.dst().octets()].concat(), [src.octets(), dst.octets()].concat());
    retarget(proto, &mut l4, (&old, &new), 0, sport, icmp_type, seed)?;
    let mut out = vec![0x45, (pkt[0] << 4) | (pkt[1] >> 4), 0, 0, 0, 0, 0x40, 0, pkt[7] - 1, proto, 0, 0];
    out.extend(src.octets());
    out.extend(dst.octets());
    out[2..4].copy_from_slice(&((20 + l4.len()) as u16).to_be_bytes());
    let ck = checksum::checksum(&out, 0);
    out[10..12].copy_from_slice(&ck.to_be_bytes());
    out.extend(l4);
    Ok(out)
}

// Translated an IPv4 reply into IPv6 with the given addresses and destination port.
pub fn to_v6(pkt: &[u8], src: Ipv6Addr, dst: Ipv6Addr, dport: u16) -> Result<Vec<u8>, Error> {
    let mut tmp = pkt.to_vec();
    let ip = Ipv4::parse(&mut tmp)?;
    let (ttl, tos, mut l4) = (ip.bytes()[8], ip.bytes()[1], ip.l4().to_vec());
    if ttl <= 1 {
        return Err(Error::HopLimit);
    }
    let (proto, icmp_type) = match (ip.proto(), l4.first()) {
        (TCP, _) => (TCP, 0),
        (UDP, _) => (UDP, 0),
        (ICMP, Some(&ECHO_REQUEST)) => (ICMPV6, ECHO_REQUEST6),
        (ICMP, Some(&ECHO_REPLY)) => (ICMPV6, ECHO_REPLY6),
        _ => return Err(Error::Unsupported),
    };
    let seed = checksum::pseudo_v6(src, dst, proto, l4.len());
    let (old, new) = ([ip.src().octets(), ip.dst().octets()].concat(), [src.octets(), dst.octets()].concat());
    retarget(proto, &mut l4, (&old, &new), 2, dport, icmp_type, seed)?;
    let mut out = vec![0x60 | (tos >> 4), tos << 4, 0, 0];
    out.extend((l4.len() as u16).to_be_bytes());
    out.extend([proto, ttl - 1]);
    out.extend(src.octets());
    out.extend(dst.octets());
    out.extend(l4);
    Ok(out)
}
