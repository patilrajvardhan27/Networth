use std::net::{Ipv4Addr, Ipv6Addr};

use crate::checksum;
use crate::ipv4::{ICMP, TCP, UDP};
use crate::l4::{ECHO_REPLY, ECHO_REPLY6, ECHO_REQUEST, ECHO_REQUEST6, ICMPV6};

// Wrapped a transport segment in an IPv4 header with a good checksum.
fn ip(proto: u8, src: Ipv4Addr, dst: Ipv4Addr, l4: &[u8]) -> Vec<u8> {
    let mut p = vec![0x45, 0, 0, 0, 0, 1, 0x40, 0, 64, proto, 0, 0];
    p.extend(src.octets());
    p.extend(dst.octets());
    p[2..4].copy_from_slice(&((20 + l4.len()) as u16).to_be_bytes());
    let ck = checksum::checksum(&p, 0);
    p[10..12].copy_from_slice(&ck.to_be_bytes());
    p.extend(l4);
    p
}

// Wrapped a transport segment in an IPv6 header.
fn ip6(next: u8, src: Ipv6Addr, dst: Ipv6Addr, l4: &[u8]) -> Vec<u8> {
    let mut p = vec![0x60, 0, 0, 0];
    p.extend((l4.len() as u16).to_be_bytes());
    p.extend([next, 64]);
    p.extend(src.octets());
    p.extend(dst.octets());
    p.extend(l4);
    p
}

// Stamped a checksum into a segment at the given offset, using 0xffff where UDP would have sent zero.
fn seal(mut seg: Vec<u8>, at: usize, proto: u8, seed: u64) -> Vec<u8> {
    let ck = checksum::checksum(&seg, seed);
    let ck = if proto == UDP && ck == 0 { 0xffff } else { ck };
    seg[at..at + 2].copy_from_slice(&ck.to_be_bytes());
    seg
}

// Laid out a UDP datagram with an empty checksum.
fn udp_segment(sport: u16, dport: u16, data: &[u8]) -> Vec<u8> {
    let mut seg = [sport.to_be_bytes(), dport.to_be_bytes()].concat();
    seg.extend(((8 + data.len()) as u16).to_be_bytes());
    seg.extend([0, 0]);
    seg.extend(data);
    seg
}

// Laid out a TCP segment with an optional MSS option and an empty checksum.
fn tcp_segment(sport: u16, dport: u16, flags: u8, mss: Option<u16>, data: &[u8]) -> Vec<u8> {
    let words = if mss.is_some() { 6 } else { 5 };
    let mut seg = [sport.to_be_bytes(), dport.to_be_bytes()].concat();
    seg.extend([0, 0, 0, 1, 0, 0, 0, 1, words << 4, flags, 0xff, 0xff, 0, 0, 0, 0]);
    if let Some(m) = mss {
        seg.extend([2, 4]);
        seg.extend(m.to_be_bytes());
    }
    seg.extend(data);
    seg
}

// Laid out an ICMP style echo message with an empty checksum.
fn echo_segment(kind: u8, id: u16) -> Vec<u8> {
    let mut seg = vec![kind, 0, 0, 0];
    seg.extend(id.to_be_bytes());
    seg.extend([0, 1, b'p', b'i', b'n', b'g']);
    seg
}

// Built a UDP datagram inside an IPv4 packet.
pub fn udp4(src: Ipv4Addr, sport: u16, dst: Ipv4Addr, dport: u16, data: &[u8]) -> Vec<u8> {
    let seg = udp_segment(sport, dport, data);
    ip(UDP, src, dst, &seal(seg.clone(), 6, UDP, checksum::pseudo_v4(src, dst, UDP, seg.len())))
}

// Built a TCP segment with an optional MSS option inside an IPv4 packet.
pub fn tcp4(src: Ipv4Addr, sport: u16, dst: Ipv4Addr, dport: u16, flags: u8, mss: Option<u16>, data: &[u8]) -> Vec<u8> {
    let seg = tcp_segment(sport, dport, flags, mss, data);
    ip(TCP, src, dst, &seal(seg.clone(), 16, TCP, checksum::pseudo_v4(src, dst, TCP, seg.len())))
}

// Built an ICMP echo request or reply inside an IPv4 packet.
pub fn icmp4(src: Ipv4Addr, dst: Ipv4Addr, id: u16, reply: bool) -> Vec<u8> {
    ip(ICMP, src, dst, &seal(echo_segment(if reply { ECHO_REPLY } else { ECHO_REQUEST }, id), 2, ICMP, 0))
}

// Built a UDP datagram inside an IPv6 packet.
pub fn udp6(src: Ipv6Addr, sport: u16, dst: Ipv6Addr, dport: u16, data: &[u8]) -> Vec<u8> {
    let seg = udp_segment(sport, dport, data);
    ip6(UDP, src, dst, &seal(seg.clone(), 6, UDP, checksum::pseudo_v6(src, dst, UDP, seg.len())))
}

// Built a TCP segment inside an IPv6 packet.
pub fn tcp6(src: Ipv6Addr, sport: u16, dst: Ipv6Addr, dport: u16, flags: u8, mss: Option<u16>, data: &[u8]) -> Vec<u8> {
    let seg = tcp_segment(sport, dport, flags, mss, data);
    ip6(TCP, src, dst, &seal(seg.clone(), 16, TCP, checksum::pseudo_v6(src, dst, TCP, seg.len())))
}

// Built an ICMPv6 echo request or reply inside an IPv6 packet.
pub fn icmp6(src: Ipv6Addr, dst: Ipv6Addr, id: u16, reply: bool) -> Vec<u8> {
    let seg = echo_segment(if reply { ECHO_REPLY6 } else { ECHO_REQUEST6 }, id);
    ip6(ICMPV6, src, dst, &seal(seg.clone(), 2, ICMPV6, checksum::pseudo_v6(src, dst, ICMPV6, seg.len())))
}
