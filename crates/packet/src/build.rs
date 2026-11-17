use std::net::Ipv4Addr;

use crate::checksum;
use crate::ipv4::{ICMP, TCP, UDP};
use crate::l4::{ECHO_REPLY, ECHO_REQUEST};

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

// Stamped the pseudo header checksum into a segment at the given offset.
fn seal(mut seg: Vec<u8>, at: usize, proto: u8, src: Ipv4Addr, dst: Ipv4Addr) -> Vec<u8> {
    let ck = checksum::checksum(&seg, checksum::pseudo_v4(src, dst, proto, seg.len()));
    let ck = if proto == UDP && ck == 0 { 0xffff } else { ck };
    seg[at..at + 2].copy_from_slice(&ck.to_be_bytes());
    seg
}

// Built a UDP datagram inside an IPv4 packet.
pub fn udp4(src: Ipv4Addr, sport: u16, dst: Ipv4Addr, dport: u16, data: &[u8]) -> Vec<u8> {
    let mut seg = [sport.to_be_bytes(), dport.to_be_bytes()].concat();
    seg.extend(((8 + data.len()) as u16).to_be_bytes());
    seg.extend([0, 0]);
    seg.extend(data);
    ip(UDP, src, dst, &seal(seg, 6, UDP, src, dst))
}

// Built a TCP segment with an optional MSS option inside an IPv4 packet.
pub fn tcp4(src: Ipv4Addr, sport: u16, dst: Ipv4Addr, dport: u16, flags: u8, mss: Option<u16>, data: &[u8]) -> Vec<u8> {
    let words = if mss.is_some() { 6 } else { 5 };
    let mut seg = [sport.to_be_bytes(), dport.to_be_bytes()].concat();
    seg.extend([0, 0, 0, 1, 0, 0, 0, 1, words << 4, flags, 0xff, 0xff, 0, 0, 0, 0]);
    if let Some(m) = mss {
        seg.extend([2, 4]);
        seg.extend(m.to_be_bytes());
    }
    seg.extend(data);
    ip(TCP, src, dst, &seal(seg, 16, TCP, src, dst))
}

// Built an ICMP echo request or reply inside an IPv4 packet.
pub fn icmp4(src: Ipv4Addr, dst: Ipv4Addr, id: u16, reply: bool) -> Vec<u8> {
    let mut seg = vec![if reply { ECHO_REPLY } else { ECHO_REQUEST }, 0, 0, 0];
    seg.extend(id.to_be_bytes());
    seg.extend([0, 1, b'p', b'i', b'n', b'g']);
    let ck = checksum::checksum(&seg, 0);
    seg[2..4].copy_from_slice(&ck.to_be_bytes());
    ip(ICMP, src, dst, &seg)
}
