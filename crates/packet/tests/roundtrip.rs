use std::net::Ipv4Addr;

use etherparse::{IpNumber, Ipv4Header, SlicedPacket, TransportSlice};
use packet::build::{icmp4, tcp4, udp4};
use packet::l4::{ACK, SYN};
use packet::{Ipv4, Side};
use proptest::prelude::*;

// Turned four random bytes into an address.
fn addr(b: [u8; 4]) -> Ipv4Addr {
    Ipv4Addr::from(b)
}

// Rewrote every field the NAT touches and expected both checksums to stay valid.
fn rewrite(buf: &mut [u8], src: Ipv4Addr, sp: u16, dst: Ipv4Addr, dp: u16) {
    let mut ip = Ipv4::parse(buf).unwrap();
    ip.set_addr(Side::Src, src);
    ip.set_addr(Side::Dst, dst);
    ip.set_port(Side::Src, sp);
    ip.set_port(Side::Dst, dp);
}

proptest! {
    // Checked UDP rewrites against a full recompute and etherparse as the outside witness.
    #[test]
    fn udp_rewrite_keeps_checksums(a in any::<[u8;4]>(), b in any::<[u8;4]>(), c in any::<[u8;4]>(), d in any::<[u8;4]>(),
                                   p in 1u16.., q in 1u16.., r in 1u16.., s in 1u16.., data in proptest::collection::vec(any::<u8>(), 0..200)) {
        let mut pkt = udp4(addr(a), p, addr(b), q, &data);
        rewrite(&mut pkt, addr(c), r, addr(d), s);
        let ip = Ipv4::parse(&mut pkt).unwrap();
        prop_assert!(ip.header_ok() && ip.l4_ok());
        let parsed = SlicedPacket::from_ip(ip.bytes()).unwrap();
        let Some(TransportSlice::Udp(udp)) = parsed.transport else { return Err(TestCaseError::fail("not udp")) };
        prop_assert_eq!((udp.source_port(), udp.destination_port()), (r, s));
        let (hdr, _) = Ipv4Header::from_slice(ip.bytes()).unwrap();
        prop_assert_eq!(hdr.source, c);
        prop_assert_eq!(udp.checksum(), udp.to_header().calc_checksum_ipv4(&hdr, udp.payload()).unwrap());
    }

    // Checked TCP rewrites the same way, flags and options included.
    #[test]
    fn tcp_rewrite_keeps_checksums(a in any::<[u8;4]>(), b in any::<[u8;4]>(), c in any::<[u8;4]>(), d in any::<[u8;4]>(),
                                   p in 1u16.., q in 1u16.., r in 1u16.., s in 1u16.., mss in proptest::option::of(536u16..9000),
                                   data in proptest::collection::vec(any::<u8>(), 0..200)) {
        let mut pkt = tcp4(addr(a), p, addr(b), q, SYN | ACK, mss, &data);
        rewrite(&mut pkt, addr(c), r, addr(d), s);
        let ip = Ipv4::parse(&mut pkt).unwrap();
        prop_assert!(ip.header_ok() && ip.l4_ok());
        let parsed = SlicedPacket::from_ip(ip.bytes()).unwrap();
        let Some(TransportSlice::Tcp(tcp)) = parsed.transport else { return Err(TestCaseError::fail("not tcp")) };
        prop_assert_eq!((tcp.source_port(), tcp.destination_port()), (r, s));
        let (hdr, _) = Ipv4Header::from_slice(ip.bytes()).unwrap();
        prop_assert_eq!(tcp.checksum(), tcp.to_header().calc_checksum_ipv4(&hdr, tcp.payload()).unwrap());
    }

    // Clamped a random MSS and confirmed the checksum survived and the value landed.
    #[test]
    fn mss_clamp_keeps_checksum(mss in 537u16..9000, max in 536u16..1500) {
        let mut pkt = tcp4(addr([10, 0, 0, 1]), 1000, addr([10, 0, 0, 2]), 80, SYN, Some(mss), b"");
        let mut ip = Ipv4::parse(&mut pkt).unwrap();
        prop_assert_eq!(ip.clamp_mss(max), mss > max);
        prop_assert!(ip.l4_ok());
        let tcp = packet::l4::Tcp::parse(ip.l4()).unwrap();
        prop_assert_eq!(u16::from_be_bytes([tcp.options()[2], tcp.options()[3]]), mss.min(max));
    }

    // Rewrote an ICMP echo id and kept the ICMP checksum valid.
    #[test]
    fn icmp_id_rewrite_keeps_checksum(id in any::<u16>(), new in any::<u16>(), reply in any::<bool>()) {
        let mut pkt = icmp4(addr([10, 0, 0, 1]), addr([10, 0, 0, 2]), id, reply);
        let mut ip = Ipv4::parse(&mut pkt).unwrap();
        ip.set_port(Side::Src, new);
        prop_assert!(ip.header_ok() && ip.l4_ok());
        prop_assert_eq!(&ip.l4()[4..6], &new.to_be_bytes()[..]);
    }
}

// Confirmed the builder output parsed cleanly under etherparse before any rewriting.
#[test]
fn builder_output_is_valid() {
    let pkt = udp4(addr([1, 2, 3, 4]), 5, addr([6, 7, 8, 9]), 10, b"hi");
    let (hdr, _) = Ipv4Header::from_slice(&pkt).unwrap();
    assert_eq!(hdr.protocol, IpNumber::UDP);
    assert_eq!(hdr.header_checksum, hdr.calc_header_checksum());
}

// Refused fragments instead of guessing at them.
#[test]
fn fragments_are_rejected() {
    let mut pkt = udp4(addr([1, 1, 1, 1]), 1, addr([2, 2, 2, 2]), 2, b"x");
    pkt[6] = 0x20;
    assert_eq!(Ipv4::parse(&mut pkt).err(), Some(packet::Error::Fragment));
}
