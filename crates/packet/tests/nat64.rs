use std::net::{Ipv4Addr, Ipv6Addr};

use etherparse::{Ipv4Header, Ipv6Header, SlicedPacket, TransportSlice};
use packet::build::{icmp4, icmp6, tcp4, tcp6, udp4, udp6};
use packet::ipv6::Ipv6;
use packet::l4::{ACK, ECHO_REPLY6};
use packet::nat64::{embed, extract, to_v4, to_v6, WKP};
use packet::{Error, Ipv4};
use proptest::prelude::*;

// Turned sixteen random bytes into an address.
fn v6(b: [u8; 16]) -> Ipv6Addr {
    Ipv6Addr::from(b)
}

// Checked every checksum and field of a translated IPv4 packet, with etherparse as the witness.
fn check_v4(out: &mut [u8], src: Ipv4Addr, dst: Ipv4Addr) {
    let ip = Ipv4::parse(out).unwrap();
    assert!(ip.header_ok() && ip.l4_ok());
    assert_eq!((ip.src(), ip.dst()), (src, dst));
    let (hdr, _) = Ipv4Header::from_slice(ip.bytes()).unwrap();
    match SlicedPacket::from_ip(ip.bytes()).unwrap().transport {
        Some(TransportSlice::Tcp(t)) => {
            assert_eq!(t.checksum(), t.to_header().calc_checksum_ipv4(&hdr, t.payload()).unwrap())
        }
        Some(TransportSlice::Udp(u)) => {
            assert_eq!(u.checksum(), u.to_header().calc_checksum_ipv4(&hdr, u.payload()).unwrap())
        }
        _ => {}
    }
}

// Checked every checksum of a translated IPv6 packet, with etherparse as the witness.
fn check_v6(out: &[u8]) {
    assert!(Ipv6::parse(out).unwrap().l4_checksum_ok());
    let (hdr, _) = Ipv6Header::from_slice(out).unwrap();
    match SlicedPacket::from_ip(out).unwrap().transport {
        Some(TransportSlice::Tcp(t)) => {
            assert_eq!(t.checksum(), t.to_header().calc_checksum_ipv6(&hdr, t.payload()).unwrap())
        }
        Some(TransportSlice::Udp(u)) => {
            assert_eq!(u.checksum(), u.to_header().calc_checksum_ipv6(&hdr, u.payload()).unwrap())
        }
        _ => {}
    }
}

proptest! {
    // Translated random IPv6 TCP and UDP packets to IPv4 and expected valid checksums and fields.
    #[test]
    fn six_to_four_keeps_checksums(c in any::<[u8;16]>(), d in any::<[u8;4]>(), g in any::<[u8;4]>(), p in 1u16.., q in 1u16.., r in 1u16.., tcp in any::<bool>(),
                                   data in proptest::collection::vec(any::<u8>(), 0..300)) {
        let (src, dst) = (v6(c), embed(WKP, Ipv4Addr::from(d)));
        let pkt = if tcp { tcp6(src, p, dst, q, ACK, Some(1440), &data) } else { udp6(src, p, dst, q, &data) };
        let mut out = to_v4(&pkt, Ipv4Addr::from(g), r, extract(WKP, dst).unwrap()).unwrap();
        check_v4(&mut out, Ipv4Addr::from(g), Ipv4Addr::from(d));
        prop_assert_eq!(Ipv4::parse(&mut out).unwrap().ports(), Some((r, q)));
    }

    // Translated random IPv4 replies to IPv6 and expected valid checksums and the client port.
    #[test]
    fn four_to_six_keeps_checksums(s in any::<[u8;4]>(), g in any::<[u8;4]>(), c in any::<[u8;16]>(), p in 1u16.., q in 1u16.., r in 1u16.., tcp in any::<bool>(),
                                   data in proptest::collection::vec(any::<u8>(), 0..300)) {
        let pkt = if tcp { tcp4(Ipv4Addr::from(s), p, Ipv4Addr::from(g), q, ACK, None, &data) } else { udp4(Ipv4Addr::from(s), p, Ipv4Addr::from(g), q, &data) };
        let out = to_v6(&pkt, embed(WKP, Ipv4Addr::from(s)), v6(c), r).unwrap();
        check_v6(&out);
        prop_assert_eq!(Ipv6::parse(&out).unwrap().ports(), Some((p, r)));
    }

    // Round tripped an echo through both directions and expected its id and checksum to hold.
    #[test]
    fn icmp_translates_both_ways(c in any::<[u8;16]>(), d in any::<[u8;4]>(), g in any::<[u8;4]>(), id in any::<u16>(), gid in any::<u16>()) {
        let (client, server) = (v6(c), embed(WKP, Ipv4Addr::from(d)));
        let mut out = to_v4(&icmp6(client, server, id, false), Ipv4Addr::from(g), gid, Ipv4Addr::from(d)).unwrap();
        prop_assert!(Ipv4::parse(&mut out).unwrap().l4_ok());
        let reply = icmp4(Ipv4Addr::from(d), Ipv4Addr::from(g), gid, true);
        let back = to_v6(&reply, server, client, id).unwrap();
        check_v6(&back);
        prop_assert_eq!((Ipv6::parse(&back).unwrap().ports(), back[40]), (Some((0, id)), ECHO_REPLY6));
    }

    // Fed arbitrary bytes to both translators and expected a clean refusal, never a panic.
    #[test]
    fn translators_never_panic(head in prop_oneof![Just(0x60u8), Just(0x45u8), any::<u8>()], next in prop_oneof![Just(6u8), Just(17u8), Just(58u8), Just(1u8), any::<u8>()],
                               tail in proptest::collection::vec(any::<u8>(), 0..90)) {
        let mut buf = vec![head, 0, 0, 0, 0, 0, next, 64];
        buf.extend(tail);
        let len = (buf.len().saturating_sub(40)) as u16;
        buf[4..6].copy_from_slice(&len.to_be_bytes());
        let mut v4 = buf.clone();
        if v4.len() >= 20 {
            let total = v4.len() as u16;
            v4[0] = 0x45;
            v4[2..4].copy_from_slice(&total.to_be_bytes());
            v4[8..10].copy_from_slice(&[64, next]);
        }
        let _ = to_v4(&buf, Ipv4Addr::LOCALHOST, 1, Ipv4Addr::LOCALHOST);
        let _ = to_v6(&v4, WKP, WKP, 1);
    }
}

// Embedded and extracted an address and refused one outside the prefix.
#[test]
fn rfc6052_round_trip() {
    let a = Ipv4Addr::new(203, 0, 113, 9);
    assert_eq!(embed(WKP, a).to_string(), "64:ff9b::cb00:7109");
    assert_eq!(extract(WKP, embed(WKP, a)), Some(a));
    assert_eq!(extract(WKP, "2001:db8::1".parse().unwrap()), None);
}

// Refused to forward a packet whose hop limit had run out.
#[test]
fn exhausted_hop_limit_is_refused() {
    let mut pkt = udp6("2001:db8::2".parse().unwrap(), 1, embed(WKP, Ipv4Addr::LOCALHOST), 2, b"x");
    pkt[7] = 1;
    assert_eq!(to_v4(&pkt, Ipv4Addr::LOCALHOST, 1, Ipv4Addr::LOCALHOST), Err(Error::HopLimit));
}
