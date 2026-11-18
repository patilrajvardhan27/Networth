use std::borrow::Cow;
use std::fs::File;
use std::net::Ipv4Addr;
use std::path::PathBuf;
use std::time::Duration;

use nat_core::{Acl, Cidr, Config, ManualClock, Nat, Pool, Rule};
use natdiff::capture::{self, Frame};
use natdiff::compare::{compare, Options, Report};
use packet::build::{icmp4, tcp4, udp4};
use packet::l4::{ACK, SYN};
use packet::{Ipv4, Side};
use pcap_file::pcap::{PcapPacket, PcapWriter};
use pcap_file::pcapng::blocks::enhanced_packet::EnhancedPacketBlock;
use pcap_file::pcapng::blocks::interface_description::InterfaceDescriptionBlock;
use pcap_file::pcapng::PcapNgWriter;
use pcap_file::DataLink;

const A: Ipv4Addr = Ipv4Addr::new(172, 16, 10, 2);
const B: Ipv4Addr = Ipv4Addr::new(172, 16, 10, 3);
const S: Ipv4Addr = Ipv4Addr::new(203, 0, 113, 9);
const E: Ipv4Addr = Ipv4Addr::new(172, 16, 50, 1);

// Built the ACL the lab style config used, as parsed rules.
fn rules() -> Vec<Rule> {
    ["deny 172.16.0.0/16 172.16.0.0/16", "permit 172.16.10.0/24 any"].iter().map(|r| r.parse().unwrap()).collect()
}

// Made the options both the replay and the comparison used.
fn options() -> Options {
    Options { pool: "198.51.100.0/27".parse::<Cidr>().unwrap(), acl: rules(), mss: Some(1400) }
}

// Wrote out outbound traffic from two hosts, with TCP, UDP, ICMP and one exempt flow.
fn inside_traffic() -> Vec<Vec<u8>> {
    vec![
        tcp4(A, 40000, S, 443, SYN, Some(1460), b""),
        tcp4(A, 40000, S, 443, ACK, None, b"hello"),
        tcp4(A, 40000, S, 443, ACK, None, b"world"),
        tcp4(B, 40000, S, 443, SYN, Some(1460), b""),
        tcp4(B, 40000, S, 443, ACK, None, b"data"),
        udp4(A, 5353, S, 53, b"one"),
        udp4(A, 5353, S, 53, b"two"),
        udp4(B, 5353, S, 53, b"three"),
        icmp4(A, S, 7, false),
        icmp4(A, S, 7, false),
        udp4(A, 9, E, 9, b"exempt"),
    ]
}

// Played the router with its own port habits by pre-filling the pool with decoy flows.
fn router(inside: &[Vec<u8>]) -> Vec<Vec<u8>> {
    let cfg = Config { acl: Acl::new(rules()), mss: Some(1400), ..Config::default() };
    let mut nat = Nat::new(cfg, Pool::new("198.51.100.0/27".parse().unwrap()), ManualClock::default());
    for p in [40000u16, 5353] {
        let mut decoy = udp4(Ipv4Addr::new(172, 16, 10, 99), p, S, if p == 5353 { 53 } else { 443 }, b"");
        nat.outbound(&mut decoy).unwrap();
        let mut decoy = tcp4(Ipv4Addr::new(172, 16, 10, 99), p, S, 443, SYN, None, b"");
        nat.outbound(&mut decoy).unwrap();
    }
    inside
        .iter()
        .filter_map(|p| {
            let mut copy = p.clone();
            nat.outbound(&mut copy).ok().map(|_| copy)
        })
        .collect()
}

// Wrapped packets as capture frames spaced ten milliseconds apart.
fn frames(packets: Vec<Vec<u8>>) -> Vec<Frame> {
    packets.into_iter().enumerate().map(|(i, ip)| Frame { at: Duration::from_millis(10 * i as u64), ip }).collect()
}

// Put an Ethernet header on an IP packet.
fn eth(ip: &[u8]) -> Vec<u8> {
    [&[0u8; 12][..], &[8, 0], ip].concat()
}

// Picked a unique temp path for a capture file.
fn tmp(name: &str) -> PathBuf {
    std::env::temp_dir().join(format!("natdiff-{}-{name}", std::process::id()))
}

// Ran the comparison on the honest traffic with one tamper applied to the router side.
fn run(tamper: impl FnOnce(&mut Vec<Vec<u8>>)) -> Report {
    let inside = inside_traffic();
    let mut out = router(&inside);
    tamper(&mut out);
    compare(&frames(inside), &frames(out), &options())
}

// Rewrote a field of one router packet through the same parser the NAT uses.
fn edit(out: &mut [Vec<u8>], idx: usize, f: impl FnOnce(&mut Ipv4)) {
    f(&mut Ipv4::parse(&mut out[idx]).unwrap());
}

// Read both capture formats back and expected an honest router to pass with every flow matched.
#[test]
fn matching_router_passes_through_both_file_formats() {
    let inside = inside_traffic();
    let out = router(&inside);
    let (pcap, pcapng) = (tmp("in.pcap"), tmp("out.pcapng"));
    let mut w = PcapWriter::new(File::create(&pcap).unwrap()).unwrap();
    for (i, p) in inside.iter().enumerate() {
        let data = eth(p);
        w.write_packet(&PcapPacket::new_owned(Duration::from_millis(10 * i as u64), data.len() as u32, data)).unwrap();
    }
    let mut ng = PcapNgWriter::new(File::create(&pcapng).unwrap()).unwrap();
    ng.write_pcapng_block(InterfaceDescriptionBlock::new(DataLink::ETHERNET, 0xffff)).unwrap();
    for (i, p) in out.iter().enumerate() {
        let data = eth(p);
        let block = EnhancedPacketBlock {
            interface_id: 0,
            timestamp: Duration::from_millis(10 * i as u64),
            original_len: data.len() as u32,
            data: Cow::Owned(data),
            options: vec![],
        };
        ng.write_pcapng_block(block).unwrap();
    }
    drop((w, ng));
    let report = compare(&capture::read(&pcap).unwrap(), &capture::read(&pcapng).unwrap(), &options());
    assert_eq!(report.violations, Vec::<String>::new());
    assert_eq!((report.matched, report.unmatched, report.flows), (inside.len(), 0, 5));
    let _ = (std::fs::remove_file(pcap), std::fs::remove_file(pcapng));
}

// Changed a destination and expected the comparison to say so.
#[test]
fn changed_destination_is_flagged() {
    let r = run(|o| edit(o, 2, |ip| ip.set_addr(Side::Dst, Ipv4Addr::new(203, 0, 113, 10))));
    assert!(r.violations.iter().any(|v| v.contains("destination changed")), "{:?}", r.violations);
}

// Left a source untranslated and expected the comparison to say so.
#[test]
fn untranslated_source_is_flagged() {
    let r = run(|o| edit(o, 5, |ip| ip.set_addr(Side::Src, A)));
    assert!(r.violations.iter().any(|v| v.contains("untranslated")), "{:?}", r.violations);
}

// Moved a flow's source port mid-flow and expected the comparison to say so.
#[test]
fn mapping_change_is_flagged() {
    let r = run(|o| edit(o, 2, |ip| ip.set_port(Side::Src, 61000)));
    assert!(r.violations.iter().any(|v| v.contains("changed the mapping")), "{:?}", r.violations);
}

// Used an address outside the pool and expected the comparison to say so.
#[test]
fn source_outside_pool_is_flagged() {
    let r = run(|o| edit(o, 5, |ip| ip.set_addr(Side::Src, Ipv4Addr::new(192, 0, 2, 77))));
    assert!(r.violations.iter().any(|v| v.contains("outside the pool")), "{:?}", r.violations);
}

// Broke a checksum and expected the comparison to say so.
#[test]
fn bad_checksum_is_flagged() {
    let r = run(|o| {
        let at = 20 + 6;
        o[5][at] ^= 0xff;
    });
    assert!(r.violations.iter().any(|v| v.contains("invalid checksum")), "{:?}", r.violations);
}
