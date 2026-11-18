use std::net::{Ipv4Addr, Ipv6Addr};

use nat_core::reflect::Dir;
use nat_core::{Config, Error, ManualClock, Nat, Pool, Verdict};
use packet::build::{icmp4, icmp6, tcp4, tcp6, udp4, udp6};
use packet::ipv6::Ipv6;
use packet::l4::{ACK, SYN};
use packet::nat64::{embed, WKP};
use packet::Ipv4;

const CLIENT: Ipv6Addr = Ipv6Addr::new(0x2001, 0xdb8, 0x10, 0, 0, 0, 0, 2);
const SERVER: Ipv4Addr = Ipv4Addr::new(203, 0, 113, 9);

// Stood up a NAT with the well-known NAT64 prefix switched on.
fn rig() -> Nat<ManualClock> {
    let cfg = Config { nat64: Some(WKP), ..Config::default() };
    Nat::new(cfg, Pool::new("198.51.100.0/27".parse().unwrap()), ManualClock::default())
}

// Read the pool address and port a translated IPv4 packet carried.
fn global(buf: &mut [u8]) -> (Ipv4Addr, u16) {
    let ip = Ipv4::parse(buf).unwrap();
    assert!(ip.header_ok() && ip.l4_ok());
    (ip.src(), ip.ports().unwrap().0)
}

// Walked a TCP handshake from an IPv6 client to an IPv4 server and back.
#[test]
fn tcp_handshake_crosses_families() {
    let mut nat = rig();
    let mut syn = tcp6(CLIENT, 6000, embed(WKP, SERVER), 80, SYN, Some(1440), b"");
    assert_eq!(nat.process(Dir::Out, &mut syn), Ok(Verdict::Translated));
    let (addr, port) = global(&mut syn);
    assert!(nat.pool().contains(addr) && port == 6000);
    assert_eq!(Ipv4::parse(&mut syn).unwrap().dst(), SERVER);

    let mut synack = tcp4(SERVER, 80, addr, port, SYN | ACK, None, b"");
    assert_eq!(nat.process(Dir::In, &mut synack), Ok(Verdict::Translated));
    let ip = Ipv6::parse(&synack).unwrap();
    assert!(ip.l4_checksum_ok());
    assert_eq!((ip.src(), ip.dst(), ip.ports()), (embed(WKP, SERVER), CLIENT, Some((80, 6000))));

    let mut data = tcp6(CLIENT, 6000, embed(WKP, SERVER), 80, ACK, None, b"hello");
    assert_eq!(nat.process(Dir::Out, &mut data), Ok(Verdict::Translated));
    assert_eq!(Ipv4::parse(&mut data).unwrap().l4().len(), 25);
}

// Sent UDP and an echo through the translator and matched both replies.
#[test]
fn udp_and_icmp_round_trip() {
    let mut nat = rig();
    let mut q = udp6(CLIENT, 5353, embed(WKP, SERVER), 53, b"q");
    nat.process(Dir::Out, &mut q).unwrap();
    let (addr, port) = global(&mut q);
    let mut a = udp4(SERVER, 53, addr, port, b"a");
    nat.process(Dir::In, &mut a).unwrap();
    assert_eq!(Ipv6::parse(&a).unwrap().ports(), Some((53, 5353)));

    let mut ping = icmp6(CLIENT, embed(WKP, SERVER), 77, false);
    nat.process(Dir::Out, &mut ping).unwrap();
    let (addr, id) = global(&mut ping);
    let mut pong = icmp4(SERVER, addr, id, true);
    nat.process(Dir::In, &mut pong).unwrap();
    let ip = Ipv6::parse(&pong).unwrap();
    assert!(ip.l4_checksum_ok());
    assert_eq!(ip.ports(), Some((0, 77)));
}

// Confirmed that outsiders, other prefixes and a disabled NAT64 are all refused.
#[test]
fn unsolicited_and_foreign_packets_are_refused() {
    let mut nat = rig();
    let mut syn = tcp6(CLIENT, 6000, embed(WKP, SERVER), 80, SYN, None, b"");
    nat.process(Dir::Out, &mut syn).unwrap();
    let (addr, port) = global(&mut syn);
    let mut sneaky = tcp4(SERVER, 80, addr, port, SYN, None, b"");
    assert_eq!(nat.process(Dir::In, &mut sneaky), Err(Error::Rejected));
    let mut other = udp6(CLIENT, 1, "2001:db8:99::1".parse().unwrap(), 2, b"x");
    assert_eq!(nat.process(Dir::Out, &mut other), Err(Error::Unsupported));
    let mut off = Nat::new(Config::default(), Pool::new("198.51.100.0/27".parse().unwrap()), ManualClock::default());
    let mut pkt = udp6(CLIENT, 1, embed(WKP, SERVER), 2, b"x");
    assert_eq!(off.process(Dir::Out, &mut pkt), Err(Error::Unsupported));
}

// Mixed IPv4 and IPv6 clients on one pool and expected both to translate.
#[test]
fn both_families_share_the_pool() {
    let mut nat = rig();
    let mut v4 = udp4(Ipv4Addr::new(172, 16, 10, 2), 4000, SERVER, 9, b"");
    let mut v6 = udp6(CLIENT, 4000, embed(WKP, SERVER), 9, b"");
    assert_eq!(nat.process(Dir::Out, &mut v4), Ok(Verdict::Translated));
    assert_eq!(nat.process(Dir::Out, &mut v6), Ok(Verdict::Translated));
    assert_ne!(global(&mut v4), global(&mut v6));
}
