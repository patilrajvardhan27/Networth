use std::net::Ipv4Addr;
use std::time::Duration;

use nat_core::{Acl, Cidr, Config, Error, ManualClock, Nat, Pool, Rule, Verdict};
use packet::build::{icmp4, tcp4, udp4};
use packet::l4::{ACK, FIN, SYN};
use packet::Ipv4;

const HOST: Ipv4Addr = Ipv4Addr::new(172, 16, 10, 2);
const OTHER: Ipv4Addr = Ipv4Addr::new(172, 16, 10, 3);
const SERVER: Ipv4Addr = Ipv4Addr::new(203, 0, 113, 9);

// Stood up a NAT over the documentation pool with a clock the test controlled.
fn rig(acl: &[&str], pool: &str) -> (Nat<ManualClock>, ManualClock) {
    let clock = ManualClock::default();
    let rules = acl.iter().map(|r| r.parse::<Rule>().unwrap()).collect();
    let cfg = Config { acl: if acl.is_empty() { Acl::default() } else { Acl::new(rules) }, ..Config::default() };
    (Nat::new(cfg, Pool::new(pool.parse::<Cidr>().unwrap()), clock.clone()), clock)
}

// Read back the addressing of a translated packet.
fn view(buf: &mut [u8]) -> (Ipv4Addr, u16, Ipv4Addr, u16) {
    let ip = Ipv4::parse(buf).unwrap();
    assert!(ip.header_ok() && ip.l4_ok());
    let (s, d) = ip.ports().unwrap();
    (ip.src(), s, ip.dst(), d)
}

// Sent a UDP packet out, got a reply back and saw both rewritten correctly.
#[test]
fn udp_round_trip_keeps_the_source_port() {
    let (mut nat, _) = rig(&[], "198.51.100.0/27");
    let mut out = udp4(HOST, 5000, SERVER, 53, b"q");
    assert_eq!(nat.outbound(&mut out), Ok(Verdict::Translated));
    let (src, sport, dst, dport) = view(&mut out);
    assert!(nat.pool().contains(src) && sport == 5000 && (dst, dport) == (SERVER, 53));
    let mut back = udp4(SERVER, 53, src, sport, b"a");
    assert_eq!(nat.inbound(&mut back), Ok(Verdict::Translated));
    assert_eq!(view(&mut back), (SERVER, 53, HOST, 5000));
}

// Collided two hosts on one source port and saw the second move to the next free one.
#[test]
fn clashing_ports_take_the_next_free_slot() {
    let (mut nat, _) = rig(&[], "198.51.100.0/30");
    let mut a = udp4(HOST, 4000, SERVER, 9, b"");
    let mut b = udp4(OTHER, 4000, SERVER, 9, b"");
    nat.outbound(&mut a).unwrap();
    nat.outbound(&mut b).unwrap();
    let (ga, pa, ..) = view(&mut a);
    let (gb, pb, ..) = view(&mut b);
    assert!((ga, pa) != (gb, pb));
}

// Ran a pool of one address dry and expected a clean refusal.
#[test]
fn exhausted_pool_refuses_new_flows() {
    let (mut nat, _) = rig(&[], "198.51.100.4/32");
    for p in 1024..=65535u16 {
        let mut pkt = udp4(HOST, p, SERVER, 9, b"");
        nat.outbound(&mut pkt).unwrap();
    }
    let mut extra = udp4(OTHER, 2000, SERVER, 9, b"");
    assert_eq!(nat.outbound(&mut extra), Err(Error::PoolExhausted));
}

// Let the clock run past the UDP timeout and saw the flow vanish.
#[test]
fn idle_flows_expire() {
    let (mut nat, clock) = rig(&[], "198.51.100.0/27");
    let mut out = udp4(HOST, 5000, SERVER, 9, b"");
    nat.outbound(&mut out).unwrap();
    clock.advance(Duration::from_secs(299));
    assert_eq!(nat.expire(), 0);
    clock.advance(Duration::from_secs(2));
    assert_eq!(nat.expire(), 1);
    assert!(nat.table().is_empty());
}

// Matched the lab's deny-then-permit ACL and saw inside to inside traffic skip translation.
#[test]
fn acl_exempts_inside_to_inside() {
    let (mut nat, _) = rig(&["deny 172.16.0.0/16 172.16.0.0/16", "permit 172.16.10.0/24 any"], "198.51.100.0/27");
    let mut inner = udp4(HOST, 1, Ipv4Addr::new(172, 16, 50, 1), 2, b"");
    assert_eq!(nat.outbound(&mut inner), Ok(Verdict::Bypassed));
    let mut outer = udp4(HOST, 1, SERVER, 2, b"");
    assert_eq!(nat.outbound(&mut outer), Ok(Verdict::Translated));
}

// Tried to start a TCP flow from outside and saw every attempt dropped.
#[test]
fn outsiders_cannot_initiate() {
    let (mut nat, _) = rig(&[], "198.51.100.0/27");
    let mut probe = tcp4(SERVER, 4444, Ipv4Addr::new(198, 51, 100, 1), 22, SYN, None, b"");
    assert_eq!(nat.inbound(&mut probe), Err(Error::NoMapping));
    let mut syn = tcp4(HOST, 6000, SERVER, 443, SYN, Some(1460), b"");
    nat.outbound(&mut syn).unwrap();
    let (g, gp, ..) = view(&mut syn);
    let mut sneaky = tcp4(SERVER, 443, g, gp, SYN, None, b"");
    assert_eq!(nat.inbound(&mut sneaky), Err(Error::Rejected));
    let mut synack = tcp4(SERVER, 443, g, gp, SYN | ACK, None, b"");
    assert_eq!(nat.inbound(&mut synack), Ok(Verdict::Translated));
    let mut fin = tcp4(HOST, 6000, SERVER, 443, FIN | ACK, None, b"");
    assert_eq!(nat.outbound(&mut fin), Ok(Verdict::Translated));
}

// Sent a bare ACK with no mapping behind it and saw it refused.
#[test]
fn midstream_tcp_without_state_is_dropped() {
    let (mut nat, _) = rig(&[], "198.51.100.0/27");
    let mut ack = tcp4(HOST, 6001, SERVER, 443, ACK, None, b"");
    assert_eq!(nat.outbound(&mut ack), Err(Error::NoMapping));
}

// Clamped the MSS in both directions during the handshake.
#[test]
fn mss_is_clamped_when_configured() {
    let cfg = Config { mss: Some(1400), ..Config::default() };
    let mut nat = Nat::new(cfg, Pool::new("198.51.100.0/27".parse().unwrap()), ManualClock::default());
    let mut syn = tcp4(HOST, 6002, SERVER, 443, SYN, Some(1460), b"");
    nat.outbound(&mut syn).unwrap();
    let ip = Ipv4::parse(&mut syn).unwrap();
    assert_eq!(&ip.l4()[22..24], &1400u16.to_be_bytes());
    assert!(ip.l4_ok());
}

// Pinged through the NAT and matched the reply by its rewritten echo id.
#[test]
fn icmp_echo_round_trips_by_id() {
    let (mut nat, _) = rig(&[], "198.51.100.0/27");
    let mut req = icmp4(HOST, SERVER, 77, false);
    nat.outbound(&mut req).unwrap();
    let ip = Ipv4::parse(&mut req).unwrap();
    let (gaddr, gid) = (ip.src(), ip.ports().unwrap().0);
    let mut reply = icmp4(SERVER, gaddr, gid, true);
    assert_eq!(nat.inbound(&mut reply), Ok(Verdict::Translated));
    let ip = Ipv4::parse(&mut reply).unwrap();
    assert!(ip.l4_ok());
    assert_eq!((ip.dst(), ip.ports().unwrap().1), (HOST, 77));
}
