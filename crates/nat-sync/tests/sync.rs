use std::net::Ipv4Addr;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use nat_core::{Config, ManualClock, Nat, Pool, Verdict};
use packet::build::udp4;
use packet::Ipv4;
use tokio::net::UdpSocket;

const HOST: Ipv4Addr = Ipv4Addr::new(172, 16, 10, 2);
const SERVER: Ipv4Addr = Ipv4Addr::new(203, 0, 113, 9);

// Built a NAT over the documentation pool for one side of the pair.
fn side() -> Arc<Mutex<Nat<ManualClock>>> {
    let pool = Pool::new("198.51.100.0/27".parse().unwrap());
    Arc::new(Mutex::new(Nat::new(Config::default(), pool, ManualClock::default())))
}

// Opened a flow on the active, killed it and let the standby answer the reply.
#[tokio::test]
async fn standby_translates_flows_it_never_saw() {
    let (active, standby) = (side(), side());
    let rx = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let peer = rx.local_addr().unwrap();
    tokio::spawn(nat_sync::receive(standby.clone(), rx));

    let mut pkt = udp4(HOST, 5000, SERVER, 53, b"q");
    assert_eq!(active.lock().unwrap().outbound(&mut pkt), Ok(Verdict::Translated));
    let (global, gport) = {
        let ip = Ipv4::parse(&mut pkt).unwrap();
        (ip.src(), ip.ports().unwrap().0)
    };

    let tx = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let sender = tokio::spawn(nat_sync::replicate(active, tx, peer, Duration::from_millis(20)));
    tokio::time::sleep(Duration::from_millis(150)).await;
    sender.abort();

    let mut reply = udp4(SERVER, 53, global, gport, b"a");
    assert_eq!(standby.lock().unwrap().inbound(&mut reply), Ok(Verdict::Translated));
    let ip = Ipv4::parse(&mut reply).unwrap();
    assert_eq!((ip.dst(), ip.ports().unwrap().1), (HOST, 5000));
    assert!(ip.l4_ok());
}

// Round tripped an IPv6 inside address and a removal through the wire format.
#[test]
fn codec_carries_both_families() {
    use nat_core::reflect::TcpState;
    use nat_core::{Delta, Mapping};
    use nat_sync::codec::{decode, encode};
    let local = "[2001:db8:10::2]:5000".parse().unwrap();
    let (global, remote) = ("198.51.100.1:5000".parse().unwrap(), "203.0.113.9:80".parse().unwrap());
    let mapping = Mapping { proto: 6, local, global, remote, state: TcpState::Established, expires: Duration::ZERO };
    let deltas = vec![
        Delta::Upsert { mapping, ttl: Duration::from_secs(30) },
        Delta::Remove { proto: 17, local: "172.16.10.2:9".parse().unwrap(), remote },
    ];
    let wire = encode(&deltas);
    assert_eq!(decode(&wire[0]), Some(deltas));
    assert_eq!(decode(&wire[0][..wire[0].len() - 3]), None);
}
