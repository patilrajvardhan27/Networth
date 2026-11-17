use std::net::Ipv4Addr;

use criterion::{criterion_group, criterion_main, Criterion, Throughput};
use nat_core::{Config, ManualClock, Nat, Pool};
use packet::build::{tcp4, udp4};
use packet::l4::{ACK, SYN};
use packet::Ipv4;

const SERVER: Ipv4Addr = Ipv4Addr::new(203, 0, 113, 9);

// Timed outbound and inbound translation on an established flow, one packet per iteration.
fn translate(c: &mut Criterion) {
    let mut nat = Nat::new(Config::default(), Pool::new("198.51.100.0/27".parse().unwrap()), ManualClock::default());
    let host = Ipv4Addr::new(172, 16, 10, 2);
    let mut syn = tcp4(host, 5000, SERVER, 80, SYN, None, b"");
    nat.outbound(&mut syn).unwrap();
    let global = Ipv4::parse(&mut syn).unwrap().src();
    let mut synack = tcp4(SERVER, 80, global, 5000, SYN | ACK, None, b"");
    nat.inbound(&mut synack).unwrap();

    let out = tcp4(host, 5000, SERVER, 80, ACK, None, &[0u8; 512]);
    let back = tcp4(SERVER, 80, global, 5000, ACK, None, &[0u8; 512]);
    let udp = udp4(host, 6000, SERVER, 53, &[0u8; 64]);
    let mut buf = vec![0u8; 2048];

    let mut g = c.benchmark_group("nat");
    g.throughput(Throughput::Elements(1));
    g.bench_function("tcp_outbound_established", |b| {
        b.iter(|| {
            buf[..out.len()].copy_from_slice(&out);
            nat.outbound(&mut buf[..out.len()]).unwrap()
        })
    });
    g.bench_function("tcp_inbound_established", |b| {
        b.iter(|| {
            buf[..back.len()].copy_from_slice(&back);
            nat.inbound(&mut buf[..back.len()]).unwrap()
        })
    });
    g.bench_function("udp_outbound_established", |b| {
        b.iter(|| {
            buf[..udp.len()].copy_from_slice(&udp);
            nat.outbound(&mut buf[..udp.len()]).unwrap()
        })
    });
    g.finish();
}

criterion_group!(benches, translate);
criterion_main!(benches);
