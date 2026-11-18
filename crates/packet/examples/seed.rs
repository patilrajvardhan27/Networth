use std::net::Ipv4Addr;

use packet::build::{icmp4, tcp4, udp4};
use packet::l4::SYN;

// Wrote one well-formed packet per protocol into a corpus folder for the fuzzer to mutate.
fn main() -> std::io::Result<()> {
    let dir = std::env::args().nth(1).unwrap_or_else(|| "fuzz/corpus/parse".into());
    let (a, b) = (Ipv4Addr::new(172, 16, 10, 2), Ipv4Addr::new(203, 0, 113, 9));
    let seeds = [
        ("udp", udp4(a, 5000, b, 53, b"query")),
        ("tcp-syn", tcp4(a, 6000, b, 443, SYN, Some(1460), b"")),
        ("icmp", icmp4(a, b, 7, false)),
    ];
    for (name, bytes) in seeds {
        std::fs::write(format!("{dir}/{name}.bin"), bytes)?;
    }
    Ok(())
}
