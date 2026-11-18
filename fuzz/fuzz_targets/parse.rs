#![no_main]
use libfuzzer_sys::fuzz_target;
use packet::{ipv6::Ipv6, Ipv4, Side};

fuzz_target!(|data: &[u8]| {
    let mut buf = data.to_vec();
    if let Ok(mut ip) = Ipv4::parse(&mut buf) {
        let _ = (ip.src(), ip.dst(), ip.ports(), ip.tcp_flags(), ip.header_ok(), ip.l4_ok());
        ip.clamp_mss(1400);
        ip.set_addr(Side::Src, [10, 0, 0, 1].into());
        ip.set_port(Side::Dst, 4242);
    }
    if let Ok(ip) = Ipv6::parse(data) {
        let _ = (ip.src(), ip.dst(), ip.l4_checksum_ok());
    }
});
