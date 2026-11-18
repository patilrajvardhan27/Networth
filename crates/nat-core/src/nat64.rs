use std::net::{SocketAddr, SocketAddrV4, SocketAddrV6};

use packet::ipv4::ICMP;
use packet::ipv6::Ipv6;
use packet::l4::ICMPV6;
use packet::nat64::{embed, extract, to_v4, to_v6};
use packet::Ipv4;

use crate::clock::Clock;
use crate::nat::{Nat, Verdict};
use crate::reflect::Dir;
use crate::Error;

impl<C: Clock> Nat<C> {
    // Translated one packet in either family, swapping the buffer when NAT64 changed its shape.
    pub fn process(&mut self, dir: Dir, buf: &mut Vec<u8>) -> Result<Verdict, Error> {
        match (dir, buf.first().map(|b| b >> 4)) {
            (Dir::Out, Some(4)) => self.outbound(buf),
            (Dir::Out, Some(6)) => self.outbound64(buf),
            (Dir::In, Some(4)) => self.inbound_any(buf),
            _ => self.reject(Error::Malformed(packet::Error::Version)),
        }
    }
    // Turned an IPv6 client packet bound for the NAT64 prefix into IPv4 from a pool address.
    fn outbound64(&mut self, buf: &mut Vec<u8>) -> Result<Verdict, Error> {
        let Some(prefix) = self.cfg.nat64 else { return self.reject(Error::Unsupported) };
        let (local, remote, proto, flags) = {
            let ip = Ipv6::parse(buf)?;
            let (Some(dst), Some((sport, dport))) = (extract(prefix, ip.dst()), ip.ports()) else {
                return self.reject(Error::Unsupported);
            };
            let proto = if ip.next_header() == ICMPV6 { ICMP } else { ip.next_header() };
            let local = SocketAddr::V6(SocketAddrV6::new(ip.src(), sport, 0, 0));
            (local, SocketAddrV4::new(dst, dport), proto, ip.tcp_flags())
        };
        let m = self.flow_out(proto, local, remote, flags)?;
        let mut out = match to_v4(buf, *m.global.ip(), m.global.port(), *remote.ip()) {
            Ok(out) => out,
            Err(e) => return self.reject(e.into()),
        };
        if let Some(max) = self.cfg.mss {
            Ipv4::parse(&mut out)?.clamp_mss(max);
        }
        *buf = out;
        self.stats.outbound += 1;
        Ok(Verdict::Translated)
    }
    // Translated a returning IPv4 packet, back into IPv6 when its flow began on the IPv6 side.
    fn inbound_any(&mut self, buf: &mut Vec<u8>) -> Result<Verdict, Error> {
        let mut ip = Ipv4::parse(buf)?;
        let m = self.flow_in(&ip)?;
        match m.local {
            SocketAddr::V4(local) => self.rewrite_in(&mut ip, local),
            SocketAddr::V6(local) => {
                let Some(prefix) = self.cfg.nat64 else { return self.reject(Error::Unsupported) };
                match to_v6(ip.bytes(), embed(prefix, *m.remote.ip()), *local.ip(), local.port()) {
                    Ok(out) => *buf = out,
                    Err(e) => return self.reject(e.into()),
                }
                self.stats.inbound += 1;
            }
        }
        Ok(Verdict::Translated)
    }
}
