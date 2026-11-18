use std::net::{Ipv4Addr, Ipv6Addr, SocketAddr, SocketAddrV4};
use std::time::Duration;

use nat_core::reflect::TcpState;
use nat_core::{Delta, Mapping};

const MAGIC: [u8; 2] = *b"NS";
const UPSERT: u8 = 1;
const REMOVE: u8 = 2;
const MAX_ITEMS: usize = 30;

// Wrote a socket address as a family byte, the address bytes and the port.
fn put(out: &mut Vec<u8>, a: SocketAddr) {
    match a {
        SocketAddr::V4(v) => out.extend([4].into_iter().chain(v.ip().octets())),
        SocketAddr::V6(v) => out.extend([6].into_iter().chain(v.ip().octets())),
    }
    out.extend(a.port().to_be_bytes());
}

struct Reader<'a>(&'a [u8]);

impl Reader<'_> {
    // Took the next n bytes, or nothing if the datagram ran short.
    fn take(&mut self, n: usize) -> Option<&[u8]> {
        let (head, rest) = self.0.split_at_checked(n)?;
        self.0 = rest;
        Some(head)
    }
    // Took one byte.
    fn byte(&mut self) -> Option<u8> {
        self.take(1).map(|b| b[0])
    }
    // Took a big-endian u16.
    fn u16(&mut self) -> Option<u16> {
        self.take(2).map(|b| u16::from_be_bytes([b[0], b[1]]))
    }
    // Took a big-endian u32.
    fn u32(&mut self) -> Option<u32> {
        self.take(4).map(|b| u32::from_be_bytes([b[0], b[1], b[2], b[3]]))
    }
    // Took a socket address of either family.
    fn addr(&mut self) -> Option<SocketAddr> {
        let ip = match self.byte()? {
            4 => Ipv4Addr::from(<[u8; 4]>::try_from(self.take(4)?).ok()?).into(),
            6 => Ipv6Addr::from(<[u8; 16]>::try_from(self.take(16)?).ok()?).into(),
            _ => return None,
        };
        Some(SocketAddr::new(ip, self.u16()?))
    }
    // Took a socket address and insisted it was IPv4.
    fn v4(&mut self) -> Option<SocketAddrV4> {
        match self.addr()? {
            SocketAddr::V4(a) => Some(a),
            SocketAddr::V6(_) => None,
        }
    }
}

// Packed deltas into datagrams small enough to dodge fragmentation.
pub fn encode(deltas: &[Delta]) -> Vec<Vec<u8>> {
    deltas
        .chunks(MAX_ITEMS)
        .map(|chunk| {
            let mut out = MAGIC.to_vec();
            out.extend((chunk.len() as u16).to_be_bytes());
            for d in chunk {
                match d {
                    Delta::Upsert { mapping: m, ttl } => {
                        out.extend([UPSERT, m.proto, m.state as u8]);
                        put(&mut out, m.local);
                        put(&mut out, SocketAddr::V4(m.global));
                        put(&mut out, SocketAddr::V4(m.remote));
                        out.extend((ttl.as_millis() as u32).to_be_bytes());
                    }
                    Delta::Remove { proto, local, remote } => {
                        out.extend([REMOVE, *proto]);
                        put(&mut out, *local);
                        put(&mut out, SocketAddr::V4(*remote));
                    }
                }
            }
            out
        })
        .collect()
}

// Unpacked one datagram, returning nothing if it was damaged or foreign.
pub fn decode(b: &[u8]) -> Option<Vec<Delta>> {
    let mut r = Reader(b);
    if r.take(2)? != MAGIC {
        return None;
    }
    let count = r.u16()?;
    let mut out = Vec::new();
    for _ in 0..count {
        match r.byte()? {
            UPSERT => {
                let (proto, state) = (r.byte()?, r.byte()?);
                let state = [TcpState::SynSent, TcpState::Established, TcpState::Closing][usize::from(state).min(2)];
                let mapping = Mapping {
                    proto,
                    local: r.addr()?,
                    global: r.v4()?,
                    remote: r.v4()?,
                    state,
                    expires: Duration::ZERO,
                };
                out.push(Delta::Upsert { mapping, ttl: Duration::from_millis(u64::from(r.u32()?)) });
            }
            REMOVE => out.push(Delta::Remove { proto: r.byte()?, local: r.addr()?, remote: r.v4()? }),
            _ => return None,
        }
    }
    Some(out)
}
