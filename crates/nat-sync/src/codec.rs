use std::net::{Ipv4Addr, SocketAddrV4};
use std::time::Duration;

use nat_core::reflect::TcpState;
use nat_core::{Delta, Mapping};

const MAGIC: [u8; 2] = *b"NS";
const UPSERT: u8 = 1;
const REMOVE: u8 = 2;
const MAX_ITEMS: usize = 40;

// Wrote a socket address as six bytes.
fn put(out: &mut Vec<u8>, a: SocketAddrV4) {
    out.extend(a.ip().octets());
    out.extend(a.port().to_be_bytes());
}

// Read a socket address back from six bytes.
fn take(b: &[u8]) -> SocketAddrV4 {
    SocketAddrV4::new(Ipv4Addr::new(b[0], b[1], b[2], b[3]), u16::from_be_bytes([b[4], b[5]]))
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
                        [m.local, m.global, m.remote].into_iter().for_each(|a| put(&mut out, a));
                        out.extend((ttl.as_millis() as u32).to_be_bytes());
                    }
                    Delta::Remove { proto, local, remote } => {
                        out.extend([REMOVE, *proto]);
                        put(&mut out, *local);
                        put(&mut out, *remote);
                    }
                }
            }
            out
        })
        .collect()
}

// Unpacked one datagram, returning nothing if it was damaged or foreign.
pub fn decode(b: &[u8]) -> Option<Vec<Delta>> {
    if b.len() < 4 || b[..2] != MAGIC {
        return None;
    }
    let (count, mut rest) = (usize::from(u16::from_be_bytes([b[2], b[3]])), &b[4..]);
    let mut out = Vec::with_capacity(count);
    for _ in 0..count {
        match *rest.first()? {
            UPSERT if rest.len() >= 3 + 18 + 4 => {
                let state = [TcpState::SynSent, TcpState::Established, TcpState::Closing][usize::from(rest[2]).min(2)];
                let ttl = u32::from_be_bytes(rest[21..25].try_into().ok()?);
                let mapping = Mapping {
                    proto: rest[1],
                    local: take(&rest[3..9]),
                    global: take(&rest[9..15]),
                    remote: take(&rest[15..21]),
                    state,
                    expires: Duration::ZERO,
                };
                out.push(Delta::Upsert { mapping, ttl: Duration::from_millis(u64::from(ttl)) });
                rest = &rest[25..];
            }
            REMOVE if rest.len() >= 14 => {
                out.push(Delta::Remove { proto: rest[1], local: take(&rest[2..8]), remote: take(&rest[8..14]) });
                rest = &rest[14..];
            }
            _ => return None,
        }
    }
    Some(out)
}
