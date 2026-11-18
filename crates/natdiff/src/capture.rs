use std::fs::File;
use std::io::{self, BufReader, Read};
use std::path::Path;
use std::time::Duration;

use pcap_file::pcap::PcapReader;
use pcap_file::pcapng::{Block, PcapNgReader};

const PCAPNG_MAGIC: [u8; 4] = [0x0a, 0x0d, 0x0d, 0x0a];

pub struct Frame {
    pub at: Duration,
    pub ip: Vec<u8>,
}

// Wrapped a parser failure as an I/O error.
fn bad(e: impl std::fmt::Display) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, e.to_string())
}

// Stripped an Ethernet header and any VLAN tags, keeping only IPv4 payloads.
fn strip(frame: &[u8]) -> Option<Vec<u8>> {
    let mut at = 12;
    while frame.get(at..at + 2)? == [0x81, 0x00] {
        at += 4;
    }
    (frame.get(at..at + 2)? == [0x08, 0x00]).then(|| frame[at + 2..].to_vec())
}

// Read every IPv4 packet from a classic pcap or pcapng file in capture order.
pub fn read(path: &Path) -> io::Result<Vec<Frame>> {
    let mut magic = [0u8; 4];
    File::open(path)?.read_exact(&mut magic)?;
    let file = BufReader::new(File::open(path)?);
    let mut out = Vec::new();
    if magic == PCAPNG_MAGIC {
        let mut reader = PcapNgReader::new(file).map_err(bad)?;
        while let Some(block) = reader.next_block() {
            if let Block::EnhancedPacket(p) = block.map_err(bad)? {
                out.extend(strip(&p.data).map(|ip| Frame { at: p.timestamp, ip }));
            }
        }
    } else {
        let mut reader = PcapReader::new(file).map_err(bad)?;
        while let Some(packet) = reader.next_packet() {
            let p = packet.map_err(bad)?;
            out.extend(strip(&p.data).map(|ip| Frame { at: p.timestamp, ip }));
        }
    }
    Ok(out)
}
