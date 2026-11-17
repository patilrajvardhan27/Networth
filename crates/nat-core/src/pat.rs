use std::collections::HashMap;
use std::net::{Ipv4Addr, SocketAddrV4};
use std::ops::RangeInclusive;

use crate::cidr::Cidr;
use crate::table::Table;

pub struct Pool {
    addrs: Vec<Ipv4Addr>,
    paired: HashMap<Ipv4Addr, usize>,
    next: usize,
}

// Picked the port block a source port belonged to so it stayed in its own neighbourhood.
fn class(port: u16) -> RangeInclusive<u16> {
    match port {
        0..=511 => 1..=511,
        512..=1023 => 512..=1023,
        _ => 1024..=65535,
    }
}

impl Pool {
    // Opened a pool over every usable host in a prefix.
    pub fn new(cidr: Cidr) -> Self {
        Self { addrs: cidr.hosts(), paired: HashMap::new(), next: 0 }
    }
    // Asked whether an address belonged to the pool.
    pub fn contains(&self, a: Ipv4Addr) -> bool {
        self.addrs.contains(&a)
    }
    // Counted the addresses on offer.
    pub fn len(&self) -> usize {
        self.addrs.len()
    }
    // Asked whether the pool had no addresses at all.
    pub fn is_empty(&self) -> bool {
        self.addrs.is_empty()
    }
    // Remembered which pool address an inside host had been given, as a standby learned from its peer.
    pub fn adopt(&mut self, local: Ipv4Addr, global: Ipv4Addr) {
        if let Some(i) = self.addrs.iter().position(|a| *a == global) {
            self.paired.insert(local, i);
        }
    }
    // Looked for a free port beside the wanted one, keeping it if it was free and otherwise taking the next open slot.
    fn pick_port(table: &Table, proto: u8, addr: Ipv4Addr, want: u16, remote: SocketAddrV4) -> Option<u16> {
        let free = |p: u16| table.is_free(proto, SocketAddrV4::new(addr, p), remote);
        if free(want) {
            return Some(want);
        }
        let range = class(want);
        let (lo, span) = (u32::from(*range.start()), u32::from(*range.end()) - u32::from(*range.start()) + 1);
        let from = u32::from(want).saturating_sub(lo);
        (1..span).map(|i| (lo + (from + i) % span) as u16).find(|&p| free(p))
    }
    // Chose a global endpoint for a new flow, sticking each inside host to one pool address when it could.
    pub fn allocate(
        &mut self,
        table: &Table,
        proto: u8,
        local: SocketAddrV4,
        remote: SocketAddrV4,
    ) -> Option<SocketAddrV4> {
        if self.addrs.is_empty() {
            return None;
        }
        let start = *self.paired.entry(*local.ip()).or_insert_with(|| {
            let i = self.next;
            self.next = (i + 1) % self.addrs.len();
            i
        });
        for i in 0..self.addrs.len() {
            let idx = (start + i) % self.addrs.len();
            if let Some(port) = Self::pick_port(table, proto, self.addrs[idx], local.port(), remote) {
                self.paired.insert(*local.ip(), idx);
                return Some(SocketAddrV4::new(self.addrs[idx], port));
            }
        }
        None
    }
}
