use std::net::SocketAddrV4;

use packet::{Ipv4, Side};

use crate::acl::Acl;
use crate::clock::Clock;
use crate::pat::Pool;
use crate::reflect::{step, Dir, TcpState};
use crate::table::{Id, Mapping, Table};
use crate::timeouts::Timeouts;
use crate::Error;

#[derive(Clone, Debug, Default)]
pub struct Config {
    pub timeouts: Timeouts,
    pub acl: Acl,
    pub mss: Option<u16>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Verdict {
    Translated,
    Bypassed,
}

#[derive(Clone, Copy, Debug, Default)]
pub struct Stats {
    pub outbound: u64,
    pub inbound: u64,
    pub dropped: u64,
}

pub struct Nat<C: Clock> {
    cfg: Config,
    table: Table,
    pool: Pool,
    clock: C,
    stats: Stats,
}

impl<C: Clock> Nat<C> {
    // Put a translator together from its config, pool and clock.
    pub fn new(cfg: Config, pool: Pool, clock: C) -> Self {
        Self { cfg, table: Table::default(), pool, clock, stats: Stats::default() }
    }
    // Lent out the table for display.
    pub fn table(&self) -> &Table {
        &self.table
    }
    // Lent out the pool for display.
    pub fn pool(&self) -> &Pool {
        &self.pool
    }
    // Lent out the config for display.
    pub fn config(&self) -> &Config {
        &self.cfg
    }
    // Read the packet counters.
    pub fn stats(&self) -> Stats {
        self.stats
    }
    // Read the injected clock.
    pub fn now(&self) -> std::time::Duration {
        self.clock.now()
    }
    // Retired quiet flows using the injected clock.
    pub fn expire(&mut self) -> usize {
        self.table.expire(self.clock.now())
    }
    // Took replication deltas that were queued since the last call.
    pub fn drain_deltas(&mut self) -> Vec<crate::Delta> {
        self.table.drain_deltas(self.clock.now())
    }
    // Applied a peer's delta and taught the pool which address its host was given.
    pub fn apply(&mut self, delta: crate::Delta) {
        if let crate::Delta::Upsert { mapping, .. } = &delta {
            self.pool.adopt(*mapping.local.ip(), *mapping.global.ip());
        }
        self.table.apply(delta, self.clock.now());
    }
    // Counted a refusal and handed the reason back.
    fn reject<T>(&mut self, e: Error) -> Result<T, Error> {
        self.stats.dropped += 1;
        Err(e)
    }
    // Refreshed a flow's state and deadline and returned its mapping.
    fn refresh(&mut self, id: Id, dir: Dir, flags: Option<u8>) -> Result<Mapping, Error> {
        let m = self.table.get(id).cloned().ok_or(Error::NoMapping)?;
        let state = match flags {
            Some(f) => step(m.state, dir, f).ok_or(Error::Rejected)?,
            None => m.state,
        };
        let ttl = self.cfg.timeouts.pick(m.proto, m.remote.port(), state);
        self.table.touch(id, state, self.clock.now() + ttl);
        Ok(Mapping { state, ..m })
    }
    // Translated a packet leaving the inside, building a mapping when it started a new flow.
    pub fn outbound(&mut self, buf: &mut [u8]) -> Result<Verdict, Error> {
        let mut ip = Ipv4::parse(buf)?;
        let Some((sport, dport)) = ip.ports() else { return self.reject(Error::Unsupported) };
        let (proto, flags) = (ip.proto(), ip.tcp_flags());
        if !self.cfg.acl.translates(ip.src(), ip.dst()) {
            return Ok(Verdict::Bypassed);
        }
        let (local, remote) = (SocketAddrV4::new(ip.src(), sport), SocketAddrV4::new(ip.dst(), dport));
        let id = match self.table.by_local(proto, local, remote) {
            Some(id) => id,
            None if flags.is_some_and(|f| f & packet::l4::SYN == 0) => return self.reject(Error::NoMapping),
            None => {
                let Some(global) = self.pool.allocate(&self.table, proto, local, remote) else {
                    return self.reject(Error::PoolExhausted);
                };
                let m = Mapping { proto, local, global, remote, state: TcpState::SynSent, expires: self.clock.now() };
                self.table.insert(m)
            }
        };
        let m = self.refresh(id, Dir::Out, flags)?;
        ip.set_addr(Side::Src, *m.global.ip());
        ip.set_port(Side::Src, m.global.port());
        self.cfg.mss.map(|max| ip.clamp_mss(max));
        self.stats.outbound += 1;
        Ok(Verdict::Translated)
    }
    // Translated a packet coming back from the outside, only when a live flow already owned it.
    pub fn inbound(&mut self, buf: &mut [u8]) -> Result<Verdict, Error> {
        let mut ip = Ipv4::parse(buf)?;
        if !self.pool.contains(ip.dst()) {
            return self.reject(Error::NotForPool);
        }
        let Some((sport, dport)) = ip.ports() else { return self.reject(Error::Unsupported) };
        let (global, remote) = (SocketAddrV4::new(ip.dst(), dport), SocketAddrV4::new(ip.src(), sport));
        let Some(id) = self.table.by_global(ip.proto(), global, remote) else { return self.reject(Error::NoMapping) };
        let m = match self.refresh(id, Dir::In, ip.tcp_flags()) {
            Ok(m) => m,
            Err(e) => return self.reject(e),
        };
        ip.set_addr(Side::Dst, *m.local.ip());
        ip.set_port(Side::Dst, m.local.port());
        self.cfg.mss.map(|max| ip.clamp_mss(max));
        self.stats.inbound += 1;
        Ok(Verdict::Translated)
    }
}
