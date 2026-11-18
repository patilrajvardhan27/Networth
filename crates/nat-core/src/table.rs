use std::collections::{BTreeSet, HashMap, HashSet};
use std::net::{SocketAddr, SocketAddrV4};
use std::time::Duration;

use crate::reflect::TcpState;

pub type Id = u64;
type Fwd = (u8, SocketAddr, SocketAddrV4);
type Rev = (u8, SocketAddrV4, SocketAddrV4);

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Mapping {
    pub proto: u8,
    pub local: SocketAddr,
    pub global: SocketAddrV4,
    pub remote: SocketAddrV4,
    pub state: TcpState,
    pub expires: Duration,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Delta {
    Upsert { mapping: Mapping, ttl: Duration },
    Remove { proto: u8, local: SocketAddr, remote: SocketAddrV4 },
}

#[derive(Default)]
pub struct Table {
    next: Id,
    items: HashMap<Id, Mapping>,
    fwd: HashMap<Fwd, Id>,
    rev: HashMap<Rev, Id>,
    deadlines: BTreeSet<(Duration, Id)>,
    dirty: HashSet<Id>,
    removed: Vec<Delta>,
}

impl Table {
    // Counted the live mappings.
    pub fn len(&self) -> usize {
        self.items.len()
    }
    // Asked whether the table held nothing at all.
    pub fn is_empty(&self) -> bool {
        self.items.is_empty()
    }
    // Looked a flow up from the inside view.
    pub fn by_local(&self, proto: u8, local: SocketAddr, remote: SocketAddrV4) -> Option<Id> {
        self.fwd.get(&(proto, local, remote)).copied()
    }
    // Looked a flow up from the outside view.
    pub fn by_global(&self, proto: u8, global: SocketAddrV4, remote: SocketAddrV4) -> Option<Id> {
        self.rev.get(&(proto, global, remote)).copied()
    }
    // Fetched a mapping by id.
    pub fn get(&self, id: Id) -> Option<&Mapping> {
        self.items.get(&id)
    }
    // Checked that no live flow already held a global endpoint toward this remote.
    pub fn is_free(&self, proto: u8, global: SocketAddrV4, remote: SocketAddrV4) -> bool {
        !self.rev.contains_key(&(proto, global, remote))
    }
    // Walked every mapping for display and sync.
    pub fn iter(&self) -> impl Iterator<Item = &Mapping> {
        self.items.values()
    }
    // Added a mapping, replacing any older one for the same flow.
    pub fn insert(&mut self, m: Mapping) -> Id {
        if let Some(old) = self.by_local(m.proto, m.local, m.remote) {
            self.drop_item(old);
        }
        self.next += 1;
        let id = self.next;
        self.fwd.insert((m.proto, m.local, m.remote), id);
        self.rev.insert((m.proto, m.global, m.remote), id);
        self.deadlines.insert((m.expires, id));
        self.items.insert(id, m);
        self.dirty.insert(id);
        id
    }
    // Refreshed a flow's state and deadline after traffic touched it.
    pub fn touch(&mut self, id: Id, state: TcpState, expires: Duration) {
        let Some(m) = self.items.get_mut(&id) else { return };
        self.deadlines.remove(&(m.expires, id));
        (m.state, m.expires) = (state, expires);
        self.deadlines.insert((expires, id));
        self.dirty.insert(id);
    }
    // Forgot a mapping from every index without recording it as removed.
    fn drop_item(&mut self, id: Id) -> Option<Mapping> {
        let m = self.items.remove(&id)?;
        self.fwd.remove(&(m.proto, m.local, m.remote));
        self.rev.remove(&(m.proto, m.global, m.remote));
        self.deadlines.remove(&(m.expires, id));
        self.dirty.remove(&id);
        Some(m)
    }
    // Retired every flow whose deadline had passed and returned how many went.
    pub fn expire(&mut self, now: Duration) -> usize {
        let due: Vec<Id> = self.deadlines.range(..=(now, Id::MAX)).map(|&(_, id)| id).collect();
        for &id in &due {
            if let Some(m) = self.drop_item(id) {
                self.removed.push(Delta::Remove { proto: m.proto, local: m.local, remote: m.remote });
            }
        }
        due.len()
    }
    // Queued every mapping to be sent again, so a late standby could catch up.
    pub fn mark_all_dirty(&mut self) {
        self.dirty.extend(self.items.keys());
    }
    // Gathered everything that changed since the last call into replication messages.
    pub fn drain_deltas(&mut self, now: Duration) -> Vec<Delta> {
        let mut out: Vec<Delta> = std::mem::take(&mut self.removed);
        for id in self.dirty.drain() {
            if let Some(m) = self.items.get(&id) {
                out.push(Delta::Upsert { mapping: m.clone(), ttl: m.expires.saturating_sub(now) });
            }
        }
        out
    }
    // Applied a delta from the active peer without echoing it back out.
    pub fn apply(&mut self, delta: Delta, now: Duration) {
        match delta {
            Delta::Upsert { mapping, ttl } => {
                let id = self.insert(Mapping { expires: now + ttl, ..mapping });
                self.dirty.remove(&id);
            }
            Delta::Remove { proto, local, remote } => {
                if let Some(id) = self.by_local(proto, local, remote) {
                    self.drop_item(id);
                }
            }
        }
    }
}
