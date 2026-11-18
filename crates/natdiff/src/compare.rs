use std::collections::{HashMap, VecDeque};
use std::net::SocketAddrV4;

use nat_core::{Acl, Cidr, Config, ManualClock, Nat, Pool, Rule, Verdict};
use packet::ipv4::{ICMP, TCP, UDP};
use packet::Ipv4;

use crate::capture::Frame;

const MAX_NOTES: usize = 50;

pub struct Options {
    pub pool: Cidr,
    pub acl: Vec<Rule>,
    pub mss: Option<u16>,
}

#[derive(Default)]
pub struct Report {
    pub inside_packets: usize,
    pub matched: usize,
    pub unmatched: usize,
    pub not_replayed: usize,
    pub flows: usize,
    pub violations: Vec<String>,
}

#[derive(PartialEq, Eq, Hash)]
struct Fp(u8, u16, u64);

#[derive(Clone, Copy, PartialEq, Eq, Hash)]
struct Flow(u8, SocketAddrV4, SocketAddrV4);

type Maps = (HashMap<Flow, SocketAddrV4>, HashMap<(u8, SocketAddrV4, SocketAddrV4), Flow>);

struct View {
    flow: Flow,
    ok: bool,
}

// Hashed some bytes with FNV-1a so packets could be paired without storing them.
fn fnv(parts: &[&[u8]]) -> u64 {
    parts
        .iter()
        .flat_map(|p| p.iter())
        .fold(0xcbf2_9ce4_8422_2325, |h, b| (h ^ u64::from(*b)).wrapping_mul(0x100_0000_01b3))
}

// Fingerprinted a packet by fields a NAT never touches, so the same packet matched across captures.
fn fingerprint(ip: &Ipv4) -> Option<Fp> {
    let (_, dport) = ip.ports()?;
    let l4 = ip.l4();
    let tag = match ip.proto() {
        TCP => fnv(&[&l4[4..8], &l4[13..14], &l4[usize::from(l4[12] >> 4) * 4..]]),
        UDP => fnv(&[&l4[8..]]),
        ICMP => fnv(&[&l4[6..]]),
        _ => return None,
    };
    Some(Fp(ip.proto(), dport, tag))
}

// Read the flow identity and checksum health out of a packet copy.
fn view(bytes: &[u8]) -> Option<View> {
    let mut copy = bytes.to_vec();
    let ip = Ipv4::parse(&mut copy).ok()?;
    let (sport, dport) = ip.ports()?;
    let flow = Flow(ip.proto(), SocketAddrV4::new(ip.src(), sport), SocketAddrV4::new(ip.dst(), dport));
    Some(View { flow, ok: ip.header_ok() && ip.l4_ok() })
}

struct Notes(Vec<String>, usize);

impl Notes {
    // Recorded a violation, keeping only the first few in full.
    fn add(&mut self, text: String) {
        self.1 += 1;
        if self.0.len() < MAX_NOTES {
            self.0.push(text);
        }
    }
}

// Tracked a flow to global mapping and its reverse, noting any change or clash.
fn track(maps: &mut Maps, who: &str, idx: usize, inside: Flow, out: Flow, notes: &mut Notes) {
    let global = out.1;
    if let Some(prev) = maps.0.insert(inside, global) {
        if prev != global {
            notes.add(format!("packet {idx}: {who} changed the mapping of {} from {prev} to {global}", inside.1));
        }
    }
    if let Some(other) = maps.1.insert((inside.0, global, inside.2), inside) {
        if other != inside {
            notes.add(format!("packet {idx}: {who} gave {global} to both {} and {}", other.1, inside.1));
        }
    }
}

// Replayed the inside capture through the NAT and compared its structure with what the router put on the outside.
pub fn compare(inside: &[Frame], outside: &[Frame], opts: &Options) -> Report {
    let clock = ManualClock::default();
    let acl = if opts.acl.is_empty() { Acl::default() } else { Acl::new(opts.acl.clone()) };
    let mut nat = Nat::new(Config { acl, mss: opts.mss, ..Config::default() }, Pool::new(opts.pool), clock.clone());
    let pool = Pool::new(opts.pool);

    let mut queue: HashMap<Fp, VecDeque<&Frame>> = HashMap::new();
    for f in outside {
        let mut copy = f.ip.clone();
        if let Some(fp) = Ipv4::parse(&mut copy).ok().and_then(|ip| fingerprint(&ip)) {
            queue.entry(fp).or_default().push_back(f);
        }
    }

    let mut report = Report { inside_packets: inside.len(), ..Report::default() };
    let (mut notes, mut ours_maps, mut ce_maps) = (Notes(Vec::new(), 0), Maps::default(), Maps::default());
    let mut last = inside.first().map_or_else(Default::default, |f| f.at);
    for (idx, frame) in inside.iter().enumerate() {
        clock.advance(frame.at.saturating_sub(last));
        last = frame.at.max(last);
        nat.expire();
        let before = view(&frame.ip);
        let mut copy = frame.ip.clone();
        let fp = Ipv4::parse(&mut copy).ok().and_then(|ip| fingerprint(&ip));
        let (Some(before), Some(fp)) = (before, fp) else {
            report.not_replayed += 1;
            continue;
        };
        let verdict = nat.outbound(&mut copy);
        let Some(ce) = queue.get_mut(&fp).and_then(|q| q.pop_front()) else {
            report.unmatched += 1;
            continue;
        };
        let (Ok(verdict), Some(theirs), Some(ours)) = (verdict, view(&ce.ip), view(&copy)) else {
            report.not_replayed += 1;
            continue;
        };
        report.matched += 1;
        let (Flow(_, _, odst), Flow(_, csrc, cdst)) = (ours.flow, theirs.flow);
        if !ours.ok || !theirs.ok {
            notes.add(format!("packet {idx}: invalid checksum (ours ok: {}, router ok: {})", ours.ok, theirs.ok));
        }
        if cdst != before.flow.2 || odst != before.flow.2 {
            notes.add(format!(
                "packet {idx}: destination changed, inside sent to {} but router sent to {cdst}",
                before.flow.2
            ));
        }
        match verdict {
            Verdict::Bypassed if csrc != before.flow.1 => notes.add(format!(
                "packet {idx}: router translated a flow the ACL exempts ({} became {csrc})",
                before.flow.1
            )),
            Verdict::Translated if csrc == before.flow.1 => {
                notes.add(format!("packet {idx}: router left {} untranslated", before.flow.1))
            }
            Verdict::Translated if !pool.contains(*csrc.ip()) => {
                notes.add(format!("packet {idx}: router source {csrc} is outside the pool {}", opts.pool))
            }
            Verdict::Translated => {
                track(&mut ours_maps, "replay", idx, before.flow, ours.flow, &mut notes);
                track(&mut ce_maps, "router", idx, before.flow, theirs.flow, &mut notes);
            }
            Verdict::Bypassed => {}
        }
    }
    report.flows = ours_maps.0.len();
    report.violations = notes.0;
    if notes.1 > MAX_NOTES {
        report.violations.push(format!("{} more violations not shown", notes.1 - MAX_NOTES));
    }
    report
}
