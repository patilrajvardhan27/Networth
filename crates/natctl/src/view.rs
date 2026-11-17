use nat_core::reflect::TcpState;
use nat_core::{Clock, Mapping, Nat};
use packet::ipv4::{ICMP, TCP, UDP};

pub struct Row {
    pub pro: &'static str,
    pub inside_global: String,
    pub inside_local: String,
    pub outside_local: String,
    pub outside_global: String,
    pub ttl: u64,
    pub state: &'static str,
}

// Named a protocol number the way the IOS show command does.
fn pro(p: u8) -> &'static str {
    match p {
        TCP => "tcp",
        UDP => "udp",
        ICMP => "icmp",
        _ => "---",
    }
}

// Named a flow's state, with plain UDP and ICMP flows simply called active.
fn state(m: &Mapping) -> &'static str {
    match (m.proto, m.state) {
        (TCP, TcpState::SynSent) => "syn-sent",
        (TCP, TcpState::Established) => "established",
        (TCP, TcpState::Closing) => "closing",
        _ => "active",
    }
}

// Turned the live table into display rows ordered by global endpoint.
pub fn rows<C: Clock>(nat: &Nat<C>) -> Vec<Row> {
    let now = nat.now();
    let mut list: Vec<&Mapping> = nat.table().iter().collect();
    list.sort_by_key(|m| (m.global, m.remote));
    list.into_iter()
        .map(|m| Row {
            pro: pro(m.proto),
            inside_global: m.global.to_string(),
            inside_local: m.local.to_string(),
            outside_local: m.remote.to_string(),
            outside_global: m.remote.to_string(),
            ttl: m.expires.saturating_sub(now).as_secs(),
            state: state(m),
        })
        .collect()
}

// Printed the table with the same five columns as `show ip nat translations`.
pub fn text<C: Clock>(nat: &Nat<C>) -> String {
    let mut out = format!(
        "{:<5}{:<24}{:<24}{:<24}{}\n",
        "Pro", "Inside global", "Inside local", "Outside local", "Outside global"
    );
    for r in rows(nat) {
        out += &format!(
            "{:<5}{:<24}{:<24}{:<24}{}\n",
            r.pro, r.inside_global, r.inside_local, r.outside_local, r.outside_global
        );
    }
    out
}

// Rendered the table as a JSON array for the dashboard.
pub fn translations_json<C: Clock>(nat: &Nat<C>) -> String {
    let items: Vec<String> = rows(nat)
        .iter()
        .map(|r| {
            format!(
                r#"{{"pro":"{}","inside_global":"{}","inside_local":"{}","outside_local":"{}","outside_global":"{}","ttl":{},"state":"{}"}}"#,
                r.pro, r.inside_global, r.inside_local, r.outside_local, r.outside_global, r.ttl, r.state
            )
        })
        .collect();
    format!("[{}]", items.join(","))
}

// Rendered the packet counters as JSON.
pub fn stats_json<C: Clock>(nat: &Nat<C>) -> String {
    let s = nat.stats();
    format!(
        r#"{{"active":{},"outbound":{},"inbound":{},"dropped":{}}}"#,
        nat.table().len(),
        s.outbound,
        s.inbound,
        s.dropped
    )
}

// Rendered the pool and timeout settings as JSON.
pub fn config_json<C: Clock>(nat: &Nat<C>, pool: &str) -> String {
    let t = nat.config().timeouts;
    let mss = nat.config().mss.map_or("null".into(), |m| m.to_string());
    format!(
        r#"{{"pool":"{pool}","pool_size":{},"mss":{mss},"timeouts":{{"tcp":{},"syn":{},"finrst":{},"udp":{},"dns":{},"icmp":{}}}}}"#,
        nat.pool().len(),
        t.tcp.as_secs(),
        t.syn.as_secs(),
        t.finrst.as_secs(),
        t.udp.as_secs(),
        t.dns.as_secs(),
        t.icmp.as_secs()
    )
}
