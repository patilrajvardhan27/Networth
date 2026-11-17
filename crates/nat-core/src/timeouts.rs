use std::time::Duration;

use crate::reflect::TcpState;
use packet::ipv4::{TCP, UDP};

#[derive(Clone, Copy, Debug)]
pub struct Timeouts {
    pub tcp: Duration,
    pub syn: Duration,
    pub finrst: Duration,
    pub udp: Duration,
    pub dns: Duration,
    pub icmp: Duration,
}

impl Default for Timeouts {
    // Started from the IOS style defaults the lab ran with.
    fn default() -> Self {
        let s = Duration::from_secs;
        Self { tcp: s(86400), syn: s(60), finrst: s(60), udp: s(300), dns: s(60), icmp: s(60) }
    }
}

impl Timeouts {
    // Chose how long a flow could sit quiet given its protocol, remote port and TCP state.
    pub fn pick(&self, proto: u8, remote_port: u16, state: TcpState) -> Duration {
        match (proto, state) {
            (TCP, TcpState::SynSent) => self.syn,
            (TCP, TcpState::Closing) => self.finrst,
            (TCP, _) => self.tcp,
            (UDP, _) if remote_port == 53 => self.dns,
            (UDP, _) => self.udp,
            _ => self.icmp,
        }
    }
}
