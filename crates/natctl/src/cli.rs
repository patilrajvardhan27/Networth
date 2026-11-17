use std::net::{Ipv4Addr, SocketAddr};
use std::time::Duration;

use clap::{Args, Parser, Subcommand};
use nat_core::{Cidr, Rule, Timeouts};

#[derive(Parser)]
#[command(name = "natctl", version, about = "Userspace NAT/PAT router over TUN devices")]
pub struct Cli {
    #[command(subcommand)]
    pub cmd: Cmd,
}

#[derive(Subcommand)]
pub enum Cmd {
    /// Run the translator on two TUN devices
    Run(Box<RunArgs>),
    /// Print the translation table like `show ip nat translations`
    Show(ShowArgs),
}

#[derive(Args)]
pub struct ShowArgs {
    #[arg(long, default_value = "127.0.0.1:8080")]
    pub admin: String,
}

#[derive(Args)]
pub struct RunArgs {
    #[arg(long, default_value = "198.51.100.0/27")]
    pub pool: Cidr,
    /// First match wins, e.g. "deny 172.16.0.0/16 172.16.0.0/16"
    #[arg(long = "acl")]
    pub acl: Vec<Rule>,
    #[arg(long, default_value = "in0")]
    pub in_dev: String,
    #[arg(long, default_value = "10.255.0.1")]
    pub in_addr: Ipv4Addr,
    #[arg(long, default_value = "out0")]
    pub out_dev: String,
    #[arg(long, default_value = "10.255.1.1")]
    pub out_addr: Ipv4Addr,
    /// Clamp the TCP MSS on SYN packets to this ceiling
    #[arg(long)]
    pub mss: Option<u16>,
    #[arg(long, default_value = "127.0.0.1:8080")]
    pub admin: SocketAddr,
    /// Push table deltas to a standby at this address
    #[arg(long)]
    pub sync_peer: Option<SocketAddr>,
    /// Receive table deltas from the active on this address
    #[arg(long)]
    pub sync_listen: Option<SocketAddr>,
    #[arg(long, default_value_t = 86400)]
    pub tcp_timeout: u64,
    #[arg(long, default_value_t = 60)]
    pub syn_timeout: u64,
    #[arg(long, default_value_t = 60)]
    pub finrst_timeout: u64,
    #[arg(long, default_value_t = 300)]
    pub udp_timeout: u64,
    #[arg(long, default_value_t = 60)]
    pub dns_timeout: u64,
    #[arg(long, default_value_t = 60)]
    pub icmp_timeout: u64,
}

impl RunArgs {
    // Folded the timeout flags into the core's timeout table.
    pub fn timeouts(&self) -> Timeouts {
        let s = Duration::from_secs;
        Timeouts {
            tcp: s(self.tcp_timeout),
            syn: s(self.syn_timeout),
            finrst: s(self.finrst_timeout),
            udp: s(self.udp_timeout),
            dns: s(self.dns_timeout),
            icmp: s(self.icmp_timeout),
        }
    }
}
