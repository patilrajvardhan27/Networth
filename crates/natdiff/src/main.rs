use std::path::PathBuf;
use std::process::ExitCode;

use clap::Parser;
use nat_core::{Cidr, Rule};
use natdiff::{capture, compare};

#[derive(Parser)]
#[command(name = "natdiff", version, about = "Check a real NAT's output against a replay of its inside traffic")]
struct Args {
    #[arg(long, help = "Capture taken on the inside of the router (pcap or pcapng)")]
    inside: PathBuf,
    #[arg(long, help = "Capture taken on the outside of the router")]
    outside: PathBuf,
    #[arg(long, help = "The router's NAT pool")]
    pool: Cidr,
    #[arg(long = "acl", help = "Rule such as \"deny 172.16.0.0/16 172.16.0.0/16\", first match wins")]
    acl: Vec<Rule>,
    #[arg(long, help = "MSS ceiling the router clamps to")]
    mss: Option<u16>,
}

// Read both captures, compared them and printed a summary, failing when the structures disagree.
fn main() -> ExitCode {
    let args = Args::parse();
    let read = |p: &PathBuf| capture::read(p).map_err(|e| format!("{}: {e}", p.display()));
    let (inside, outside) = match (read(&args.inside), read(&args.outside)) {
        (Ok(a), Ok(b)) => (a, b),
        (a, b) => {
            [a.err(), b.err()].into_iter().flatten().for_each(|e| eprintln!("natdiff: {e}"));
            return ExitCode::from(2);
        }
    };
    let opts = compare::Options { pool: args.pool, acl: args.acl, mss: args.mss };
    let r = compare::compare(&inside, &outside, &opts);
    println!(
        "inside packets {}, matched {}, unmatched {}, not replayed {}, flows {}",
        r.inside_packets, r.matched, r.unmatched, r.not_replayed, r.flows
    );
    r.violations.iter().for_each(|v| println!("VIOLATION {v}"));
    if r.violations.is_empty() {
        ExitCode::SUCCESS
    } else {
        ExitCode::FAILURE
    }
}
