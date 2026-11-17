use std::str::FromStr;

use crate::cidr::Cidr;
use std::net::Ipv4Addr;

#[derive(Clone, Copy, Debug)]
pub struct Rule {
    pub permit: bool,
    pub src: Cidr,
    pub dst: Cidr,
}

impl FromStr for Rule {
    type Err = String;
    // Parsed a line like "deny 172.16.0.0/16 172.16.0.0/16" into a rule.
    fn from_str(s: &str) -> Result<Self, String> {
        let parts: Vec<&str> = s.split_whitespace().collect();
        let [verb, src, dst] = parts[..] else { return Err(format!("expected '<permit|deny> <src> <dst>' in {s:?}")) };
        let permit = match verb {
            "permit" => true,
            "deny" => false,
            _ => return Err(format!("unknown verb {verb}")),
        };
        Ok(Self { permit, src: src.parse()?, dst: dst.parse()? })
    }
}

#[derive(Clone, Debug)]
pub struct Acl(Vec<Rule>);

impl Acl {
    // Collected rules in the order they were written.
    pub fn new(rules: Vec<Rule>) -> Self {
        Self(rules)
    }
    // Walked the rules top down and let the first hit decide, with no hit meaning no translation.
    pub fn translates(&self, src: Ipv4Addr, dst: Ipv4Addr) -> bool {
        self.0.iter().find(|r| r.src.contains(src) && r.dst.contains(dst)).is_some_and(|r| r.permit)
    }
}

impl Default for Acl {
    // Permitted everything so an unconfigured NAT translated all it saw.
    fn default() -> Self {
        Self(vec![Rule { permit: true, src: Cidr::ANY, dst: Cidr::ANY }])
    }
}
