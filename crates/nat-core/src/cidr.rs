use std::fmt;
use std::net::Ipv4Addr;
use std::str::FromStr;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Cidr {
    pub addr: Ipv4Addr,
    pub len: u8,
}

impl Cidr {
    pub const ANY: Cidr = Cidr { addr: Ipv4Addr::UNSPECIFIED, len: 0 };

    // Worked out the netmask bits for the prefix length.
    fn mask(&self) -> u32 {
        u32::MAX.checked_shl(32 - u32::from(self.len)).unwrap_or(0)
    }
    // Asked whether an address fell inside the prefix.
    pub fn contains(&self, a: Ipv4Addr) -> bool {
        u32::from(a) & self.mask() == u32::from(self.addr) & self.mask()
    }
    // Listed the usable hosts, dropping network and broadcast on anything bigger than a /31.
    pub fn hosts(&self) -> Vec<Ipv4Addr> {
        let base = u32::from(self.addr) & self.mask();
        let size = 1u64 << (32 - self.len);
        let (skip, take) = if size > 2 { (1, size - 2) } else { (0, size) };
        (0..take).map(|i| Ipv4Addr::from(base + (skip + i) as u32)).collect()
    }
}

impl FromStr for Cidr {
    type Err = String;
    // Parsed an address with a prefix, or the word any, into a Cidr.
    fn from_str(s: &str) -> Result<Self, String> {
        if s == "any" {
            return Ok(Self::ANY);
        }
        let (a, l) = s.split_once('/').unwrap_or((s, "32"));
        let addr = a.parse().map_err(|_| format!("bad address in {s}"))?;
        let len: u8 = l.parse().map_err(|_| format!("bad prefix in {s}"))?;
        if len > 32 {
            return Err(format!("prefix too long in {s}"));
        }
        Ok(Self { addr, len })
    }
}

impl fmt::Display for Cidr {
    // Printed the prefix back the way it was typed.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}/{}", self.addr, self.len)
    }
}
