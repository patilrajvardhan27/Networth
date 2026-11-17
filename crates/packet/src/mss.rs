use crate::ipv4::{Ipv4, TCP};
use crate::l4::{Tcp, SYN};

impl Ipv4<'_> {
    // Clamped the MSS option on a SYN down to the ceiling and patched the checksum in place.
    pub fn clamp_mss(&mut self, max: u16) -> bool {
        if self.proto() != TCP {
            return false;
        }
        let Ok(tcp) = Tcp::parse(self.l4()) else { return false };
        if tcp.flags() & SYN == 0 {
            return false;
        }
        let (mut at, end) = (self.hl + 20, self.hl + tcp.header_len());
        while at < end {
            match self.buf[at] {
                0 => break,
                1 => at += 1,
                kind => {
                    let len = usize::from(*self.buf.get(at + 1).unwrap_or(&0));
                    if len < 2 || at + len > end {
                        break;
                    }
                    if kind == 2 && len == 4 {
                        let old = [self.buf[at + 2], self.buf[at + 3]];
                        if u16::from_be_bytes(old) <= max {
                            return false;
                        }
                        self.patch_l4(&old, &max.to_be_bytes(), false);
                        self.buf[at + 2..at + 4].copy_from_slice(&max.to_be_bytes());
                        return true;
                    }
                    at += len;
                }
            }
        }
        false
    }
}
