use crate::Error;

pub const FIN: u8 = 0x01;
pub const SYN: u8 = 0x02;
pub const RST: u8 = 0x04;
pub const ACK: u8 = 0x10;
pub const ECHO_REPLY: u8 = 0;
pub const ECHO_REQUEST: u8 = 8;

// Read a big-endian u16 from two spots in a header.
fn be16(b: &[u8], at: usize) -> u16 {
    u16::from_be_bytes([b[at], b[at + 1]])
}

pub struct Tcp<'a>(pub &'a [u8]);

impl<'a> Tcp<'a> {
    // Looked over a TCP header and made sure its data offset fit the segment.
    pub fn parse(b: &'a [u8]) -> Result<Self, Error> {
        if b.len() < 20 || usize::from(b[12] >> 4) * 4 < 20 || usize::from(b[12] >> 4) * 4 > b.len() {
            return Err(Error::Truncated);
        }
        Ok(Self(b))
    }
    // Pulled the source port out of the header.
    pub fn src(&self) -> u16 {
        be16(self.0, 0)
    }
    // Pulled the destination port out of the header.
    pub fn dst(&self) -> u16 {
        be16(self.0, 2)
    }
    // Read the sequence number.
    pub fn seq(&self) -> u32 {
        u32::from_be_bytes([self.0[4], self.0[5], self.0[6], self.0[7]])
    }
    // Read the control flag byte.
    pub fn flags(&self) -> u8 {
        self.0[13]
    }
    // Worked out the header length in bytes from the data offset.
    pub fn header_len(&self) -> usize {
        usize::from(self.0[12] >> 4) * 4
    }
    // Handed back the raw option bytes that trail the fixed header.
    pub fn options(&self) -> &'a [u8] {
        &self.0[20..self.header_len()]
    }
}

pub struct Udp<'a>(pub &'a [u8]);

impl<'a> Udp<'a> {
    // Looked over a UDP header and its length field.
    pub fn parse(b: &'a [u8]) -> Result<Self, Error> {
        if b.len() < 8 || usize::from(be16(b, 4)) < 8 {
            return Err(Error::Truncated);
        }
        Ok(Self(b))
    }
    // Pulled the source port out of the header.
    pub fn src(&self) -> u16 {
        be16(self.0, 0)
    }
    // Pulled the destination port out of the header.
    pub fn dst(&self) -> u16 {
        be16(self.0, 2)
    }
    // Read the checksum field, where zero meant none was sent.
    pub fn checksum(&self) -> u16 {
        be16(self.0, 6)
    }
}

pub struct Icmp<'a>(pub &'a [u8]);

impl<'a> Icmp<'a> {
    // Looked over the fixed eight bytes of an ICMP header.
    pub fn parse(b: &'a [u8]) -> Result<Self, Error> {
        if b.len() < 8 {
            return Err(Error::Truncated);
        }
        Ok(Self(b))
    }
    // Read the message type byte.
    pub fn kind(&self) -> u8 {
        self.0[0]
    }
    // Read the echo identifier that stood in for a port.
    pub fn id(&self) -> u16 {
        be16(self.0, 4)
    }
}
