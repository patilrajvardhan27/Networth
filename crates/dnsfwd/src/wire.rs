pub struct Question {
    pub name: String,
    pub qtype: u16,
    pub qclass: u16,
}

pub struct Answer {
    pub rcode: u8,
    pub min_ttl: Option<u32>,
}

// Read a big-endian u16 at an offset, if the bytes were there.
fn u16_at(m: &[u8], at: usize) -> Option<u16> {
    Some(u16::from_be_bytes([*m.get(at)?, *m.get(at + 1)?]))
}

// Stepped over a name, whether spelled out in labels or ended by a compression pointer, and returned where it stopped.
fn skip_name(m: &[u8], mut at: usize) -> Option<usize> {
    loop {
        let len = *m.get(at)?;
        match len & 0xc0 {
            0 if len == 0 => return Some(at + 1),
            0 => at += 1 + usize::from(len),
            0xc0 => return m.get(at + 1).map(|_| at + 2),
            _ => return None,
        }
    }
}

// Read a plain label-only name as a lowercase dotted string.
fn read_name(m: &[u8], mut at: usize) -> Option<(String, usize)> {
    let mut name = String::new();
    loop {
        let len = usize::from(*m.get(at)?);
        if len == 0 {
            return Some((name, at + 1));
        }
        if len & 0xc0 != 0 {
            return None;
        }
        let label = m.get(at + 1..at + 1 + len)?;
        name.push_str(&String::from_utf8_lossy(label).to_ascii_lowercase());
        name.push('.');
        at += 1 + len;
    }
}

// Pulled the first question out of a message, refusing anything without exactly the shape a client sends.
pub fn question(m: &[u8]) -> Option<Question> {
    if m.len() < 12 || u16_at(m, 4)? == 0 {
        return None;
    }
    let (name, end) = read_name(m, 12)?;
    Some(Question { name, qtype: u16_at(m, end)?, qclass: u16_at(m, end + 2)? })
}

// Read the response code and the smallest answer TTL from a reply, stopping at the first record that did not fit.
pub fn answer(m: &[u8]) -> Option<Answer> {
    if m.len() < 12 || m[2] & 0x80 == 0 {
        return None;
    }
    let mut at = 12;
    for _ in 0..u16_at(m, 4)? {
        at = skip_name(m, at)? + 4;
    }
    let mut min_ttl: Option<u32> = None;
    for _ in 0..u16_at(m, 6)? {
        at = skip_name(m, at)?;
        let ttl = u32::from_be_bytes([*m.get(at + 4)?, *m.get(at + 5)?, *m.get(at + 6)?, *m.get(at + 7)?]);
        min_ttl = Some(min_ttl.map_or(ttl, |t| t.min(ttl)));
        at += 10 + usize::from(u16_at(m, at + 8)?);
        if at > m.len() {
            return None;
        }
    }
    Some(Answer { rcode: m[3] & 0x0f, min_ttl })
}
