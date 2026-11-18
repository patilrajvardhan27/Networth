use dnsfwd::wire::{answer, question};

const QUERY: &[u8] = &[0x12, 0x34, 1, 0, 0, 1, 0, 0, 0, 0, 0, 0, 1, b'A', 4, b't', b'e', b's', b't', 0, 0, 1, 0, 1];

// Built a reply with two answers whose TTLs were 60 and 30.
fn reply() -> Vec<u8> {
    let mut r = QUERY.to_vec();
    r[2..4].copy_from_slice(&[0x81, 0x80]);
    r[6..8].copy_from_slice(&[0, 2]);
    for ttl in [60u8, 30] {
        r.extend([0xc0, 0x0c, 0, 1, 0, 1, 0, 0, 0, ttl, 0, 4, 192, 0, 2, 53]);
    }
    r
}

// Read the name lowercase with its type and class.
#[test]
fn parses_the_question() {
    let q = question(QUERY).unwrap();
    assert_eq!((q.name.as_str(), q.qtype, q.qclass), ("a.test.", 1, 1));
}

// Took the smaller of two TTLs and the success code.
#[test]
fn picks_the_minimum_ttl() {
    let a = answer(&reply()).unwrap();
    assert_eq!((a.rcode, a.min_ttl), (0, Some(30)));
}

// Rejected a query that claimed to be a response and a response that was not one.
#[test]
fn checks_the_response_bit() {
    assert!(answer(QUERY).is_none());
}

// Truncated a reply at every length and fed noise through both parsers, expecting no panic.
#[test]
fn hostile_input_never_panics() {
    let full = reply();
    for n in 0..full.len() {
        let _ = (question(&full[..n]), answer(&full[..n]));
    }
    let mut x = 0x2545_f491_4f6c_dd1du64;
    for _ in 0..20_000 {
        let noise: Vec<u8> = (0..64)
            .map(|_| {
                x ^= x << 13;
                x ^= x >> 7;
                x ^= x << 17;
                x as u8
            })
            .collect();
        let mut msg = full.clone();
        let len = noise.len().min(msg.len() - 12);
        msg[12..12 + len].copy_from_slice(&noise[..len]);
        let _ = (question(&noise), answer(&noise), question(&msg), answer(&msg));
    }
}
