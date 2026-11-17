use std::net::SocketAddr;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;
use std::time::Duration;

use tokio::net::UdpSocket;

// Wrote a hand-made A query for a.test with the given id.
fn query(id: u16) -> Vec<u8> {
    let mut q = id.to_be_bytes().to_vec();
    q.extend([1, 0, 0, 1, 0, 0, 0, 0, 0, 0, 1, b'a', 4, b't', b'e', b's', b't', 0, 0, 1, 0, 1]);
    q
}

// Turned a query into a reply carrying one A record with a 60 second TTL.
fn reply(q: &[u8]) -> Vec<u8> {
    let mut r = q.to_vec();
    r[2..4].copy_from_slice(&[0x81, 0x80]);
    r[6..8].copy_from_slice(&[0, 1]);
    r.extend([0xc0, 0x0c, 0, 1, 0, 1, 0, 0, 0, 60, 0, 4, 192, 0, 2, 53]);
    r
}

// Bound a socket on loopback and handed back both it and its address.
async fn bind() -> (Arc<UdpSocket>, SocketAddr) {
    let s = Arc::new(UdpSocket::bind("127.0.0.1:0").await.unwrap());
    let a = s.local_addr().unwrap();
    (s, a)
}

// Asked twice and expected the upstream to hear about it only once.
#[tokio::test]
async fn second_answer_comes_from_the_cache() {
    let (up, up_addr) = bind().await;
    let hits = Arc::new(AtomicUsize::new(0));
    let counter = hits.clone();
    tokio::spawn(async move {
        let mut buf = [0u8; 512];
        loop {
            let (n, from) = up.recv_from(&mut buf).await.unwrap();
            counter.fetch_add(1, Ordering::SeqCst);
            up.send_to(&reply(&buf[..n]), from).await.unwrap();
        }
    });
    let (fwd, fwd_addr) = bind().await;
    tokio::spawn(dnsfwd::serve(fwd, up_addr));

    let client = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    for id in [0x1111u16, 0x2222] {
        client.send_to(&query(id), fwd_addr).await.unwrap();
        let mut buf = [0u8; 512];
        let n = tokio::time::timeout(Duration::from_secs(2), client.recv(&mut buf)).await.unwrap().unwrap();
        assert_eq!(&buf[..2], &id.to_be_bytes());
        assert_eq!(&buf[n - 4..n], &[192, 0, 2, 53]);
    }
    assert_eq!(hits.load(Ordering::SeqCst), 1);
}
