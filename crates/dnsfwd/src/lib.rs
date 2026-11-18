// Gathered a forwarder that answered repeat questions from a TTL cache.

pub mod wire;

use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use tokio::net::UdpSocket;

const MAX_TTL: u32 = 300;
const UPSTREAM_WAIT: Duration = Duration::from_secs(2);

type Key = (String, u16, u16);
type Cache = Arc<Mutex<HashMap<Key, (Vec<u8>, Instant)>>>;

// Asked the upstream resolver once and waited a short while for its reply.
async fn ask(upstream: SocketAddr, query: &[u8]) -> Option<Vec<u8>> {
    let sock = UdpSocket::bind("0.0.0.0:0").await.ok()?;
    sock.send_to(query, upstream).await.ok()?;
    let mut buf = vec![0u8; 4096];
    let n = tokio::time::timeout(UPSTREAM_WAIT, sock.recv(&mut buf)).await.ok()?.ok()?;
    buf.truncate(n);
    Some(buf)
}

// Answered from the cache when it could, otherwise forwarded and remembered the reply for its shortest TTL.
async fn answer(query: &[u8], upstream: SocketAddr, cache: &Cache) -> Option<Vec<u8>> {
    let q = wire::question(query)?;
    let k: Key = (q.name, q.qtype, q.qclass);
    let cached = cache.lock().unwrap().get(&k).filter(|(_, until)| *until > Instant::now()).map(|(b, _)| b.clone());
    if let Some(mut hit) = cached {
        hit[..2].copy_from_slice(&query[..2]);
        tracing::info!(name = %k.0, "cache hit");
        return Some(hit);
    }
    let reply = ask(upstream, query).await?;
    let parsed = wire::answer(&reply).filter(|_| reply[..2] == query[..2])?;
    let ttl = parsed.min_ttl.unwrap_or(0).min(MAX_TTL);
    if ttl > 0 && parsed.rcode == 0 {
        cache.lock().unwrap().insert(k.clone(), (reply.clone(), Instant::now() + Duration::from_secs(u64::from(ttl))));
    }
    tracing::info!(name = %k.0, ttl, "forwarded upstream");
    Some(reply)
}

// Served queries on a socket forever, one task per question.
pub async fn serve(sock: Arc<UdpSocket>, upstream: SocketAddr) -> std::io::Result<()> {
    let cache: Cache = Cache::default();
    let mut buf = vec![0u8; 1500];
    loop {
        let (n, from) = sock.recv_from(&mut buf).await?;
        let (query, sock, cache) = (buf[..n].to_vec(), sock.clone(), cache.clone());
        tokio::spawn(async move {
            if let Some(reply) = answer(&query, upstream, &cache).await {
                let _ = sock.send_to(&reply, from).await;
            }
        });
    }
}
