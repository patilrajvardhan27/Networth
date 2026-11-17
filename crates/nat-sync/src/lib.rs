//! Active/standby replication of NAT mappings over UDP.

pub mod codec;

use std::net::SocketAddr;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use nat_core::{Clock, Nat};
use tokio::net::UdpSocket;

const RESYNC_EVERY: u32 = 25;

// Sent changed mappings to the standby on a steady beat and replayed the whole table now and then.
pub async fn replicate<C: Clock + Send + 'static>(
    nat: Arc<Mutex<Nat<C>>>,
    sock: UdpSocket,
    peer: SocketAddr,
    every: Duration,
) -> std::io::Result<()> {
    let mut tick = tokio::time::interval(every);
    let mut beats = 0u32;
    loop {
        tick.tick().await;
        beats = beats.wrapping_add(1);
        let deltas = {
            let mut n = nat.lock().unwrap();
            if beats % RESYNC_EVERY == 0 {
                n.table_mut().mark_all_dirty();
            }
            n.drain_deltas()
        };
        for datagram in codec::encode(&deltas) {
            sock.send_to(&datagram, peer).await?;
        }
    }
}

// Listened for the active's datagrams and folded each delta into the local table.
pub async fn receive<C: Clock + Send + 'static>(nat: Arc<Mutex<Nat<C>>>, sock: UdpSocket) -> std::io::Result<()> {
    let mut buf = vec![0u8; 2048];
    loop {
        let (n, from) = sock.recv_from(&mut buf).await?;
        match codec::decode(&buf[..n]) {
            Some(deltas) => {
                let mut guard = nat.lock().unwrap();
                deltas.into_iter().for_each(|d| guard.apply(d));
            }
            None => tracing::warn!(%from, "ignored a malformed sync datagram"),
        }
    }
}
