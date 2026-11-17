use std::sync::{Arc, Mutex};
use std::time::Duration;

use nat_core::reflect::Dir;
use nat_core::{Acl, Config, Nat, Pool, SystemClock, Verdict};
use tokio::net::UdpSocket;
use tokio::task::JoinSet;
use tun_rs::{AsyncDevice, DeviceBuilder};

use crate::cli::RunArgs;
use crate::http::{self, Shared};

type Res<T> = Result<T, Box<dyn std::error::Error + Send + Sync>>;

// Opened a TUN device with a /30 link address so the kernel could route to it.
fn tun(name: &str, addr: std::net::Ipv4Addr) -> Res<Arc<AsyncDevice>> {
    Ok(Arc::new(DeviceBuilder::new().name(name).ipv4(addr, 30, None).mtu(1500).build_async()?))
}

// Carried packets from one device through the translator and onto the other.
async fn pump(from: Arc<AsyncDevice>, to: Arc<AsyncDevice>, nat: Shared, dir: Dir) -> Res<()> {
    let mut buf = vec![0u8; 2048];
    loop {
        let n = from.recv(&mut buf).await?;
        let verdict = {
            let mut nat = nat.lock().unwrap();
            match dir {
                Dir::Out => nat.outbound(&mut buf[..n]),
                Dir::In => nat.inbound(&mut buf[..n]),
            }
        };
        match verdict {
            Ok(Verdict::Translated | Verdict::Bypassed) => {
                to.send(&buf[..n]).await?;
            }
            Err(e) => tracing::debug!(?dir, error = %e, "dropped a packet"),
        }
    }
}

// Swept expired flows out of the table once a second.
async fn sweep(nat: Shared) -> Res<()> {
    let mut tick = tokio::time::interval(Duration::from_secs(1));
    loop {
        tick.tick().await;
        let gone = nat.lock().unwrap().expire();
        if gone > 0 {
            tracing::debug!(gone, "expired flows");
        }
    }
}

// Wired the devices, translator, sync and console together and ran until one stopped or Ctrl-C came.
pub async fn run(args: RunArgs) -> Res<()> {
    let acl = if args.acl.is_empty() { Acl::default() } else { Acl::new(args.acl.clone()) };
    let cfg = Config { timeouts: args.timeouts(), acl, mss: args.mss };
    let nat: Shared = Arc::new(Mutex::new(Nat::new(cfg, Pool::new(args.pool), SystemClock::new())));
    let (inside, outside) = (tun(&args.in_dev, args.in_addr)?, tun(&args.out_dev, args.out_addr)?);
    tracing::info!(pool = %args.pool, inside = %args.in_dev, outside = %args.out_dev, "translator up");

    let mut tasks: JoinSet<Res<()>> = JoinSet::new();
    tasks.spawn(pump(inside.clone(), outside.clone(), nat.clone(), Dir::Out));
    tasks.spawn(pump(outside, inside, nat.clone(), Dir::In));
    tasks.spawn(sweep(nat.clone()));
    let (admin, pool) = (args.admin, args.pool.to_string());
    tasks.spawn({
        let nat = nat.clone();
        async move { Ok(http::serve(admin, nat, pool).await?) }
    });
    if let Some(peer) = args.sync_peer {
        let sock = UdpSocket::bind("0.0.0.0:0").await?;
        let nat = nat.clone();
        tasks.spawn(async move { Ok(nat_sync::replicate(nat, sock, peer, Duration::from_millis(200)).await?) });
    }
    if let Some(listen) = args.sync_listen {
        let sock = UdpSocket::bind(listen).await?;
        tasks.spawn(async move { Ok(nat_sync::receive(nat, sock).await?) });
    }
    tokio::select! {
        _ = tokio::signal::ctrl_c() => Ok(()),
        done = tasks.join_next() => done.map_or(Ok(()), |r| r?),
    }
}
