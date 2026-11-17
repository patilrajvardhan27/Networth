use std::net::SocketAddr;
use std::sync::Arc;

use clap::Parser;
use tokio::net::UdpSocket;

#[derive(Parser)]
#[command(name = "dnsfwd", version, about = "UDP DNS forwarder with a TTL cache")]
struct Args {
    #[arg(long, default_value = "0.0.0.0:5353")]
    listen: SocketAddr,
    #[arg(long, default_value = "1.1.1.1:53")]
    upstream: SocketAddr,
}

// Bound the listening socket and forwarded until the process was stopped.
#[tokio::main]
async fn main() -> std::io::Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::from_default_env().add_directive("dnsfwd=info".parse().unwrap()),
        )
        .init();
    let args = Args::parse();
    tracing::info!(listen = %args.listen, upstream = %args.upstream, "forwarding");
    dnsfwd::serve(Arc::new(UdpSocket::bind(args.listen).await?), args.upstream).await
}
