use std::io::{Read, Write};
use std::net::TcpStream;
use std::sync::Arc;

use clap::Parser;
use rustls::pki_types::{pem::PemObject, CertificateDer, ServerName};
use rustls::{ClientConfig, ClientConnection, RootCertStore, StreamOwned};

#[derive(Parser)]
#[command(name = "tlsprobe", about = "Handshake with a TLS server and print its HTTP status line")]
struct Args {
    addr: String,
    #[arg(long)]
    server_name: String,
    #[arg(long)]
    ca: String,
}

type Res<T> = Result<T, Box<dyn std::error::Error>>;

// Trusted one PEM certificate, connected, and read back the first response line.
fn probe(args: &Args) -> Res<String> {
    let mut roots = RootCertStore::empty();
    for cert in CertificateDer::pem_file_iter(&args.ca)? {
        roots.add(cert?)?;
    }
    let provider = Arc::new(rustls::crypto::ring::default_provider());
    let cfg = ClientConfig::builder_with_provider(provider)
        .with_safe_default_protocol_versions()?
        .with_root_certificates(roots)
        .with_no_client_auth();
    let conn = ClientConnection::new(Arc::new(cfg), ServerName::try_from(args.server_name.clone())?)?;
    let mut tls = StreamOwned::new(conn, TcpStream::connect(&args.addr)?);
    tls.write_all(b"GET / HTTP/1.0\r\n\r\n")?;
    let mut body = String::new();
    let _ = tls.read_to_string(&mut body);
    let version = tls.conn.protocol_version().map_or("?".into(), |v| format!("{v:?}"));
    Ok(format!("{version} {}", body.lines().next().unwrap_or("(no response)")))
}

// Ran the probe and exited non-zero if the handshake failed.
fn main() {
    match probe(&Args::parse()) {
        Ok(line) => println!("tls ok: {line}"),
        Err(e) => {
            eprintln!("tls failed: {e}");
            std::process::exit(1);
        }
    }
}
