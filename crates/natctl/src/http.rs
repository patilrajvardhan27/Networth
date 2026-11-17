use std::sync::{Arc, Mutex};

use nat_core::{Nat, SystemClock};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};

use crate::view;

pub type Shared = Arc<Mutex<Nat<SystemClock>>>;

const ASSETS: [(&str, &str, &[u8]); 6] = [
    ("/", "text/html", include_bytes!("../../../dashboard/index.html")),
    ("/style.css", "text/css", include_bytes!("../../../dashboard/style.css")),
    ("/app.js", "text/javascript", include_bytes!("../../../dashboard/app.js")),
    ("/pixel.js", "text/javascript", include_bytes!("../../../dashboard/pixel.js")),
    ("/fonts/jersey-10.woff2", "font/woff2", include_bytes!("../../../dashboard/fonts/jersey-10.woff2")),
    ("/fonts/manrope.woff2", "font/woff2", include_bytes!("../../../dashboard/fonts/manrope.woff2")),
];

// Picked a response for a path, from the embedded assets or the live table.
fn route(path: &str, nat: &Shared, pool: &str) -> (u16, &'static str, Vec<u8>) {
    if let Some((_, mime, body)) = ASSETS.iter().find(|(p, ..)| *p == path) {
        return (200, mime, body.to_vec());
    }
    let n = nat.lock().unwrap();
    match path {
        "/api/translations" => (200, "application/json", view::translations_json(&n).into_bytes()),
        "/api/stats" => (200, "application/json", view::stats_json(&n).into_bytes()),
        "/api/config" => (200, "application/json", view::config_json(&n, pool).into_bytes()),
        "/api/show" => (200, "text/plain", view::text(&n).into_bytes()),
        _ => (404, "text/plain", b"not found".to_vec()),
    }
}

// Answered one request on a connection and closed it.
async fn handle(mut sock: TcpStream, nat: Shared, pool: String) -> std::io::Result<()> {
    let mut buf = [0u8; 2048];
    let n = sock.read(&mut buf).await?;
    let head = String::from_utf8_lossy(&buf[..n]);
    let path = head.split_whitespace().nth(1).unwrap_or("/").split('?').next().unwrap_or("/");
    let (code, mime, body) = route(path, &nat, &pool);
    let reason = if code == 200 { "OK" } else { "Not Found" };
    let header = format!(
        "HTTP/1.1 {code} {reason}\r\nContent-Type: {mime}\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
        body.len()
    );
    sock.write_all(header.as_bytes()).await?;
    sock.write_all(&body).await
}

// Served the dashboard and read-only API until the listener failed.
pub async fn serve(addr: std::net::SocketAddr, nat: Shared, pool: String) -> std::io::Result<()> {
    let listener = TcpListener::bind(addr).await?;
    tracing::info!(%addr, "admin console listening");
    loop {
        let (sock, _) = listener.accept().await?;
        let (nat, pool) = (nat.clone(), pool.clone());
        tokio::spawn(async move {
            if let Err(e) = handle(sock, nat, pool).await {
                tracing::debug!(error = %e, "admin request failed");
            }
        });
    }
}

// Fetched a path from a running instance and returned its body text.
pub async fn get(addr: &str, path: &str) -> std::io::Result<String> {
    let mut sock = TcpStream::connect(addr).await?;
    sock.write_all(format!("GET {path} HTTP/1.1\r\nHost: {addr}\r\nConnection: close\r\n\r\n").as_bytes()).await?;
    let mut raw = Vec::new();
    sock.read_to_end(&mut raw).await?;
    let text = String::from_utf8_lossy(&raw);
    Ok(text.split_once("\r\n\r\n").map_or_else(String::new, |(_, body)| body.to_string()))
}
