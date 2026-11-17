mod cli;
mod engine;
mod http;
mod view;

use clap::Parser;
use cli::{Cli, Cmd};

// Parsed the command line and handed off to either the engine or the show client.
#[tokio::main]
async fn main() {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::from_default_env().add_directive("natctl=info".parse().unwrap()),
        )
        .init();
    let result = match Cli::parse().cmd {
        Cmd::Run(args) => engine::run(*args).await,
        Cmd::Show(a) => http::get(&a.admin, "/api/show").await.map(|t| print!("{t}")).map_err(Into::into),
    };
    if let Err(e) = result {
        eprintln!("natctl: {e}");
        std::process::exit(1);
    }
}
