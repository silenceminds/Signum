mod config;
mod edge;
mod http_filter;
mod scanner;
mod smpv2;
mod tls;

use clap::Parser;
use config::EdgeConfig;
use rand::RngCore;
use std::path::PathBuf;
use tracing_subscriber::EnvFilter;

#[derive(Parser, Debug)]
#[command(name = "signum-edge", about = "Signum public edge reverse proxy & SMPv2 server")]
struct Args {
    #[arg(short, long, default_value = "signum-edge.toml")]
    config: PathBuf,
    /// Generate a cryptographically random 512-bit (128-hex) Signum access key and exit
    #[arg(long)]
    gen_key_512: bool,
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    tracing_subscriber::fmt()
        .with_env_filter(EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("info")))
        .init();

    let args = Args::parse();
    if args.gen_key_512 {
        let mut key = [0u8; 64];
        rand::thread_rng().fill_bytes(&mut key);
        println!("{}", hex::encode(key));
        return Ok(());
    }
    let cfg = EdgeConfig::load(&args.config)?;
    edge::run_edge(cfg).await
}
