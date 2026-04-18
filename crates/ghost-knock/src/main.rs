//! TOTP-based port derivation CLI for Ghost-Protocol.

use anyhow::{Context, Result};
use clap::Parser;
use ghost_knock::{connect_with_retry, proxy_stream, KnockConfig};

/// TOTP port-derivation CLI and SSH ProxyCommand.
#[derive(Parser, Debug)]
#[command(name = "ghost-knock", version, about = "TOTP port-derivation CLI")]
struct Cli {
    /// Hostname or IP of the Ghost-Protocol daemon.
    #[arg(value_name = "HOST")]
    host: String,

    /// Base port for derivation.
    #[arg(value_name = "BASE_PORT")]
    base_port: u16,

    /// Port range for derivation (e.g. 1000).
    #[arg(value_name = "RANGE")]
    range: u16,

    /// Base32-encoded TOTP shared secret.
    #[arg(value_name = "SECRET", env = "GHOST_TOTP_SECRET")]
    secret: String,

    /// Connect timeout in seconds.
    #[arg(short, long, default_value = "5")]
    timeout: u64,
}

#[tokio::main]
async fn main() -> Result<()> {
    tracing_subscriber::fmt()
        .with_writer(std::io::stderr)
        .init();
        
    let cli = Cli::parse();

    // Decode secret
    let secret_bytes = base32::decode(base32::Alphabet::RFC4648 { padding: true }, &cli.secret)
        .context("Failed to decode Base32 secret. Ensure it follows RFC4648 padding rules.")?;

    let config = KnockConfig {
        host: cli.host,
        base_port: cli.base_port,
        range: cli.range,
        timeout: cli.timeout,
    };

    let stream = connect_with_retry(&config, &secret_bytes).await?;
    proxy_stream(stream).await?;

    Ok(())
}
