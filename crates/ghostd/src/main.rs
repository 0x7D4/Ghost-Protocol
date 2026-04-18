//! Ghost-Protocol daemon entry point.

use anyhow::Result;
use clap::Parser;
use tracing::info;
use tracing_subscriber::EnvFilter;

use ghost_common::SOCKET_PATH;
use ghostd::broadcaster::EventBroadcaster;

/// Ghost-Protocol Moving Target Defense daemon.
#[derive(Parser, Debug)]
#[command(name = "ghostd", version, about = "Moving Target Defense daemon")]
struct Cli {
    /// Path to the configuration file.
    #[arg(short, long, default_value = "/etc/ghost-protocol/config.toml")]
    config: String,

    /// Network interface to attach eBPF programs to.
    #[arg(short, long)]
    interface: Option<String>,

    /// Enable verbose logging.
    #[arg(short, long)]
    verbose: bool,
}

#[tokio::main]
async fn main() -> Result<()> {
    let cli = Cli::parse();

    // Initialize tracing subscriber
    let filter = if cli.verbose {
        EnvFilter::new("debug")
    } else {
        EnvFilter::new("info")
    };
    tracing_subscriber::fmt().with_env_filter(filter).init();

    info!("ghostd starting with config: {}", cli.config);

    // Initialize broadcaster
    let broadcaster = EventBroadcaster::new();
    broadcaster.clone().start_server().await?;

    // TODO: Load configuration from file
    // TODO: Load and attach eBPF programs via ebpf_loader (pass broadcaster)
    // TODO: Start tarpit engine (pass broadcaster)

    // Keep service alive
    tokio::signal::ctrl_c().await?;
    info!("ghostd shutting down");
    let _ = std::fs::remove_file(SOCKET_PATH);
    Ok(())
}
