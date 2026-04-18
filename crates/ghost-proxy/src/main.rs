use anyhow::{Context, Result};
use ghost_proxy::{current_timestamp, decode_secret, derive_port, ProxyConfig, ProxyEntry, validate_config};
use std::fs;
use std::sync::Arc;
use tokio::io::{self, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tracing::{error, info};

#[tokio::main]
async fn main() -> Result<()> {
    tracing_subscriber::fmt()
        .with_writer(std::io::stderr)
        .init();

    let config_path = std::env::args()
        .nth(1)
        .unwrap_or_else(|| "proxy.toml".to_string());
    
    let config_content = fs::read_to_string(&config_path)
        .with_context(|| format!("Failed to read config file: {}", config_path))?;
    
    let config: ProxyConfig = toml::from_str(&config_content)
        .context("Failed to parse config TOML")?;
        
    validate_config(&config).context("Configuration validation failed")?;

    let mut handles = Vec::new();

    for entry in &config.proxies {
        let entry = Arc::new(entry.clone());
        
        // Spawn proxy listener
        let proxy_entry = entry.clone();
        handles.push(tokio::spawn(async move {
            if let Err(e) = run_proxy(proxy_entry).await {
                error!("Proxy on port {} failed: {}", 0, e);
            }
        }));

        // Spawn health check
        let health_port = entry.stable_port + 1;
        handles.push(tokio::spawn(async move {
            if let Err(e) = run_health_check(health_port).await {
                error!("Health check on port {} failed: {}", health_port, e);
            }
        }));
    }

    info!("Ghost-Proxy started with {} proxy entries", config.proxies.len());
    
    for handle in handles {
        let _ = handle.await;
    }

    Ok(())
}

async fn run_proxy(entry: Arc<ProxyEntry>) -> Result<()> {
    let listener = TcpListener::bind(format!("0.0.0.0:{}", entry.stable_port))
        .await
        .with_context(|| format!("Failed to bind stable port {}", entry.stable_port))?;
    
    info!("Stable proxy listening on port {}", entry.stable_port);
    
    let secret = decode_secret(&entry.secret)?;

    loop {
        let (client_stream, addr) = listener.accept().await?;
        let entry_inner = entry.clone();
        let secret_inner = secret.clone();

        tokio::spawn(async move {
            if let Err(e) = handle_connection(client_stream, entry_inner, &secret_inner).await {
                error!("Error handling connection from {}: {}", addr, e);
            }
        });
    }
}

async fn handle_connection(mut client_stream: TcpStream, entry: Arc<ProxyEntry>, secret: &[u8]) -> Result<()> {
    let now = current_timestamp();
    let target_port = derive_port(secret, entry.base_port, entry.range, now);
    let target_addr = format!("127.0.0.1:{}", target_port);

    info!("Forwarding new connection to {}", target_addr);

    let mut target_stream = TcpStream::connect(&target_addr).await
        .with_context(|| format!("Failed to connect to target {}", target_addr))?;

    let (mut client_read, mut client_write) = client_stream.split();
    let (mut target_read, mut target_write) = target_stream.split();

    let client_to_target = io::copy(&mut client_read, &mut target_write);
    let target_to_client = io::copy(&mut target_read, &mut client_write);

    tokio::try_join!(client_to_target, target_to_client)?;

    Ok(())
}

async fn run_health_check(port: u16) -> Result<()> {
    let listener = TcpListener::bind(format!("0.0.0.0:{}", port)).await?;
    info!("Health check listening on port {}", port);

    loop {
        let (mut stream, _) = listener.accept().await?;
        tokio::spawn(async move {
            let response = "HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\nOK";
            let _ = stream.write_all(response.as_bytes()).await;
            let _ = stream.flush().await;
            let _ = stream.shutdown().await;
        });
    }
}
