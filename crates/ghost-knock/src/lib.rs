//! Library for TOTP-based port derivation and proxying.

use anyhow::Result;
use std::time::{SystemTime, UNIX_EPOCH};
use tokio::io::{self, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio::time::{sleep, Duration};
use totp_lite::{totp, Sha1};
use tracing::{info, warn};

/// Configuration for the knock process.
pub struct KnockConfig {
    pub host: String,
    pub base_port: u16,
    pub range: u16,
    pub timeout: u64,
}

/// Attempt to connect to the derived port with boundary-aware retry.
pub async fn connect_with_retry(config: &KnockConfig, secret: &[u8]) -> Result<TcpStream> {
    let mut retries = 0;
    loop {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs();

        let port = derive_port(secret, config.base_port, config.range, now);
        let addr = format!("{}:{}", config.host, port);
        
        info!("Attempting connection to {} (retry={})", addr, retries);
        
        match tokio::time::timeout(Duration::from_secs(config.timeout), TcpStream::connect(&addr)).await {
            Ok(Ok(stream)) => {
                info!("Connected to {}!", addr);
                return Ok(stream);
            }
            Ok(Err(e)) => {
                let err_desc = e.to_string();
                warn!("Connection to {} failed: {}", addr, err_desc);
                if retries == 0 && is_near_boundary() {
                    retry_wait(&mut retries).await;
                    continue;
                }
                return Err(anyhow::anyhow!("Failed to connect to {}: {}", addr, err_desc));
            }
            Err(_) => {
                warn!("Connection to {} timed out", addr);
                if retries == 0 && is_near_boundary() {
                    retry_wait(&mut retries).await;
                    continue;
                }
                return Err(anyhow::anyhow!("Connection to {} timed out", addr));
            }
        }
    }
}

/// Bi-directional proxy between stdin/stdout and the provided TCP stream.
pub async fn proxy_stream(stream: TcpStream) -> Result<()> {
    let (mut socket_read, mut socket_write) = stream.into_split();
    let mut stdin = io::stdin();
    let mut stdout = io::stdout();

    let client_to_server = async {
        io::copy(&mut stdin, &mut socket_write).await?;
        socket_write.shutdown().await?;
        Result::<()>::Ok(())
    };

    let server_to_client = async {
        io::copy(&mut socket_read, &mut stdout).await?;
        Result::<()>::Ok(())
    };

    let (res_c2s, res_s2c) = tokio::join!(client_to_server, server_to_client);
    res_c2s?;
    res_s2c?;
    Ok(())
}

/// Deterministically derives a port number from a secret and timestamp.
pub fn derive_port(secret: &[u8], base_port: u16, range: u16, time: u64) -> u16 {
    let code_str = totp::<Sha1>(secret, time);
    let code: u32 = code_str.parse().unwrap_or(0);
    base_port + ((code % (range as u32)) as u16)
}

fn is_near_boundary() -> bool {
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs();
    let remaining = 30 - (now % 30);
    remaining <= 5
}

async fn retry_wait(retries: &mut i32) {
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs();
    let remaining = 30 - (now % 30);
    warn!("Failure occurred within 5s of TOTP boundary ({}s left). Waiting for next step...", remaining);
    sleep(Duration::from_secs(remaining + 1)).await;
    *retries += 1;
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_derive_port_determinism() {
        let secret = b"testsecret123456";
        let base = 10000;
        let range = 1000;

        let p1 = derive_port(secret, base, range, 1600000000);
        let p4 = derive_port(secret, base, range, 1600000010);
        assert_eq!(p1, p4, "Within same 30s window, port must be identical");

        let p3 = derive_port(secret, base, range, 1600000030);
        assert_ne!(p1, p3, "Port should change across TOTP steps");
    }
}
