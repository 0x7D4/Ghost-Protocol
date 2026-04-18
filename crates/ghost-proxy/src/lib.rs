use anyhow::Result;
use serde::{Deserialize, Serialize};
use std::time::{SystemTime, UNIX_EPOCH};
use totp_lite::{totp, Sha1};

#[derive(Debug, Deserialize, Serialize, Clone)]
pub struct ProxyConfig {
    pub proxies: Vec<ProxyEntry>,
}

#[derive(Debug, Deserialize, Serialize, Clone)]
pub struct ProxyEntry {
    pub stable_port: u16,
    pub base_port: u16,
    pub range: u16,
    pub secret: String,
}

pub fn derive_port(secret: &[u8], base_port: u16, range: u16, time: u64) -> u16 {
    let code_str = totp::<Sha1>(secret, time);
    let code: u32 = code_str.parse().unwrap_or(0);
    base_port + ((code % (range as u32)) as u16)
}

pub fn current_timestamp() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs()
}

pub fn decode_secret(secret: &str) -> Result<Vec<u8>> {
    base32::decode(base32::Alphabet::RFC4648 { padding: true }, secret)
        .ok_or_else(|| anyhow::anyhow!("Failed to decode Base32 secret"))
}

pub fn validate_config(config: &ProxyConfig) -> Result<()> {
    for entry in &config.proxies {
        // 1. base_port + range <= 65535
        if entry.base_port as u32 + entry.range as u32 > 65535 {
            anyhow::bail!(
                "Invalid port range for entry on stable_port {}: base_port {} + range {} exceeds 65535",
                entry.stable_port, entry.base_port, entry.range
            );
        }

        // 2. stable_port not in range base_port..base_port+range
        let range_end = entry.base_port + entry.range;
        if entry.stable_port >= entry.base_port && entry.stable_port <= range_end {
            anyhow::bail!(
                "Collision detected: stable_port {} is inside its own TOTP derivation range {}-{}",
                entry.stable_port, entry.base_port, range_end
            );
        }

        // 3. secret not empty and valid base32
        if entry.secret.trim().is_empty() {
            anyhow::bail!("Secret for proxy on port {} cannot be empty", entry.stable_port);
        }
        if decode_secret(&entry.secret).is_err() {
            anyhow::bail!("Secret for proxy on port {} is not a valid Base32 string", entry.stable_port);
        }
    }
    Ok(())
}
