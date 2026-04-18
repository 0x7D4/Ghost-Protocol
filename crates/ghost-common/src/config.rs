//! Daemon and component configuration.

use serde::{Deserialize, Serialize};

/// Top-level Ghost-Protocol configuration.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GhostConfig {
    /// Network interface to attach eBPF programs to (e.g., "eth0").
    pub interface: String,
    /// TOTP shared secret (base32-encoded).
    pub totp_secret: String,
    /// Port rotation interval in seconds.
    pub rotation_interval_secs: u64,
    /// Whether to enable the tarpit deception engine.
    pub tarpit_enabled: bool,
    /// Whether to enable the LLM persona engine.
    pub llm_enabled: bool,
    /// Ollama API endpoint (e.g., "http://localhost:11434").
    pub ollama_endpoint: String,
    /// The LLM model to use for persona generation.
    pub ollama_model: String,
    /// Proxy listen address (e.g., "127.0.0.1:8443").
    pub proxy_listen_addr: String,
}

impl Default for GhostConfig {
    fn default() -> Self {
        Self {
            interface: "eth0".to_string(),
            totp_secret: String::new(),
            rotation_interval_secs: 30,
            tarpit_enabled: true,
            llm_enabled: false,
            ollama_endpoint: "http://localhost:11434".to_string(),
            ollama_model: "llama3.2".to_string(),
            proxy_listen_addr: "127.0.0.1:8443".to_string(),
        }
    }
}
