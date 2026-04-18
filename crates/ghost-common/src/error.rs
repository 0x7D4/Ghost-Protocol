//! Shared error types for Ghost-Protocol.

use thiserror::Error;

/// Errors that can occur across Ghost-Protocol components.
#[derive(Debug, Error)]
pub enum GhostError {
    /// Configuration file could not be parsed.
    #[error("configuration error: {0}")]
    Config(String),

    /// TOTP secret is invalid or missing.
    #[error("invalid TOTP secret: [REDACTED]")]
    TotpSecret(String),

    /// eBPF program loading or attachment failed.
    #[error("eBPF error: {0}")]
    Ebpf(String),

    /// Network or proxy error.
    #[error("network error: {0}")]
    Network(String),

    /// LLM / Ollama communication error.
    #[error("LLM engine error: {0}")]
    Llm(String),

    /// Generic I/O error.
    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),
}
