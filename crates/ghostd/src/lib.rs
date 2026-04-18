//! Ghost-Protocol daemon library.
//!
//! This crate provides the core daemon functionality:
//! - eBPF program loading and management (Linux only)
//! - Tarpit deception engine
//! - LLM persona engine (via Ollama)
//! - Firewall rule management

#[cfg(target_os = "linux")]
pub mod ebpf_loader;
pub mod firewall;
pub mod persona;
pub mod tarpit;
pub mod session;
pub mod broadcaster;
