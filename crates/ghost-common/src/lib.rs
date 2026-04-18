//! Shared types for Ghost-Protocol.

use serde::{Deserialize, Serialize};

/// Persona definition used for morphing outbound SYN-ACK responses.
#[repr(C)]
#[derive(Debug, Clone, Copy, Serialize, Deserialize)]
pub struct PersonaConfig {
    pub ttl: u8,
    pub _pad8: u8,
    pub window_size: u16,
    pub ip_id: u16,
}

/// Key for the connection tracker (src_ip, dst_port).
#[repr(C)]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct ConntrackKey {
    pub src_ip: u32,
    pub dst_port: u16,
    pub _pad16: u16,
}

/// Statistics for reconnaissance detection per source IP.
#[derive(Debug, Clone, Copy, Serialize, Deserialize)]
pub struct ReconStats {
    /// Number of unique ports hit by this IP.
    pub unique_ports_hit: u16,
    /// Timestamp (ns) of the first packet in the current window.
    pub first_seen_ns: u64,
}

pub const SOCKET_PATH: &str = "/tmp/ghostd.sock";

/// Events emitted by ghostd for real-time dashboard monitoring.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum DashboardEvent {
    /// A new scanner has been identified and flagged in eBPF.
    ScannerFlagged { src_ip: String, timestamp_ms: u64 },
    /// A tarpit session has completed, providing a detailed forensic report.
    SessionClosed { report: serde_json::Value },
    /// A deceptive persona is currently active and engaging an attacker.
    PersonaActive { port: u16, persona: String },
    /// Current health and occupancy status of the eBPF data plane.
    EbpfStatus {
        persona_index: u8,
        rotation_secs_remaining: u8,
        scanner_count: u32,
        allowlist_size: u32,
    },
}
