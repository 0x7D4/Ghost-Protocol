//! TOTP knock protocol types.

use serde::{Deserialize, Serialize};

/// A single knock event derived from the current TOTP window.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct KnockSequence {
    /// The derived port numbers for this time window.
    pub ports: Vec<u16>,
    /// Unix timestamp when this sequence was generated.
    pub generated_at: u64,
    /// Time-to-live in seconds before the sequence expires.
    pub ttl_secs: u64,
}

/// State of a knock sequence validation.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum KnockState {
    /// Waiting for the first knock in the sequence.
    Idle,
    /// Partially matched — expecting more knocks.
    Partial { matched: u8, total: u8 },
    /// Full sequence matched — access granted.
    Authenticated,
    /// Sequence failed — reset.
    Failed,
}

/// Shared key/value type for the BPF blocklist map.
/// Must be `#[repr(C)]` for ABI compatibility with eBPF programs.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(C)]
pub struct BlocklistEntry {
    /// IPv4 address in network byte order.
    pub addr: u32,
    /// Unix timestamp when this entry expires.
    pub expires_at: u64,
}
