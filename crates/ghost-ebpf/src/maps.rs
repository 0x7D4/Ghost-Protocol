//! Shared BPF map definitions for Ghost-Protocol.

use aya_ebpf::{
    macros::map,
    maps::{Array, HashMap, LruHashMap},
};

use crate::types::{ConntrackKey, PersonaConfig, ReconStats};

/// Key type for IPv4 address in host byte order.
type Ipv4Addr = u32;

/// Allowlist — trusted source IP addresses.
#[map]
pub static ALLOWLIST: HashMap<Ipv4Addr, u8> = HashMap::with_max_entries(1024, 0);

/// Connection tracker for partial morph bypass.
/// Keyed by (src_ip, dst_port).
#[map]
pub static CONNTRACK: LruHashMap<ConntrackKey, u8> = LruHashMap::with_max_entries(8192, 0);

/// Active Persona Configs — indexed by rotation cycle (0-3).
#[map]
pub static PERSONAS: Array<PersonaConfig> = Array::with_max_entries(4, 0);

/// Primary Scanner Map — increments port hit counters for userspace thresholding.
#[map]
pub static SCANNER_MAP: HashMap<Ipv4Addr, ReconStats> = HashMap::with_max_entries(65536, 0);

/// Final Flagged Scanners — Global Hash for consistent cross-CPU detection.
#[map]
pub static SCANNERS: LruHashMap<u32, u64> = LruHashMap::with_max_entries(65536, 0);
