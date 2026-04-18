//! Shared types for BPF/Userspace interaction.

/// Persona definition used for morphing outbound SYN-ACK responses.
#[repr(C)]
#[derive(Clone, Copy)]
pub struct PersonaConfig {
    pub ttl: u8,
    pub _pad8: u8,
    pub window_size: u16,
    pub ip_id: u16,
}

/// IPv4 Source address key.
pub type Ipv4Addr = u32;

/// Key for the connection tracker (src_ip, dst_port).
#[repr(C)]
#[derive(Clone, Copy, PartialEq, Eq)]
pub struct ConntrackKey {
    pub src_ip: Ipv4Addr,
    pub dst_port: u16,
    pub _pad16: u16,
}

/// Statistics for reconnaissance detection per source IP.
#[repr(C)]
#[derive(Clone, Copy)]
pub struct ReconStats {
    /// Number of unique ports hit by this IP.
    pub unique_ports_hit: u16,
    /// Timestamp (ns) of the first packet in the current window.
    pub first_seen_ns: u64,
}
