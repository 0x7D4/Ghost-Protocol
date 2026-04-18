//! Firewall rule management.
//!
//! Interfaces with nftables/iptables to dynamically open and close
//! ports based on TOTP knock authentication results.

use anyhow::Result;

/// Manages dynamic firewall rules for port rotation.
pub struct FirewallManager {
    interface: String,
}

impl FirewallManager {
    /// Create a new firewall manager for the given interface.
    pub fn new(interface: impl Into<String>) -> Self {
        Self {
            interface: interface.into(),
        }
    }

    /// Open a port for a specific source IP (temporary allow rule).
    pub async fn allow_port(&self, source_ip: std::net::Ipv4Addr, port: u16) -> Result<()> {
        tracing::info!(
            "allowing {}:{} on {} via firewall",
            source_ip,
            port,
            self.interface
        );
        // TODO: Execute nftables/iptables command to add ACCEPT rule
        Ok(())
    }

    /// Close a previously opened port.
    pub async fn revoke_port(&self, source_ip: std::net::Ipv4Addr, port: u16) -> Result<()> {
        tracing::info!(
            "revoking {}:{} on {} via firewall",
            source_ip,
            port,
            self.interface
        );
        // TODO: Execute nftables/iptables command to remove ACCEPT rule
        Ok(())
    }
}
