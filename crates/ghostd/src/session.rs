//! Attacker confusion score and session tracking.

use std::collections::VecDeque;
use std::net::Ipv4Addr;
use std::time::{Duration, Instant};
use once_cell::sync::Lazy;
use regex::Regex;
use serde::Serialize;
use serde_json::json;

/// Standard deceptive tool signatures based on behavioral patterns.
#[derive(Debug, Clone, Copy, Serialize, PartialEq, Eq)]
pub enum ToolSignature {
    Nmap,
    Masscan,
    Zmap,
    Unknown,
}

static SSH_USER_RE: Lazy<Regex> = Lazy::new(|| Regex::new(r"^[A-Za-z0-9_-]{1,32}\x00").unwrap());
static HTTP_BASIC_RE: Lazy<Regex> = Lazy::new(|| Regex::new(r"Authorization: Basic").unwrap());
static TLS_HANDSHAKE_RE: Lazy<Regex> = Lazy::new(|| Regex::new(r"^\x16\x03").unwrap());

/// Tracks an attacker interaction to quantify confusion.
pub struct SessionTracker {
    pub src_ip: Ipv4Addr,
    pub src_port: u16,
    pub started_at: Instant,
    pub connection_attempts: u32,
    pub credential_tries: u32,
    pub bytes_wasted: u64,
    pub tool_signature: ToolSignature,
    pub banner_type: String,
    
    // Internal state for timing fingerprinting
    gaps: VecDeque<Duration>,
}

impl SessionTracker {
    /// Initialize a new session tracker.
    pub fn new(src_ip: Ipv4Addr, src_port: u16, banner_type: String) -> Self {
        Self {
            src_ip,
            src_port,
            started_at: Instant::now(),
            connection_attempts: 1, // First connection
            credential_tries: 0,
            bytes_wasted: 0,
            tool_signature: ToolSignature::Unknown,
            banner_type,
            gaps: VecDeque::with_capacity(5),
        }
    }

    /// Record an incoming packet or byte chunk.
    pub fn record_packet(&mut self, bytes: &[u8], gap: Duration) {
        self.bytes_wasted += bytes.len() as u64;
        
        // Update gaps for fingerprinting
        if self.gaps.len() >= 5 {
            self.gaps.pop_front();
        }
        self.gaps.push_back(gap);

        // Tool detection logic
        self.detect_tool();

        // Credential detection logic
        self.detect_credentials(bytes);
    }

    fn detect_tool(&mut self) {
        if self.gaps.is_empty() {
            return;
        }

        // Masscan: fast burst < 10ms
        if self.gaps.iter().all(|g| g.as_millis() < 10) {
            self.tool_signature = ToolSignature::Masscan;
        } 
        // Nmap: slower scan > 100ms
        else if self.gaps.iter().any(|g| g.as_millis() > 100) {
            self.tool_signature = ToolSignature::Nmap;
        }
        // Zmap: very specific SYN-only pattern (not easily detectable within a single session 
        // without global flow context, but we use the "no pulse" heuristic)
        else if self.gaps.len() == 1 && self.gaps[0].as_millis() > 500 {
            self.tool_signature = ToolSignature::Zmap;
        }
    }

    fn detect_credentials(&mut self, bytes: &[u8]) {
        // We only scan printable-ish samples or specific protocol headers
        let sample = String::from_utf8_lossy(bytes);
        
        if SSH_USER_RE.is_match(&sample) || 
           HTTP_BASIC_RE.is_match(&sample) || 
           TLS_HANDSHAKE_RE.is_match(&sample) {
            self.credential_tries += 1;
        }
    }

    /// Calculate the confusion score based on session metrics.
    pub fn confusion_score(&self) -> u32 {
        let duration_secs = self.started_at.elapsed().as_secs() as u32;
        (duration_secs * 2) + (self.connection_attempts / 10) + (self.credential_tries * 5)
    }

    /// Generate a structured JSON report.
    pub fn confusion_report(&self) -> serde_json::Value {
        let duration_secs = self.started_at.elapsed().as_secs();
        let score = self.confusion_score();
        
        let summary = format!(
            "Confused {:?} for {}s — {} bytes wasted, {} cred attempts",
            self.tool_signature, duration_secs, self.bytes_wasted, self.credential_tries
        );

        json!({
            "src_ip": self.src_ip.to_string(),
            "duration_secs": duration_secs,
            "connection_attempts": self.connection_attempts,
            "credential_tries": self.credential_tries,
            "bytes_wasted": self.bytes_wasted,
            "tool_signature": self.tool_signature,
            "banner_type": self.banner_type,
            "score": score,
            "summary": summary
        })
    }
}
