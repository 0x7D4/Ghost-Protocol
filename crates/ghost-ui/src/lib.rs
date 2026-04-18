//! Ghost-Protocol TUI Application Logic.

use ghost_common::DashboardEvent;
use std::collections::{HashMap, VecDeque};
use std::time::Instant;

/// Metadata for a flagged scanner currently being engaged.
#[derive(Debug, Clone)]
pub struct ActiveScanner {
    pub ip: String,
    pub persona: String,
    pub started_at: Instant,
    pub score: u32,
}

/// A completed session report for the leaderboard.
#[derive(Debug, Clone)]
pub struct SessionReport {
    pub ip: String,
    pub tool: String,
    pub score: u32,
    pub duration_secs: u64,
    pub cred_tries: u32,
}

/// Operational status of the eBPF data plane.
#[derive(Debug, Clone)]
pub struct EbpfStatus {
    pub persona_index: u8,
    pub rotation_secs_remaining: u8,
    pub scanner_count: u32,
    pub allowlist_size: u32,
}

/// The main application state for the TUI.
pub struct App {
    pub active_scanners: HashMap<String, ActiveScanner>,
    pub leaderboard: Vec<SessionReport>,
    pub ebpf_status: Option<EbpfStatus>,
    pub event_log: VecDeque<String>,
}

impl Default for App {
    fn default() -> Self {
        Self::new()
    }
}

impl App {
    pub fn new() -> Self {
        Self {
            active_scanners: HashMap::new(),
            leaderboard: Vec::new(),
            ebpf_status: None,
            event_log: VecDeque::with_capacity(100),
        }
    }

    /// Process an incoming dashboard event and update internal state.
    pub fn handle_event(&mut self, event: DashboardEvent) {
        match event {
            DashboardEvent::ScannerFlagged { src_ip, .. } => {
                self.log(format!("Flagged scanner: {}", src_ip));
                // Will be fully populated once PersonaActive arrives
            }
            DashboardEvent::PersonaActive { port, persona } => {
                // Ideally we'd have the IP here, but for now we track by port/interaction if IP unknown
                // In a real scenario, PersonaActive should include src_ip. 
                // We'll update any active scanner without a persona or log it.
                self.log(format!("Persona active on port {}: {}", port, persona));
            }
            DashboardEvent::SessionClosed { report } => {
                let ip = report["src_ip"].as_str().unwrap_or("unknown").to_string();
                let tool = report["tool_signature"].as_str().unwrap_or("Unknown").to_string();
                let score = report["score"].as_u64().unwrap_or(0) as u32;
                let duration_secs = report["duration_secs"].as_u64().unwrap_or(0);
                let cred_tries = report["credential_tries"].as_u64().unwrap_or(0) as u32;

                self.log(format!("Session closed: {} (Score: {})", ip, score));
                self.active_scanners.remove(&ip);

                let session = SessionReport {
                    ip,
                    tool,
                    score,
                    duration_secs,
                    cred_tries,
                };

                self.leaderboard.push(session);
                self.leaderboard.sort_by_key(|s| std::cmp::Reverse(s.score));
                self.leaderboard.truncate(10);
            }
            DashboardEvent::EbpfStatus { persona_index, rotation_secs_remaining, scanner_count, allowlist_size } => {
                self.ebpf_status = Some(EbpfStatus {
                    persona_index,
                    rotation_secs_remaining,
                    scanner_count,
                    allowlist_size,
                });
            }
        }
    }

    /// Internal logging for the TUI event panel.
    pub fn log(&mut self, msg: String) {
        if self.event_log.len() >= 100 {
            self.event_log.pop_front();
        }
        self.event_log.push_back(msg);
    }

    /// Periodic update task (e.g. for duration timers).
    pub fn tick(&mut self) {
        // Future: update durations for active scanners
    }
}
