//! Tarpit deception engine with LLM Persona integration.

use anyhow::{Context, Result};
use std::collections::HashSet;
use std::net::{SocketAddr, IpAddr};
use std::sync::Arc;
use tokio::io::AsyncReadExt;
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::{mpsc, Mutex};
use tokio::time::{sleep, Duration, timeout, Instant};
use tracing::{info, warn};

use ghost_common::{DashboardEvent, ReconStats};
use futures_util::FutureExt;
use crate::persona::PersonaEngine;
use crate::session::SessionTracker;
use crate::broadcaster::EventBroadcaster;

/// The tarpit engine that manages deceptive connections.
#[derive(Clone)]
pub struct TarpitEngine {
    enabled: bool,
    scanners: Arc<Mutex<HashSet<u32>>>,
    conn_count: Arc<Mutex<u64>>,
    persona_engine: Arc<PersonaEngine>,
    broadcaster: Arc<EventBroadcaster>,
}

impl TarpitEngine {
    /// Create a new tarpit engine.
    pub fn new(
        broadcaster: Arc<EventBroadcaster>,
        persona_engine: Arc<PersonaEngine>,
    ) -> (Self, mpsc::Sender<u32>) {
        let (tx, rx) = mpsc::channel(100);
        let engine = Self {
            enabled: true,
            scanners: Arc::new(Mutex::new(HashSet::new())),
            conn_count: Arc::new(Mutex::new(0)),
            persona_engine,
            broadcaster,
        };
        
        let scanners = engine.scanners.clone();
        let broadcaster = engine.broadcaster.clone();

        tokio::spawn(async move {
            let mut rx = rx;
            while let Some(ip) = rx.recv().await {
                let mut set = scanners.lock().await;
                if set.insert(ip) {
                    // New scanner flagged
                    let ipv4 = IpAddr::V4(std::net::Ipv4Addr::from(ip)).to_string();
                    let timestamp_ms = std::time::SystemTime::now()
                        .duration_since(std::time::UNIX_EPOCH)
                        .unwrap_or_default()
                        .as_millis() as u64;
                    
                    broadcaster.broadcast(&DashboardEvent::ScannerFlagged { 
                        src_ip: ipv4, 
                        timestamp_ms 
                     }).await;
                }
            }
        });

        (engine, tx)
    }

    /// Programmatically flag an IP (useful for tests).
    pub async fn flag_ip(&self, ip: std::net::Ipv4Addr, _stats: ReconStats) -> Result<()> {
        let mut set = self.scanners.lock().await;
        set.insert(u32::from(ip));
        Ok(())
    }

    /// Run a listener on a specific port (returns the actual bound port immediately).
    pub async fn listen(&self, port: u16) -> Result<u16> {
        let listener = TcpListener::bind(format!("127.0.0.1:{}", port)).await
            .with_context(|| format!("Failed to bind to 127.0.0.1:{}", port))?;
        
        let bound_port = listener.local_addr()?.port();
        println!("TARPIT: Listener actively bound and waiting on 127.0.0.1:{}", bound_port);

        let scanners = self.scanners.clone();
        let conn_count = self.conn_count.clone();
        let persona_engine = self.persona_engine.clone();
        let broadcaster = self.broadcaster.clone();

        tokio::spawn(async move {
            loop {
                match listener.accept().await {
                    Ok((socket, addr)) => {
                        println!("TARPIT: Accept loop received connection from {}", addr);
                        let scanners = scanners.clone();
                        let conn_count = conn_count.clone();
                        let persona_engine = persona_engine.clone();
                        let broadcaster = broadcaster.clone();
                        tokio::spawn(async move {
                            if let Err(e) = handle_connection(socket, addr, scanners, conn_count, persona_engine, broadcaster).await {
                                warn!("Tarpit connection error from {}: {}", addr, e);
                            }
                        });
                    }
                    Err(e) => warn!("Accept error: {}", e),
                }
            }
        });
        
        Ok(bound_port)
    }

    /// Start the tarpit engine listeners on multiple ports.
    pub async fn run(&self) -> Result<()> {
        if !self.enabled {
            info!("tarpit engine disabled");
            return Ok(());
        }

        let ports = vec![22, 80, 445, 3306, 8080, 2222];
        let mut listeners = Vec::with_capacity(ports.len());

        for port in ports {
            match TcpListener::bind(format!("0.0.0.0:{}", port)).await {
                Ok(l) => {
                    info!("Tarpit engine listening on 0.0.0.0:{}", port);
                    listeners.push(l);
                }
                Err(e) => {
                    warn!("Failed to bind tarpit port {}: {}. Ensure ghostd has CAP_NET_BIND_SERVICE.", port, e);
                }
            }
        }

        if listeners.is_empty() {
            return Err(anyhow::anyhow!("All tarpit ports failed to bind"));
        }

        loop {
            // Wait for any listener to accept a connection
            let futures = listeners.iter().map(|l| l.accept().boxed());
            let (result, index, _) = futures_util::future::select_all(futures).await;
            
            match result {
                Ok((socket, addr)) => {
                    let scanners = self.scanners.clone();
                    let conn_count = self.conn_count.clone();
                    let persona_engine = self.persona_engine.clone();
                    let broadcaster = self.broadcaster.clone();
                    tokio::spawn(async move {
                        if let Err(e) = handle_connection(socket, addr, scanners, conn_count, persona_engine, broadcaster).await {
                            warn!("Tarpit connection error from {}: {}", addr, e);
                        }
                    });
                }
                Err(e) => warn!("Accept error on listener {}: {}", index, e),
            }
        }
    }

    /// Provide access to the scanner set (for tests).
    pub fn scanner_set(&self) -> Arc<Mutex<HashSet<u32>>> {
        self.scanners.clone()
    }
}

pub async fn handle_connection(
    mut socket: TcpStream, 
    addr: SocketAddr, 
    scanners: Arc<Mutex<HashSet<u32>>>, 
    _conn_count: Arc<Mutex<u64>>,
    persona_engine: Arc<PersonaEngine>,
    broadcaster: Arc<EventBroadcaster>,
) -> Result<()> {
    let ipv4 = match addr.ip() {
        IpAddr::V4(v4) => v4,
        IpAddr::V6(v6) => {
            // Normalize IPv4-mapped IPv6 address (::ffff:x.x.x.x)
            if let Some(v4) = v6.to_ipv4() {
                v4
            } else {
                return Ok(()); // Drop true IPv6 (unsupported in this phase)
            }
        }
    };
    println!("TARPIT: Accepted connection from {} on local port", ipv4);

    // Check if flagged
    {
        let set = scanners.lock().await;
        if !set.contains(&u32::from(ipv4)) {
            println!("TARPIT: IP {} NOT in scanner set. DROPPING.", ipv4);
            return Ok(()); // Drop non-scanners
        }
    }
    println!("TARPIT: IP {} IS in scanner set. ENGAGING.", ipv4);

    // Determine persona from destination port
    let local_addr = socket.local_addr()?;
    let port = local_addr.port();
    let banner_type = persona_engine.get_system_prompt(port).to_string();

    // Notify UI that a persona is active
    broadcaster.broadcast(&DashboardEvent::PersonaActive { 
        port, 
        persona: banner_type.chars().take(32).collect::<String>() // Representative name
    }).await;

    // Initialize session tracker
    let mut tracker = SessionTracker::new(ipv4, addr.port(), banner_type);
    let mut last_packet_at = Instant::now();

    info!(
        scanner_event = "engaging",
        src_ip = %addr.ip(),
        src_port = addr.port(),
        dst_port = port,
    );

    // Initial read for LLM context (up to 512 bytes with 1s timeout)
    let mut initial_input = [0u8; 512];
    let mut input_str = String::new();
    if let Ok(Ok(n)) = timeout(Duration::from_secs(1), socket.read(&mut initial_input)).await {
        let gap = last_packet_at.elapsed();
        last_packet_at = Instant::now();
        tracker.record_packet(&initial_input[..n], gap);
        input_str = String::from_utf8_lossy(&initial_input[..n]).to_string();
    }

    // Run persona engine interaction (handles streaming and fallback)
    println!("Engaging persona for port {}", port);
    if let Err(e) = persona_engine.respond(port, &input_str, &mut socket).await {
        warn!("Persona engine failed for {}: {}. Falling back to slow-drain.", addr, e);
    }

    // After persona engagement, enter long-term slow-drain phase
    let start_time = Instant::now();
    let timeout_duration = Duration::from_secs(600);
    let mut buf = [0u8; 1];

    loop {
        if start_time.elapsed() > timeout_duration {
            break;
        }

        match timeout(Duration::from_millis(500), socket.read_exact(&mut buf)).await {
            Ok(Ok(_)) => {
                let gap = last_packet_at.elapsed();
                last_packet_at = Instant::now();
                tracker.record_packet(&buf, gap);
                sleep(Duration::from_millis(500)).await;
            }
            Ok(Err(_)) => break, // Connection closed
            Err(_) => continue, // Timeout (no bytes)
        }
    }

    let report = tracker.confusion_report();
    broadcaster.broadcast(&DashboardEvent::SessionClosed { report: report.clone() }).await;

    info!(
        scanner_event = "disengaging",
        src_ip = %addr.ip(),
        src_port = addr.port(),
        report = %report
    );

    Ok(())
}
