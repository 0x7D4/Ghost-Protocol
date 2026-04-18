//! eBPF program loader using the aya framework.

use anyhow::{Context, Result};
use std::fs;
use std::sync::Arc;
use tokio::sync::Mutex;
use tracing::info;

use ghost_common::DashboardEvent;
use crate::broadcaster::EventBroadcaster;

/// BPF-compatible reconnaissance statistics (matches ghost-ebpf layout).
#[repr(C)]
#[derive(Clone, Copy)]
pub struct BpfReconStats {
    pub unique_ports_hit: u16,
    pub first_seen_ns: u64,
}

// SAFETY: BpfReconStats is #[repr(C)] and contains only Pod-compatible fields (u16, u64).
// It has no padding that could lead to uninitialized memory leakage and is safe 
// for byte-for-byte mapping with eBPF kernel maps.
unsafe impl aya::Pod for BpfReconStats {}

/// Manages the lifecycle of eBPF programs.
pub struct EbpfLoader {
    bpf: Arc<Mutex<aya::Ebpf>>,
    interface: String,
}

impl EbpfLoader {
    /// Detect the default network interface by reading /proc/net/route.
    pub fn detect_default_interface() -> Result<String> {
        let content = fs::read_to_string("/proc/net/route")
            .context("Failed to read /proc/net/route")?;
        
        for line in content.lines().skip(1) {
            let fields: Vec<&str> = line.split_whitespace().collect();
            if fields.len() >= 2 && fields[1] == "00000000" {
                return Ok(fields[0].to_string());
            }
        }
        
        Err(anyhow::anyhow!("Could not detect default network interface"))
    }

    /// Load and attach all eBPF programs.
    pub async fn load_and_attach(bpf_bytes: &[u8]) -> Result<Self> {
        let interface = Self::detect_default_interface().unwrap_or_else(|_| "eth0".to_string());
        info!("loading eBPF programs for interface {}", interface);

        let mut bpf = aya::EbpfLoader::new()
            .load(bpf_bytes)
            .context("failed to load BPF bytes")?;

        // Attach XDP Hook
        info!("Attaching ghost_xdp to {}", interface);
        let xdp_prog: &mut aya::programs::Xdp = bpf.program_mut("ghost_xdp").unwrap().try_into()?;
        xdp_prog.load()?;
        xdp_prog.attach(&interface, aya::programs::XdpFlags::default())
            .context(format!("failed to attach XDP program to interface {}", interface))?;

        // Attach TC Hook
        info!("Attaching ghost_tc (egress) to {}", interface);
        let _ = aya::programs::tc::qdisc_add_clsact(&interface); // Ignore error if it already exists
        let tc_prog: &mut aya::programs::SchedClassifier = bpf.program_mut("ghost_tc").unwrap().try_into()?;
        tc_prog.load()?;
        tc_prog.attach(&interface, aya::programs::tc::TcAttachType::Egress)
            .context(format!("failed to attach TC egress program to interface {}", interface))?;

        info!("eBPF programs successfully attached to {}", interface);

        Ok(Self { bpf: Arc::new(Mutex::new(bpf)), interface })
    }

    /// Detach all eBPF programs.
    pub async fn detach(&mut self) -> Result<()> {
        info!("detaching eBPF programs from {}", self.interface);
        // We don't necessarily need to detach explicitly as Drop handles it,
        // but this is available for manual lifecycle management.
        Ok(())
    }

    /// Spawn a background task to poll the SCANNER_MAP and notify the tarpit engine.
    /// Implements Phase 3 thresholding: >15 unique ports in 5 seconds.
    pub fn spawn_scanner_poller(
        &self, 
        tx: tokio::sync::mpsc::Sender<u32>,
        broadcaster: Arc<EventBroadcaster>
    ) -> Result<()> {
        let bpf_handle = self.bpf.clone();
        
        tokio::spawn(async move {
            let mut flagged_cache: std::collections::HashSet<u32> = std::collections::HashSet::new();
            let mut cache_times: std::collections::HashMap<u32, std::time::Instant> = std::collections::HashMap::new();
            let mut last_status_emit = std::time::Instant::now();

            loop {
                let mut to_clear = Vec::new();
                
                {
                    let mut bpf = bpf_handle.lock().await;
                    
                    use aya::maps::HashMap as AyaMap;
                    let mut scanner_map: AyaMap<_, u32, BpfReconStats> = match AyaMap::try_from(bpf.map_mut("SCANNER_MAP").unwrap()) {
                        Ok(m) => m,
                        Err(_) => {
                            drop(bpf);
                            tokio::time::sleep(std::time::Duration::from_millis(500)).await;
                            continue;
                        }
                    };

                    for (ip, stats) in scanner_map.iter().flatten() {
                        if stats.unique_ports_hit > 15 {
                            if !flagged_cache.contains(&ip) {
                                info!("Scanner threshold exceeded for IP: {:08x} ({} hits)", ip, stats.unique_ports_hit);
                                if tx.try_send(ip).is_ok() {
                                    flagged_cache.insert(ip);
                                    cache_times.insert(ip, std::time::Instant::now());
                                }
                            }
                            to_clear.push(ip);
                        }
                    }

                    for ip in to_clear {
                        let _ = scanner_map.remove(&ip);
                    }

                    if last_status_emit.elapsed() > std::time::Duration::from_secs(5) {
                        use aya::maps::Array as AyaArray;
                        let persona_map: AyaArray<_, u8> = AyaArray::try_from(bpf.map("PERSONA_INDEX").unwrap()).unwrap();
                        let persona_index: u8 = persona_map.get(&0, 0).unwrap_or(0);
                        
                        let scanners_stats: AyaMap<_, u32, BpfReconStats> = AyaMap::try_from(bpf.map("SCANNERS").unwrap()).unwrap();
                        let scanner_count = scanners_stats.iter().count() as u32;
                        
                        let allowlist: AyaMap<_, u32, u8> = AyaMap::try_from(bpf.map("ALLOWLIST").unwrap()).unwrap();
                        let allowlist_size = allowlist.iter().count() as u32;

                        let _ = broadcaster.broadcast(&DashboardEvent::EbpfStatus { 
                            persona_index, 
                            rotation_secs_remaining: 60 - (last_status_emit.elapsed().as_secs() % 60) as u8,
                            scanner_count, 
                            allowlist_size 
                        }).await;
                        
                        last_status_emit = std::time::Instant::now();
                    }
                } // Bpf lock dropped here

                let now = std::time::Instant::now();
                flagged_cache.retain(|ip| {
                    if let Some(first_seen) = cache_times.get(ip) {
                        if now.duration_since(*first_seen) < std::time::Duration::from_secs(60) {
                            true
                        } else {
                            cache_times.remove(ip);
                            false
                        }
                    } else {
                        false
                    }
                });

                tokio::time::sleep(std::time::Duration::from_millis(500)).await;
            }
        });

        Ok(())
    }

    /// Provide access to BPF context for testing.
    pub async fn bpf_lock(&self) -> tokio::sync::MutexGuard<'_, aya::Ebpf> {
        self.bpf.lock().await
    }
}
