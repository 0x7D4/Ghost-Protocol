//! Manages active UI clients connected via Unix socket.

use anyhow::{Context, Result};
use std::sync::Arc;
use tokio::net::{UnixListener, UnixStream};
use tokio::io::AsyncWriteExt;
use tokio::sync::Mutex;
use tracing::{info, warn};

use ghost_common::{DashboardEvent, SOCKET_PATH};

pub struct EventBroadcaster {
    clients: Mutex<Vec<UnixStream>>,
    path: String,
}

impl EventBroadcaster {
    pub fn new() -> Arc<Self> {
        Self::with_path(SOCKET_PATH.to_string())
    }

    pub fn with_path(path: String) -> Arc<Self> {
        Arc::new(Self {
            clients: Mutex::new(Vec::new()),
            path,
        })
    }

    /// Broadcast an event to all connected clients as a JSON line.
    /// Skip silently if no clients are connected.
    pub async fn broadcast(&self, event: &DashboardEvent) {
        let mut clients = self.clients.lock().await;
        if clients.is_empty() {
            return;
        }

        let mut msg = match serde_json::to_string(event) {
            Ok(s) => s,
            Err(e) => {
                warn!("Failed to serialize dashboard event: {}", e);
                return;
            }
        };
        msg.push('\n');

        let mut to_remove = Vec::new();
        for (i, client) in clients.iter_mut().enumerate() {
            if let Err(e) = client.write_all(msg.as_bytes()).await {
                // Eventual consistency: skip fail and remove dead client
                info!("Removing dead UI client: {}", e);
                to_remove.push(i);
            }
        }

        // Clean up dead clients in reverse order
        for i in to_remove.into_iter().rev() {
            clients.remove(i);
        }
    }

    /// Start the Unix socket listener server.
    pub async fn start_server(self: Arc<Self>) -> Result<()> {
        let path = self.path.clone();
        let _ = std::fs::remove_file(&path);
        let listener = UnixListener::bind(&path)
            .with_context(|| format!("Failed to bind Unix socket at {}", path))?;
        
        info!("Telemetry broadcaster listening on {}", path);

        tokio::spawn(async move {
            loop {
                match listener.accept().await {
                    Ok((stream, _)) => {
                        info!("New UI client connected");
                        let mut clients = self.clients.lock().await;
                        clients.push(stream);
                    }
                    Err(e) => warn!("Unix socket accept error: {}", e),
                }
            }
        });

        Ok(())
    }
}
