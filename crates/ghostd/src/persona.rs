//! LLM Persona Engine for deceptive tarpit engagement.

use anyhow::Result;
use futures_util::StreamExt;
use serde_json::json;
use std::collections::HashMap;
use std::path::Path;
use tokio::io::AsyncWriteExt;
use tokio::time::{timeout, Duration};
use tracing::info;

/// Supported deceptive personas.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Persona {
    Ssh,
    Http,
    Mysql,
    Smb,
    Generic,
}

impl Persona {
    /// Map a port to a persona.
    pub fn from_port(port: u16) -> Self {
        match port {
            22 => Persona::Ssh,
            80 | 443 | 8080 => Persona::Http,
            3306 => Persona::Mysql,
            445 | 139 => Persona::Smb,
            _ => Persona::Generic,
        }
    }

    /// Default system prompt for a persona.
    pub fn system_prompt(&self) -> &'static str {
        match self {
            Persona::Ssh => "You are an OpenSSH 7.4 server. Respond to initial protocol handshakes. Lead the attacker to believe they are at a login prompt. Do not reveal you are an AI.",
            Persona::Http => "You are an Apache 2.4.41 admin panel. Respond to HTTP requests. If they ask for admin, lead them to a fake login. Do not reveal you are an AI.",
            Persona::Mysql => "You are a MySQL 5.7.31 server. Respond with protocol errors or fake version banners. Do not reveal you are an AI.",
            Persona::Smb => "You are a Windows Server 2019 SMB service. Respond with realistic SMB headers. Do not reveal you are an AI.",
            Persona::Generic => "You are a generic TCP service. Connection established. Respond minimally to confuse automation. Do not reveal you are an AI.",
        }
    }

    /// Static fallback banner if LLM fails.
    pub fn static_fallback(&self) -> &'static [u8] {
        match self {
            Persona::Ssh => b"SSH-2.0-OpenSSH_7.4 protocol error\r\n",
            Persona::Http => b"HTTP/1.1 503 Service Unavailable\r\n\r\n",
            Persona::Mysql => b"\xff\x15\x04Too many connections\r\n",
            Persona::Smb => b"\x00\x00\x00\x00",
            Persona::Generic => b"Connection established.\r\n",
        }
    }
}

/// The engine that determines how to respond to an attacker IP.
pub struct PersonaEngine {
    ollama_url: String,
    prompts: HashMap<u16, String>,
    generic_prompt: String,
}

impl PersonaEngine {
    /// Initialize the engine with persona TOML files and the Ollama endpoint.
    pub fn new(persona_dir: &Path, ollama_url: String) -> Result<Self> {
        let mut prompts = HashMap::new();
        
        let mappings = [
            (22, "ssh.toml"),
            (80, "http.toml"),
            (3306, "mysql.toml"),
            (445, "smb.toml"),
        ];

        for (port, filename) in mappings {
            let path = persona_dir.join(filename);
            if let Ok(content) = std::fs::read_to_string(&path) {
                if let Ok(value) = toml::from_str::<serde_json::Value>(&content) {
                    if let Some(prompt) = value["system_prompt"].as_str() {
                        prompts.insert(port, prompt.to_string());
                    }
                }
            }
        }

        let generic_path = persona_dir.join("generic.toml");
        let generic_prompt = std::fs::read_to_string(&generic_path)
            .ok()
            .and_then(|c| toml::from_str::<serde_json::Value>(&c).ok())
            .and_then(|v| v["system_prompt"].as_str().map(|s| s.to_string()))
            .unwrap_or_else(|| Persona::Generic.system_prompt().to_string());

        Ok(Self {
            ollama_url,
            prompts,
            generic_prompt,
        })
    }

    /// Get the system prompt for a specific port.
    pub fn get_system_prompt(&self, port: u16) -> &str {
        self.prompts.get(&port).unwrap_or(&self.generic_prompt)
    }

    /// Interact with the attacker using Ollama streaming.
    pub async fn respond<S>(
        &self,
        port: u16,
        attacker_input: &str,
        stream: &mut S,
    ) -> Result<()> 
    where S: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin + Send
    {
        let persona = Persona::from_port(port);
        let system_prompt = self.get_system_prompt(port);

        let client = reqwest::Client::builder()
            .connect_timeout(Duration::from_secs(2))
            .timeout(Duration::from_secs(10))
            .build()?;
        let body = json!({
            "model": "phi3:mini",
            "stream": true,
            "messages": [
                {"role": "system", "content": system_prompt},
                {"role": "user", "content": attacker_input}
            ]
        });

        info!(persona = ?persona, port = port, "Initiating LLM engagement");

        // Attempt to connect and stream with much tighter timeout for the initial connection
        println!("PersonaEngine: POSTing to Ollama at {}...", self.ollama_url);
        let res = match timeout(Duration::from_secs(2), client.post(&self.ollama_url).json(&body).send()).await {
            Ok(Ok(r)) => {
                println!("PersonaEngine: Received response from Ollama");
                r
            },
            Ok(Err(e)) => {
                println!("PersonaEngine: Ollama connection error: {}. Falling back.", e);
                stream.write_all(persona.static_fallback()).await?;
                return Ok(());
            }
            Err(_) => {
                println!("PersonaEngine: Ollama connection TIMEOUT. Falling back.");
                stream.write_all(persona.static_fallback()).await?;
                return Ok(());
            }
        };

        let mut chunks = res.bytes_stream();
        while let Some(chunk_res) = chunks.next().await {
            let chunk = match chunk_res {
                Ok(c) => c,
                Err(_) => break,
            };

            // Ollama sends JSON objects per line in the stream
            if let Ok(json) = serde_json::from_slice::<serde_json::Value>(&chunk) {
                if let Some(content) = json["message"]["content"].as_str() {
                    // Stream byte-by-byte for simulation realism
                    for byte in content.as_bytes() {
                        let _ = stream.write_all(&[*byte]).await;
                        tokio::time::sleep(Duration::from_millis(1)).await; // Low latency for chunk flow
                    }
                }
            }
        }

        Ok(())
    }
}
