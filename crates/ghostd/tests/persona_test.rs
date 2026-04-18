use ghostd::persona::PersonaEngine;
use ghostd::tarpit::TarpitEngine;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use std::sync::Arc;
use std::time::Duration;
use std::path::Path;

async fn connect_with_retry(addr: String) -> TcpStream {
    let mut last_err = None;
    for _ in 0..5 {
        match TcpStream::connect(&addr).await {
            Ok(s) => return s,
            Err(e) => {
                last_err = Some(e);
                tokio::time::sleep(Duration::from_millis(200)).await;
            }
        }
    }
    panic!("Failed to connect to {} after 5 attempts: {:?}", addr, last_err);
}

#[tokio::test]
async fn test_persona_loading() {
    // This test assumes personas/ directory exists at workspace root
    // In CI we might need to point to a relative path
    let engine = PersonaEngine::new(Path::new("../../personas"), "http://127.0.0.1:11434/api/chat".to_string())
        .expect("Failed to load persona engine");
    
    assert!(engine.get_system_prompt(22).contains("SSH") || engine.get_system_prompt(22).contains("OpenSSH"));
    assert!(engine.get_system_prompt(3306).contains("MySQL"));
    assert!(engine.get_system_prompt(9999).contains("TCP echo stub"));
}

#[tokio::test]
async fn test_ollama_unavailable_fallback() {
    let persona_engine = Arc::new(PersonaEngine::new(Path::new("../../personas"), "http://127.0.0.1:11435/api/chat".to_string())
        .expect("Failed to load persona engine"));
    
    let broadcaster = ghostd::broadcaster::EventBroadcaster::new();
    let (tarpit, tx) = TarpitEngine::new(broadcaster, persona_engine);
    tx.send(0x7f000001).await.unwrap(); // Flag 127.0.0.1

    let port = 12224;
    tokio::spawn(async move {
        let listener = tokio::net::TcpListener::bind(format!("0.0.0.0:{}", port)).await.unwrap();
        let (socket, _addr) = listener.accept().await.unwrap();
        // Since we can't easily use TarpitEngine::run() with a dynamic port safely in test threads 
        // without more refactoring, we'll manually handle one connection with the same logic.
        
        let scanners = tarpit.scanner_set();
        let conn_count = Arc::new(tokio::sync::Mutex::new(0));
        let persona_engine = Arc::new(PersonaEngine::new(Path::new("../../personas"), "http://127.0.0.1:11435/api/chat".to_string()).unwrap());

        // Re-implement simplified handle_connection for test
        let mut socket = socket;
        let mut buf = [0u8; 512];
        let _ = tokio::time::timeout(Duration::from_millis(500), socket.read(&mut buf)).await;
        
        let _ = persona_engine.respond(22, "SSH-2.0-OpenSSH_8.0\r\n", &mut socket).await;
        
        // Keep open
        tokio::time::sleep(Duration::from_secs(5)).await;
    });

    tokio::time::sleep(Duration::from_millis(100)).await;

    let mut stream = connect_with_retry(format!("127.0.0.1:{}", port)).await;
    stream.write_all(b"SSH-2.0-OpenSSH_8.0\r\n").await.unwrap();

    let mut buf = [0u8; 100];
    let n = tokio::time::timeout(Duration::from_secs(3), stream.read(&mut buf))
        .await
        .expect("timeout waiting for banner")
        .expect("read failed");
    
    assert!(n > 0);
    // Should be the static SSH banner from Persona::static_fallback()
    assert!(String::from_utf8_lossy(&buf[..n]).contains("SSH-2.0-OpenSSH_7.4"));
}
