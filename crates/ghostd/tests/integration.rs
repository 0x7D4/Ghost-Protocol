use std::net::Ipv4Addr;
use std::path::Path;
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpStream, UnixStream};
use tokio::time::timeout;

use ghost_common::{DashboardEvent, ReconStats};
use ghostd::broadcaster::EventBroadcaster;
use ghostd::persona::PersonaEngine;
use ghostd::session::SessionTracker;
use ghostd::tarpit::{TarpitEngine, handle_connection};
use ghost_ui::App;
use ghost_knock::derive_port;

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

#[tokio::test(flavor = "multi_thread")]
async fn test_1_scanner_detection_to_tarpit_pipeline() {
    let broadcaster = EventBroadcaster::new();
    let persona_engine = Arc::new(PersonaEngine::new(Path::new("../../personas"), "http://127.0.0.1:11434".into()).unwrap());
    let (engine, _tx) = TarpitEngine::new(broadcaster, persona_engine);

    let local_ip = Ipv4Addr::new(127, 0, 0, 1);
    
    let (port_tx, port_rx) = tokio::sync::oneshot::channel();
    let engine_clone = engine.clone();
    tokio::spawn(async move {
        let port = engine_clone.listen(0).await.unwrap();
        port_tx.send(port).unwrap();
    });

    let port = port_rx.await.unwrap();
    println!("TEST_1: Server listening on port {}", port);

    // Wait for listener to bind
    tokio::time::sleep(Duration::from_millis(500)).await;

    // Simulate IP being flagged
    let stats = ReconStats { unique_ports_hit: 20, first_seen_ns: 0 };
    let _ = engine.flag_ip(local_ip, stats).await;

    // Connect to the tarpit
    let mut stream = connect_with_retry(format!("127.0.0.1:{}", port)).await;
    
    // IMPORTANT: Send initial bytes to trigger immediate persona response
    println!("Sending trigger payload...");
    stream.write_all(b"HELLO").await.unwrap();

    // Assert banner received
    let mut buf = [0u8; 128];
    let mut n = 0;
    let start = Instant::now();
    while start.elapsed() < Duration::from_secs(10) {
        match timeout(Duration::from_millis(1000), stream.read(&mut buf)).await {
            Ok(Ok(read_n)) if read_n > 0 => {
                println!("TEST_1: Read {} bytes: {:?}", read_n, String::from_utf8_lossy(&buf[..read_n]));
                n = read_n;
                break;
            }
            Ok(Ok(_)) => {
                println!("TEST_1: Read 0 bytes (EOF)");
                break;
            }
            Ok(Err(e)) => {
                println!("TEST_1: Read error: {}", e);
                break;
            }
            Err(_) => {
                println!("TEST_1: Read timeout, retrying...");
            }
        }
    }
    assert!(n > 0, "Banner was never received after 5s of polling");
    assert!(n > 0, "Banner should not be empty");
    let banner = String::from_utf8_lossy(&buf[..n]);
    // Port 13004 is unknown/generic -> "Connection established.\r\n"
    assert!(banner.contains("Connection established"), "Banner mismatch: {}", banner);

    // Keep connection alive for a moment
    println!("TEST_1: Read {} bytes: {:?}", n, String::from_utf8_lossy(&buf[..n]));
    assert!(n > 0, "No banner received from tarpit");
    println!("TEST_1: Finished successfully!");
}

#[tokio::test(flavor = "multi_thread")]
async fn test_2_session_tracker_lifecycle() {
    let src_ip = Ipv4Addr::new(5, 6, 7, 8);
    let mut tracker = SessionTracker::new(src_ip, 80, "Http".into());
    let auth_payload = b"Authorization: Basic dGVzdA==";
    tracker.record_packet(auth_payload, Duration::from_millis(150));
    assert_eq!(tracker.credential_tries, 1);
    println!("TEST_2: Finished successfully!");
}

#[tokio::test(flavor = "multi_thread")]
async fn test_4_event_broadcaster() {
    let socket_path = format!("/tmp/ghostd_test_{}_t4.sock", std::process::id());
    let _ = std::fs::remove_file(&socket_path);

    let broadcaster = EventBroadcaster::with_path(socket_path.clone());
    let b_clone = broadcaster.clone();
    tokio::spawn(async move {
        let _ = b_clone.start_server().await;
    });

    // Wait for socket to bind
    tokio::time::sleep(Duration::from_millis(500)).await;

    let mut client = UnixStream::connect(&socket_path).await.expect("Failed to connect to Unix socket");
    
    // Allow more time for registration
    tokio::time::sleep(Duration::from_millis(1000)).await;

    let event = DashboardEvent::ScannerFlagged {
        src_ip: "1.2.3.4".into(),
        timestamp_ms: 12345,
    };

    // Broadcast multiple times as a robust guard against registration lag
    for _ in 0..3 {
        broadcaster.broadcast(&event).await;
        tokio::time::sleep(Duration::from_millis(100)).await;
    }

    let mut buf = [0u8; 512];
    // Wait for the broadcast with long timeout and explicit retry logic if the first one misses
    let mut n = 0;
    for _ in 0..5 {
        if let Ok(Ok(read_n)) = timeout(Duration::from_secs(2), client.read(&mut buf)).await {
            if read_n > 0 {
                n = read_n;
                break;
            }
        }
        // If timeout, broadcast again
        broadcaster.broadcast(&event).await;
    }
    assert!(n > 0, "Broadcaster event never received at Unix socket");

    let feedback = String::from_utf8_lossy(&buf[..n]);
    let line = feedback.lines().next().expect("Empty response from broadcaster");
    let received: DashboardEvent = serde_json::from_str(line).unwrap();
    if let DashboardEvent::ScannerFlagged { src_ip, .. } = received {
        assert_eq!(src_ip, "1.2.3.4");
    } else {
        panic!("Unexpected event type: {:?}", received);
    }

    let _ = std::fs::remove_file(&socket_path);
    println!("TEST_4: Finished successfully!");
}

#[test]
fn test_5_app_state_leaderboard() {
    let mut app = App::new();
    let event = DashboardEvent::SessionClosed {
        report: serde_json::json!({
            "src_ip": "1.1.1.1",
            "score": 100,
            "summary": "Test"
        }),
    };
    app.handle_event(event);
    assert_eq!(app.leaderboard.len(), 1);
}

#[test]
fn test_6_totp_port_derivation_determinism() {
    let secret = b"testkey";
    let p1 = derive_port(secret, 10000, 1000, 1000000);
    let p2 = derive_port(secret, 10000, 1000, 1000000);
    assert_eq!(p1, p2);
}
