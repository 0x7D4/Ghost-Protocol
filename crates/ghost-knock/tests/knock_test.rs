use anyhow::Result;
use std::time::{SystemTime, UNIX_EPOCH};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;
use tokio::process::Command;
use tokio::time::{sleep, Duration};

#[tokio::test]
async fn test_ghost_knock_bidirectional_proxy() -> Result<()> {
    // Shared secret: "testsecret" -> "ORSXG5BRGAYDAMBQ" (Base32)
    let secret = "ORSXG5BRGAYDAMBQ";
    // 1. Start a mock TCP server on a random available port
    let listener = TcpListener::bind("127.0.0.1:0").await?;
    let port = listener.local_addr()?.port();
    
    // Derived values for the CLI to "calculate" this same port
    let target_base_port: u16 = port;
    let target_range: u16 = 1; // Range 1 ensures port is always base_port
    
    let mock_server = tokio::spawn(async move {
        let (mut socket, _) = listener.accept().await.unwrap();
        
        let mut buf = [0u8; 12];
        socket.read_exact(&mut buf).await.unwrap();
        if &buf == b"hello server" {
            socket.write_all(b"hello client").await.unwrap();
            socket.flush().await.unwrap();
        }
        // Shutdown write side to signal EOF to proxy
        let _ = socket.shutdown().await;
        // Keep read side open for a moment
        sleep(Duration::from_millis(100)).await;
    });

    // 2. Run ghost-knock as a subprocess using the direct binary path
    let bin_path = env!("CARGO_BIN_EXE_ghost-knock");
    let mut child = Command::new(bin_path)
        .args([
            "127.0.0.1",
            &target_base_port.to_string(),
            &target_range.to_string(),
            secret,
        ])
        .stdin(std::process::Stdio::piped())
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::inherit())
        .spawn()?;

    let mut stdin = child.stdin.take().expect("Failed to open stdin");
    let mut stdout = child.stdout.take().expect("Failed to open stdout");

    // 3. Perform bidirectional data flow
    // Send to server
    stdin.write_all(b"hello server").await?;
    stdin.flush().await?;
    // Signal EOF to proxy so it can shutdown the socket write side
    drop(stdin);

    // Read from server
    let mut out_buf = Vec::new();
    // We expect the proxy to exit when both directions are done (join! in lib.rs)
    stdout.read_to_end(&mut out_buf).await?;
    
    assert_eq!(&out_buf, b"hello client");

    // 4. Cleanup
    mock_server.await?;
    let status = child.wait().await?;
    assert!(status.success());

    Ok(())
}
