use ghostd::session::{SessionTracker, ToolSignature};
use std::net::Ipv4Addr;
use std::time::{Duration, Instant};

#[test]
fn test_session_tracker_score_formula() {
    let mut tracker = SessionTracker::new(Ipv4Addr::new(1, 2, 3, 4), 12345, "SSH".to_string());
    
    // Manually adjust started_at for testing (using field if pub, otherwise we simulate wait)
    // Formula: (duration_secs * 2) + (connection_attempts / 10) + (credential_tries * 5)
    
    tracker.connection_attempts = 20; // +2 points
    tracker.credential_tries = 3;     // +15 points
    
    // We can't easily mock Instant::now() without more effort, so we assert the base components 
    // are present and the math works for them. 
    // Given connection_attempts=20 and credential_tries=3, score should be >= 17.
    let score = tracker.confusion_score();
    assert!(score >= 17);
}

#[test]
fn test_session_tracker_report_json() {
    let mut tracker = SessionTracker::new(Ipv4Addr::new(1, 2, 3, 4), 12345, "SSH".to_string());
    tracker.record_packet(b"hello", Duration::from_millis(150)); // Nmap fingerprint (>100ms)
    
    let report = tracker.confusion_report();
    
    assert_eq!(report["src_ip"], "1.2.3.4");
    assert_eq!(report["bytes_wasted"], 5);
    assert_eq!(report["tool_signature"], "Nmap");
    assert!(report["summary"].as_str().unwrap().contains("Confused Nmap"));
}

#[test]
fn test_credential_regex_detection() {
    let mut tracker = SessionTracker::new(Ipv4Addr::new(1, 2, 3, 4), 12345, "HTTP".to_string());
    
    // Test HTTP Basic Auth
    tracker.record_packet(b"GET / HTTP/1.1\r\nAuthorization: Basic dXNlcjpwYXNz\r\n\r\n", Duration::from_millis(1));
    assert_eq!(tracker.credential_tries, 1);
    
    // Test SSH user (null terminated)
    tracker.record_packet(b"root\x00", Duration::from_millis(1));
    assert_eq!(tracker.credential_tries, 2);
    
    // Test TLS Handshake
    tracker.record_packet(b"\x16\x03\x01\x00\x00", Duration::from_millis(1));
    assert_eq!(tracker.credential_tries, 3);
}
