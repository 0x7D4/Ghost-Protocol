use ghost_ui::App;
use ghost_common::DashboardEvent;
use serde_json::json;

#[test]
fn test_leaderboard_entry_after_session_closed() {
    let mut app = App::new();
    let report = json!({
        "src_ip": "1.2.3.4",
        "tool_signature": "Nmap",
        "score": 150,
        "duration_secs": 60,
        "credential_tries": 2
    });

    app.handle_event(DashboardEvent::SessionClosed { report });

    assert_eq!(app.leaderboard.len(), 1);
    assert_eq!(app.leaderboard[0].ip, "1.2.3.4");
    assert_eq!(app.leaderboard[0].score, 150);
}

#[test]
fn test_leaderboard_sorting() {
    let mut app = App::new();
    
    app.handle_event(DashboardEvent::SessionClosed { 
        report: json!({"src_ip": "1", "tool_signature": "X", "score": 100, "duration_secs": 1, "credential_tries": 0}) 
    });
    app.handle_event(DashboardEvent::SessionClosed { 
        report: json!({"src_ip": "2", "tool_signature": "X", "score": 300, "duration_secs": 1, "credential_tries": 0}) 
    });
    app.handle_event(DashboardEvent::SessionClosed { 
        report: json!({"src_ip": "3", "tool_signature": "X", "score": 200, "duration_secs": 1, "credential_tries": 0}) 
    });

    assert_eq!(app.leaderboard[0].ip, "2");
    assert_eq!(app.leaderboard[1].ip, "3");
    assert_eq!(app.leaderboard[2].ip, "1");
}

#[test]
fn test_ebpf_status_update() {
    let mut app = App::new();
    let status = DashboardEvent::EbpfStatus {
        persona_index: 2,
        rotation_secs_remaining: 45,
        scanner_count: 12,
        allowlist_size: 5,
    };

    app.handle_event(status);

    let s = app.ebpf_status.as_ref().unwrap();
    assert_eq!(s.persona_index, 2);
    assert_eq!(s.rotation_secs_remaining, 45);
    assert_eq!(s.scanner_count, 12);
    assert_eq!(s.allowlist_size, 5);
}
