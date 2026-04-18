//! Ghost-Protocol TUI Dashboard.

use anyhow::Result;
use crossterm::{
    event::{self, DisableMouseCapture, EnableMouseCapture, Event, KeyCode},
    execute,
    terminal::{disable_raw_mode, enable_raw_mode, EnterAlternateScreen, LeaveAlternateScreen},
};
use ghost_common::{DashboardEvent, SOCKET_PATH};
use ghost_ui::App;
use ratatui::{
    backend::CrosstermBackend,
    layout::{Constraint, Direction, Layout},
    widgets::{Block, Borders, Paragraph, Row, Table, List, ListItem},
    Frame, Terminal,
};
use std::{io, time::{Duration, Instant}, sync::{Arc, Mutex as StdMutex}};
use tokio::io::AsyncBufReadExt;
use tokio::net::UnixStream;

#[tokio::main]
async fn main() -> Result<()> {
    // Setup terminal
    enable_raw_mode()?;
    let mut stdout = io::stdout();
    execute!(stdout, EnterAlternateScreen, EnableMouseCapture)?;
    let backend = CrosstermBackend::new(stdout);
    let mut terminal = Terminal::new(backend)?;

    // Create app state
    let app = Arc::new(StdMutex::new(App::new()));

    // Socket client task
    let app_clone = app.clone();
    tokio::spawn(async move {
        loop {
            match UnixStream::connect(SOCKET_PATH).await {
                Ok(stream) => {
                    let reader = tokio::io::BufReader::new(stream);
                    let mut lines = reader.lines();
                    while let Ok(Some(line)) = lines.next_line().await {
                        if let Ok(event) = serde_json::from_str::<DashboardEvent>(&line) {
                            let mut app = app_clone.lock().unwrap();
                            app.handle_event(event);
                        }
                    }
                }
                Err(_) => {
                    tokio::time::sleep(Duration::from_secs(1)).await;
                }
            }
        }
    });

    // Main loop
    let mut last_tick = Instant::now();
    let tick_rate = Duration::from_millis(500);

    loop {
        terminal.draw(|f| ui(f, &app.lock().unwrap()))?;

        let timeout = tick_rate
            .checked_sub(last_tick.elapsed())
            .unwrap_or_else(|| Duration::from_secs(0));

        if event::poll(timeout)? {
            if let Event::Key(key) = event::read()? {
                if let KeyCode::Char('q') = key.code {
                    break;
                }
            }
        }

        if last_tick.elapsed() >= tick_rate {
            app.lock().unwrap().tick();
            last_tick = Instant::now();
        }
    }

    // Restore terminal
    disable_raw_mode()?;
    execute!(
        terminal.backend_mut(),
        LeaveAlternateScreen,
        DisableMouseCapture
    )?;
    terminal.show_cursor()?;

    Ok(())
}

fn ui(f: &mut Frame, app: &App) {
    let chunks = Layout::default()
        .direction(Direction::Vertical)
        .constraints([Constraint::Percentage(50), Constraint::Percentage(50)].as_ref())
        .split(f.area());

    let top_chunks = Layout::default()
        .direction(Direction::Horizontal)
        .constraints([Constraint::Percentage(50), Constraint::Percentage(50)].as_ref())
        .split(chunks[0]);

    let bottom_chunks = Layout::default()
        .direction(Direction::Horizontal)
        .constraints([Constraint::Percentage(50), Constraint::Percentage(50)].as_ref())
        .split(chunks[1]);

    // Panel 1: Active Scanners
    let scanner_rows: Vec<Row> = app.active_scanners.values().map(|s| {
        Row::new(vec![
            s.ip.clone(),
            s.persona.clone(),
            format!("{}s", s.started_at.elapsed().as_secs()),
            s.score.to_string(),
        ])
    }).collect();

    let scanner_table = Table::new(
        scanner_rows,
        [
            Constraint::Percentage(30),
            Constraint::Percentage(30),
            Constraint::Percentage(20),
            Constraint::Percentage(20),
        ]
    )
    .header(Row::new(vec!["IP", "Persona", "Duration", "Score"]))
    .block(Block::default().borders(Borders::ALL).title("Active Engagements"));
    f.render_widget(scanner_table, top_chunks[0]);

    // Panel 2: eBPF Status
    let status_text = if let Some(ref status) = app.ebpf_status {
        format!(
            "Persona Index: {}\nRotation: {}s remaining\nScanner Map: {}\nAllowlist: {}",
            status.persona_index, status.rotation_secs_remaining, status.scanner_count, status.allowlist_size
        )
    } else {
        "Waiting for status update...".to_string()
    };
    let status_para = Paragraph::new(status_text)
        .block(Block::default().borders(Borders::ALL).title("eBPF Data Plane Metrics"));
    f.render_widget(status_para, top_chunks[1]);

    // Panel 3: Leaderboard
    let leaderboard_rows: Vec<Row> = app.leaderboard.iter().map(|s| {
        Row::new(vec![
            s.ip.clone(),
            s.tool.clone(),
            s.score.to_string(),
            format!("{}s", s.duration_secs),
            s.cred_tries.to_string(),
        ])
    }).collect();

    let leaderboard_table = Table::new(
        leaderboard_rows,
        [
            Constraint::Percentage(25),
            Constraint::Percentage(20),
            Constraint::Percentage(15),
            Constraint::Percentage(20),
            Constraint::Percentage(20),
        ]
    )
    .header(Row::new(vec!["IP", "Tool", "Score", "Time", "Creds"]))
    .block(Block::default().borders(Borders::ALL).title("Confusion Leaderboard (Top 10)"));
    f.render_widget(leaderboard_table, bottom_chunks[0]);

    // Panel 4: Event Log
    let events: Vec<ListItem> = app.event_log.iter().rev().take(20).map(|log| {
        ListItem::new(log.as_str())
    }).collect();
    let event_list = List::new(events)
        .block(Block::default().borders(Borders::ALL).title("Real-time Event Log"));
    f.render_widget(event_list, bottom_chunks[1]);
}
