use crossterm::event::{self, Event, KeyCode, KeyEventKind, KeyModifiers};
use crossterm::terminal::{
    disable_raw_mode, enable_raw_mode, EnterAlternateScreen, LeaveAlternateScreen,
};
use crossterm::ExecutableCommand;
use ratatui::backend::CrosstermBackend;
use ratatui::layout::{Constraint, Direction, Layout};
use ratatui::style::{Color, Style};
use ratatui::text::Line;
use ratatui::widgets::{Block, Borders, Paragraph, Tabs};
use ratatui::Terminal;
use std::io::{stdin, stdout, IsTerminal};

#[derive(Clone, Copy, PartialEq, Eq)]
enum Tab {
    Monitor,
    Capture,
    Cracking,
    Help,
}

impl Tab {
    fn titles() -> &'static [&'static str] {
        &["Monitor", "Capture", "Cracking", "Help/About"]
    }
    fn index(self) -> usize {
        match self {
            Tab::Monitor => 0,
            Tab::Capture => 1,
            Tab::Cracking => 2,
            Tab::Help => 3,
        }
    }
    fn from_index(i: usize) -> Self {
        match i {
            0 => Tab::Monitor,
            1 => Tab::Capture,
            2 => Tab::Cracking,
            _ => Tab::Help,
        }
    }
}

struct TerminalGuard;
impl Drop for TerminalGuard {
    fn drop(&mut self) {
        let _ = disable_raw_mode();
        let _ = stdout().execute(LeaveAlternateScreen);
    }
}

/// Display a UI preview; no capture or verification jobs are started here.
pub fn run() -> anyhow::Result<()> {
    anyhow::ensure!(
        stdin().is_terminal() && stdout().is_terminal(),
        "TUI preview requires an interactive terminal"
    );
    enable_raw_mode()?;
    let _guard = TerminalGuard;
    stdout().execute(EnterAlternateScreen)?;
    let backend = CrosstermBackend::new(stdout());
    let mut terminal = Terminal::new(backend)?;
    let mut tab = Tab::Monitor;
    let mut should_quit = false;

    while !should_quit {
        terminal.draw(|f| {
            let chunks = Layout::default()
                .direction(Direction::Vertical)
                .constraints([Constraint::Length(3), Constraint::Min(0)])
                .split(f.area());

            let tabs = Tabs::new(
                Tab::titles()
                    .iter()
                    .cloned()
                    .map(Line::from)
                    .collect::<Vec<_>>(),
            )
            .block(Block::default().borders(Borders::ALL).title("air-tui"))
            .select(tab.index())
            .style(Style::default().fg(Color::White))
            .highlight_style(Style::default().fg(Color::Yellow));
            f.render_widget(tabs, chunks[0]);

            let body = match tab {
                Tab::Monitor => Paragraph::new("Monitor interfaces\n\nNo interfaces (stub).")
                    .block(Block::default().borders(Borders::ALL).title("Monitor")),
                Tab::Capture => Paragraph::new("Live capture\n\nPackets/Clients/APs (stub).")
                    .block(Block::default().borders(Borders::ALL).title("Capture")),
                Tab::Cracking => {
                    Paragraph::new("UI preview only — no verification job is running.\n\nUse the aircrack CLI subcommand for offline verification.")
                        .block(Block::default().borders(Borders::ALL).title("Cracking"))
                }
                Tab::Help => Paragraph::new(
                    "UI preview — capture and verification are not connected.\n\nKeys: Left/Right/Tab switch tabs; q, Esc or Ctrl-C quit.",
                )
                .block(Block::default().borders(Borders::ALL).title("Help")),
            };
            f.render_widget(body, chunks[1]);
        })?;

        if event::poll(std::time::Duration::from_millis(250))? {
            if let Event::Key(k) = event::read()? {
                if k.kind == KeyEventKind::Press {
                    match k.code {
                        KeyCode::Char('c') if k.modifiers.contains(KeyModifiers::CONTROL) => {
                            should_quit = true
                        }
                        KeyCode::Char('q') | KeyCode::Esc => should_quit = true,
                        KeyCode::Left => tab = Tab::from_index((tab.index() + 3) % 4),
                        KeyCode::Right => tab = Tab::from_index((tab.index() + 1) % 4),
                        KeyCode::Tab => tab = Tab::from_index((tab.index() + 1) % 4),
                        _ => {}
                    }
                }
            }
        }
    }

    Ok(())
}

pub mod survey;

pub mod wifi_scan;

pub mod apex_tokens;

mod wifi_charts;
