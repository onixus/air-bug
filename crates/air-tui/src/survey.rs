use air_capture::survey::{display_bytes, mac_string, Survey};
use crossterm::event::{self, Event, KeyCode, KeyEventKind, KeyModifiers};
use crossterm::terminal::{enable_raw_mode, EnterAlternateScreen};
use crossterm::ExecutableCommand;
use ratatui::backend::CrosstermBackend;
use ratatui::layout::{Constraint, Layout};
use ratatui::widgets::{Block, Borders, Cell, Paragraph, Row, Table};
use ratatui::Terminal;
use std::io::{self, IsTerminal, Stdout};
use std::time::Duration;

pub enum Action {
    Quit,
    Previous,
    Next,
    ToggleHop,
    None,
}
pub struct Dashboard {
    terminal: Terminal<CrosstermBackend<Stdout>>,
    _guard: super::TerminalGuard,
    offset: usize,
    clients: bool,
}
impl Dashboard {
    pub fn open() -> anyhow::Result<Self> {
        anyhow::ensure!(
            io::stdin().is_terminal() && io::stdout().is_terminal(),
            "survey requires a terminal; use --plain for noninteractive output"
        );
        enable_raw_mode()?;
        let guard = super::TerminalGuard;
        io::stdout().execute(EnterAlternateScreen)?;
        let terminal = Terminal::new(CrosstermBackend::new(io::stdout()))?;
        Ok(Self {
            terminal,
            _guard: guard,
            offset: 0,
            clients: false,
        })
    }
    pub fn input(&mut self) -> io::Result<Action> {
        if !event::poll(Duration::ZERO)? {
            return Ok(Action::None);
        }
        if let Event::Key(key) = event::read()? {
            if key.kind != KeyEventKind::Press {
                return Ok(Action::None);
            }
            return Ok(match key.code {
                KeyCode::Char('q') | KeyCode::Esc => Action::Quit,
                KeyCode::Char('c') if key.modifiers.contains(KeyModifiers::CONTROL) => Action::Quit,
                KeyCode::Left => Action::Previous,
                KeyCode::Right => Action::Next,
                KeyCode::Char(' ') => Action::ToggleHop,
                KeyCode::Up => {
                    self.offset = self.offset.saturating_sub(1);
                    Action::None
                }
                KeyCode::Down => {
                    self.offset = self.offset.saturating_add(1);
                    Action::None
                }
                KeyCode::Tab => {
                    self.clients = !self.clients;
                    self.offset = 0;
                    Action::None
                }
                _ => Action::None,
            });
        }
        Ok(Action::None)
    }
    pub fn draw(&mut self, data: &Survey, status: &str, now: Duration) -> io::Result<()> {
        let size = if self.clients {
            data.stations.len()
        } else {
            data.aps.len()
        };
        self.offset = self.offset.min(size.saturating_sub(1));
        let ap_offset = if self.clients { 0 } else { self.offset };
        let client_offset = if self.clients { self.offset } else { 0 };
        let clients = self.clients;
        self.terminal
            .draw(|f| render(f, data, status, now, clients, ap_offset, client_offset))?;
        Ok(())
    }
}

fn render(
    f: &mut ratatui::Frame,
    data: &Survey,
    status: &str,
    now: Duration,
    clients: bool,
    ap_offset: usize,
    client_offset: usize,
) {
    let areas = Layout::vertical([
        Constraint::Length(3),
        Constraint::Percentage(55),
        Constraint::Min(4),
        Constraint::Length(5),
        Constraint::Length(2),
    ])
    .split(f.area());
    f.render_widget(
        Paragraph::new(status).block(
            Block::default()
                .borders(Borders::ALL)
                .title("Passive Wi-Fi survey"),
        ),
        areas[0],
    );
    let aps = data.aps.iter().skip(ap_offset).map(|(mac, ap)| {
        Row::new(vec![
            mac_string(mac),
            display_bytes(&ap.ssid),
            ap.channel
                .map(|c| c.to_string())
                .unwrap_or_else(|| "?".into()),
            ap.last_direct_observation
                .as_ref()
                .and_then(|o| o.radio)
                .map(|r| r.band)
                .unwrap_or("?")
                .into(),
            ap.signal
                .map(|s| s.to_string())
                .unwrap_or_else(|| "?".into()),
            if ap.security.is_empty() {
                "?".into()
            } else {
                ap.security.clone()
            },
            ap.beacons.to_string(),
            ap.packets.to_string(),
            ap.verification_label().into(),
            ap.pmf().into(),
            now.saturating_sub(ap.last_seen).as_secs().to_string(),
        ])
    });
    let table = Table::new(
        aps,
        [
            Constraint::Length(17),
            Constraint::Min(12),
            Constraint::Length(4),
            Constraint::Length(6),
            Constraint::Length(5),
            Constraint::Length(9),
            Constraint::Length(8),
            Constraint::Length(8),
            Constraint::Length(8),
            Constraint::Length(10),
            Constraint::Length(5),
        ],
    )
    .header(Row::new([
        "BSSID", "SSID", "CH", "Band", "dBm", "Security", "Beacons", "Packets", "Evidence", "PMF",
        "Age/s",
    ]))
    .block(Block::default().borders(Borders::ALL).title(format!(
        "{} Access points ({})",
        if clients { "" } else { ">" },
        data.aps.len()
    )));
    f.render_widget(table, areas[1]);
    let stations = data.stations.iter().skip(client_offset).map(|(mac, sta)| {
        Row::new(vec![
            Cell::from(mac_string(mac)),
            Cell::from(
                sta.bssid
                    .as_ref()
                    .map(mac_string)
                    .unwrap_or_else(|| "unassociated?".into()),
            ),
            Cell::from(
                sta.signal
                    .map(|s| s.to_string())
                    .unwrap_or_else(|| "?".into()),
            ),
            Cell::from(sta.packets.to_string()),
            Cell::from(now.saturating_sub(sta.last_seen).as_secs().to_string()),
            Cell::from(display_bytes(&sta.probe)),
        ])
    });
    f.render_widget(
        Table::new(
            stations,
            [
                Constraint::Length(17),
                Constraint::Length(17),
                Constraint::Length(5),
                Constraint::Length(8),
                Constraint::Length(5),
                Constraint::Min(10),
            ],
        )
        .header(Row::new([
            "Client",
            "Last BSSID",
            "dBm",
            "Packets",
            "Age/s",
            "Last probe SSID",
        ]))
        .block(Block::default().borders(Borders::ALL).title(format!(
            "{} Clients ({})",
            if clients { ">" } else { "" },
            data.stations.len()
        ))),
        areas[2],
    );
    let mut details = data
        .aps
        .iter()
        .nth(ap_offset)
        .map(|(mac, ap)| {
            let audit = ap
                .security_audit
                .as_ref()
                .filter(|_| ap.audit_last_status == Some("valid"));
            let notes = audit
                .map(|a| {
                    format!(
                        "{}: {}",
                        a.advertised.assessment.advertised_mode,
                        a.advertised
                            .assessment
                            .findings
                            .iter()
                            .map(|f| format!("{} ({})", f.id, f.recommendation))
                            .collect::<Vec<_>>()
                            .join("; ")
                    )
                })
                .unwrap_or_else(|| ap.audit_last_status.unwrap_or("unknown").into());
            format!(
                "{} audit: {} | RNR reports: {} | capture: {}",
                mac_string(mac),
                notes,
                data.rnr_neighbors
                    .values()
                    .filter(|n| n.reporter_bssid == *mac)
                    .count(),
                ap.capture_observations().join(", ")
            )
        })
        .unwrap_or_else(|| "Audit and capture diagnostics: no AP observed".into());
    if let Some((_, ap)) = data.aps.iter().nth(ap_offset) {
        details.push_str(&format!(
            "\n{} | {}\nRoaming advertisement: {}",
            ap.enterprise.summary(),
            ap.enterprise.observations().join("; "),
            ap.roaming_capabilities
                .as_ref()
                .map(|c| c.summary())
                .unwrap_or_else(|| "unknown".into())
        ));
    }
    details.push_str(&format!(
        "\nRoaming: {} events, {} evicted, {} malformed (unverified)",
        data.roaming.events.len(),
        data.roaming.evicted,
        data.roaming.malformed_management
    ));
    if let Some(e) = data.roaming.events.back() {
        details.push_str(&format!(
            "\n#{} {} status={} reason={} client={} AP={}",
            e.record_index,
            e.kind,
            e.status_code
                .map(|s| s.to_string())
                .unwrap_or_else(|| "?".into()),
            e.reason_code
                .map(|s| s.to_string())
                .unwrap_or_else(|| "?".into()),
            e.station,
            e.bssid
        ));
    }
    f.render_widget(Paragraph::new(details), areas[3]);
    f.render_widget(Paragraph::new("←/→ channel (hold) · Space hop/hold · Tab table · ↑/↓ scroll · q/Esc/Ctrl-C stop\nHS/FT/PMKID: structural evidence; PMF: advertised. ? = unobserved; retry frames counted."), areas[4]);
}

#[cfg(test)]
mod tests {
    use super::*;
    use air_capture::survey::{AccessPoint, Station};
    #[test]
    fn dashboard_renders_live_rows_and_survives_small_terminals() {
        let mut data = Survey::default();
        let ap = [2, 1, 2, 3, 4, 5];
        data.aps.insert(
            ap,
            AccessPoint {
                ssid: b"Lab\x1b".to_vec(),
                channel: Some(6),
                signal: Some(-42),
                handshake_m1m2: true,
                pmkid: true,
                ..Default::default()
            },
        );
        data.stations.insert(
            [2, 6, 7, 8, 9, 10],
            Station {
                bssid: Some(ap),
                ..Default::default()
            },
        );
        let mut response = vec![0x30, 0, 0, 0];
        response.extend([2, 6, 7, 8, 9, 10]);
        response.extend(ap);
        response.extend(ap);
        response.extend([0; 2]);
        response.extend([0, 0, 17, 0, 0, 0]);
        data.observe(105, &response, Duration::ZERO, None);
        for (w, h) in [(120, 32), (60, 12), (10, 3)] {
            let mut terminal = Terminal::new(ratatui::backend::TestBackend::new(w, h)).unwrap();
            terminal
                .draw(|f| render(f, &data, "CH 6 | hold", Duration::ZERO, false, 0, 0))
                .unwrap();
            if w == 120 {
                let buffer = terminal.backend().buffer();
                let text: String = buffer.content.iter().map(|c| c.symbol()).collect();
                assert!(text.contains("Lab\\x1b"));
                assert!(text.contains("02:06:07:08:09:0a"));
                assert!(text.contains("CH 6 | hold"));
                assert!(text.contains("HS+PMKID"));
                assert!(text.contains("EAP req/resp="));
                assert!(text.contains("Roaming advertisement:"));
                assert!(text.contains("Roaming: 1 events"));
                assert!(text.contains("reassociation_response status=17 reason=?"));
            }
        }
    }
}
