//! Presentation only: no radio/device APIs.
use crossterm::{
    event::{self, Event, KeyCode, KeyEventKind, KeyModifiers},
    terminal::{enable_raw_mode, EnterAlternateScreen},
    ExecutableCommand,
};
use ratatui::{
    backend::CrosstermBackend,
    layout::{Constraint, Layout},
    style::{Modifier, Style},
    widgets::{Block, Borders, Paragraph, Row, Table, TableState, Wrap},
    Terminal,
};
use std::{
    io::{self, IsTerminal, Stdout},
    time::Duration,
};

#[derive(Clone, Debug)]
pub struct AccessPoint {
    /// Actual decoded SSID, None when unavailable. Used for filtering, not labels.
    pub ssid: Option<String>,
    pub name: String,
    pub security: String,
    pub current: bool,
    pub bssid: String,
    pub band: String,
    pub channel: Option<u16>,
    pub signal: Option<i16>,
    pub noise: Option<i16>,
}
pub fn matches_ssid(ssid: Option<&str>, filter: &str) -> bool {
    filter.is_empty() || ssid.is_some_and(|s| s.to_lowercase().contains(&filter.to_lowercase()))
}
#[derive(Default)]
pub struct View {
    pub rows: Vec<AccessPoint>,
    pub filter: String,
    pub theme: super::apex_tokens::Theme,
    editing: bool,
    saved_filter: String,
    weakest_first: bool,
    offset: usize,
    sort: usize,
    band: usize,
    help: bool,
    details: bool,
    menu: Option<usize>,
    history: super::wifi_charts::History,
    chart: u8,
    chart_target: Option<(String, String)>,
    channel_offset: usize,
}
pub enum Action {
    Quit,
    Refresh,
    TogglePause,
    None,
}
impl View {
    pub fn new(filter: String) -> Self {
        Self {
            filter,
            ..Default::default()
        }
    }
    pub fn replace(&mut self, rows: Vec<AccessPoint>) {
        let selected = self
            .visible()
            .get(self.offset)
            .and_then(|r| (r.bssid != "<restricted>").then(|| r.bssid.clone()));
        self.history.record(&rows);
        self.rows = rows;
        if let Some(bssid) = selected {
            if let Some(index) = self.visible().iter().position(|r| r.bssid == bssid) {
                self.offset = index;
            }
        }
        self.clamp();
    }
    pub fn visible(&self) -> Vec<&AccessPoint> {
        let mut rows: Vec<_> = self
            .rows
            .iter()
            .filter(|r| matches_ssid(r.ssid.as_deref(), &self.filter))
            .filter(|r| self.band == 0 || r.band == ["all", "2.4", "5", "6"][self.band])
            .collect();
        rows.sort_by(|a, b| {
            let order = match self.sort {
                1 => a.name.to_lowercase().cmp(&b.name.to_lowercase()),
                2 => a.channel.cmp(&b.channel),
                3 => a.security.cmp(&b.security),
                _ => std::cmp::Ordering::Equal,
            };
            if self.sort != 0 {
                return (if self.weakest_first {
                    order.reverse()
                } else {
                    order
                })
                .then_with(|| a.bssid.cmp(&b.bssid));
            }
            match (a.signal, b.signal) {
                (Some(a), Some(b)) => {
                    if self.weakest_first {
                        a.cmp(&b)
                    } else {
                        b.cmp(&a)
                    }
                }
                (Some(_), None) => std::cmp::Ordering::Less,
                (None, Some(_)) => std::cmp::Ordering::Greater,
                _ => std::cmp::Ordering::Equal,
            }
            .then_with(|| a.name.cmp(&b.name))
            .then_with(|| a.bssid.cmp(&b.bssid))
        });
        rows
    }
    fn clamp(&mut self) {
        self.offset = self.offset.min(self.visible().len().saturating_sub(1));
    }
    fn key(&mut self, code: KeyCode, modifiers: KeyModifiers) -> Action {
        if code == KeyCode::Char('c') && modifiers.contains(KeyModifiers::CONTROL) {
            return Action::Quit;
        }
        if code == KeyCode::F(10) {
            return Action::Quit;
        }
        if let Some(index) = self.menu {
            match code {
                KeyCode::Esc | KeyCode::Tab => self.menu = None,
                KeyCode::Up => self.menu = Some(index.saturating_sub(1)),
                KeyCode::Down => self.menu = Some((index + 1).min(11)),
                KeyCode::Enter => {
                    self.menu = None;
                    return self.key(KeyCode::F((index + 1) as u8), KeyModifiers::NONE);
                }
                _ => {}
            }
            return Action::None;
        }
        if self.chart != 0 {
            match code {
                KeyCode::Esc | KeyCode::Enter => self.chart = 0,
                KeyCode::Tab => {
                    self.chart = 0;
                    self.menu = Some(0);
                }
                KeyCode::F(2) => self.theme = self.theme.next(),
                KeyCode::F(5) => return Action::Refresh,
                KeyCode::F(9) | KeyCode::Char(' ') => return Action::TogglePause,
                KeyCode::Down => {
                    self.channel_offset = (self.channel_offset + 1).min(
                        super::wifi_charts::distribution(&self.rows)
                            .len()
                            .saturating_sub(1),
                    )
                }
                KeyCode::Up => self.channel_offset = self.channel_offset.saturating_sub(1),
                KeyCode::Home => self.channel_offset = 0,
                _ => {}
            }
            return Action::None;
        }
        if self.help || self.details {
            match code {
                KeyCode::Esc | KeyCode::Enter | KeyCode::F(1) => {
                    self.help = false;
                    self.details = false;
                }
                KeyCode::Tab => {
                    self.help = false;
                    self.details = false;
                    self.menu = Some(0);
                }
                _ => {}
            }
            return Action::None;
        }
        if self.editing {
            match code {
                KeyCode::Esc => {
                    self.filter = self.saved_filter.clone();
                    self.editing = false;
                }
                KeyCode::Enter => self.editing = false,
                KeyCode::Delete => self.filter.clear(),
                KeyCode::Backspace => {
                    self.filter.pop();
                }
                KeyCode::Char('u') if modifiers.contains(KeyModifiers::CONTROL) => {
                    self.filter.clear()
                }
                KeyCode::Char(c)
                    if !c.is_control()
                        && !modifiers.intersects(KeyModifiers::CONTROL | KeyModifiers::ALT)
                        && self.filter.chars().count() < 128 =>
                {
                    self.filter.push(c)
                }
                _ => {}
            }
            self.offset = 0;
            return Action::None;
        }
        match code {
            KeyCode::F(11) => {
                self.chart_target = self.visible().get(self.offset).and_then(|r| {
                    super::wifi_charts::identity(&r.bssid).map(|id| (id, r.name.clone()))
                });
                self.chart = 1;
            }
            KeyCode::F(12) => {
                self.chart = 2;
                self.channel_offset = 0;
            }
            KeyCode::F(1) => self.help = true,
            KeyCode::Tab => self.menu = Some(0),
            KeyCode::Enter => self.details = true,
            KeyCode::F(9) | KeyCode::Char(' ') => return Action::TogglePause,
            KeyCode::F(4) => {
                self.sort = (self.sort + 1) % 4;
                self.offset = 0;
            }
            KeyCode::F(7) => {
                self.band = (self.band + 1) % 4;
                self.offset = 0;
            }
            KeyCode::F(8) => {
                self.filter.clear();
                self.band = 0;
                let index = self.visible().iter().position(|r| r.current);
                if let Some(index) = index {
                    self.offset = index;
                }
            }
            KeyCode::End => self.offset = self.visible().len().saturating_sub(1),
            KeyCode::Char('q') | KeyCode::Esc => return Action::Quit,
            KeyCode::F(5) | KeyCode::Char('r') => return Action::Refresh,
            KeyCode::F(3) | KeyCode::Char('/') => {
                self.saved_filter = self.filter.clone();
                self.editing = true;
            }
            KeyCode::F(2) | KeyCode::Char('t') => self.theme = self.theme.next(),
            KeyCode::F(6) | KeyCode::Char('s') => {
                self.weakest_first = !self.weakest_first;
                self.offset = 0;
            }
            KeyCode::Delete | KeyCode::Char('c') => {
                self.filter.clear();
                self.offset = 0;
            }
            KeyCode::Down => self.offset = self.offset.saturating_add(1),
            KeyCode::Up => self.offset = self.offset.saturating_sub(1),
            KeyCode::PageDown => self.offset = self.offset.saturating_add(10),
            KeyCode::PageUp => self.offset = self.offset.saturating_sub(10),
            KeyCode::Home => self.offset = 0,
            _ => {}
        }
        self.clamp();
        Action::None
    }
    fn render(&self, frame: &mut ratatui::Frame, status: &str) {
        let palette = self.theme.palette();
        frame.render_widget(
            Block::default().style(
                Style::default()
                    .fg(palette.text_primary)
                    .bg(palette.bg_canvas),
            ),
            frame.area(),
        );
        let block = || {
            Block::default()
                .borders(Borders::ALL)
                .style(
                    Style::default()
                        .fg(palette.text_primary)
                        .bg(palette.surface_1),
                )
                .border_style(Style::default().fg(palette.border_control))
        };
        let areas = Layout::vertical([
            Constraint::Length(5),
            Constraint::Length(3),
            Constraint::Min(1),
            Constraint::Length(2),
        ])
        .split(frame.area());
        frame.render_widget(
            Paragraph::new(status)
                .wrap(Wrap { trim: false })
                .block(block().title(format!(
                    "WI-FI SCAN | APEX · {} · F2 theme",
                    self.theme.name()
                ))),
            areas[0],
        );
        frame.render_widget(
            Paragraph::new(format!(
                "{}{}",
                self.filter
                    .chars()
                    .map(|c| if c.is_control() {
                        c.escape_default().to_string()
                    } else {
                        c.to_string()
                    })
                    .collect::<String>(),
                if self.editing { "▏" } else { "" }
            ))
            .block(
                block()
                    .border_style(Style::default().fg(if self.editing {
                        palette.focus_ring
                    } else {
                        palette.border_control
                    }))
                    .title(if self.editing {
                        "SSID filter · Enter apply · Esc cancel · Delete clear"
                    } else {
                        "SSID filter · F3 edit · Delete clear"
                    }),
            ),
            areas[1],
        );
        let rows = self.visible();
        let shown = rows.len();
        let table = Table::new(
            rows.iter().map(|r| {
                Row::new(vec![
                    if r.current {
                        "* Connected".into()
                    } else {
                        String::new()
                    },
                    r.name.clone(),
                    r.bssid.clone(),
                    r.security.clone(),
                    r.band.clone(),
                    number(r.channel),
                    number(r.signal),
                    number(r.noise),
                ])
                .style(if r.current {
                    Style::default()
                        .fg(palette.success)
                        .bg(palette.success_subtle)
                        .add_modifier(Modifier::BOLD)
                } else {
                    Style::default()
                })
            }),
            [
                Constraint::Length(11),
                Constraint::Min(16),
                Constraint::Length(17),
                Constraint::Length(18),
                Constraint::Length(6),
                Constraint::Length(7),
                Constraint::Length(10),
                Constraint::Length(10),
            ],
        )
        .header(
            Row::new([
                "Status",
                "SSID",
                "BSSID",
                "Security",
                "GHz",
                "Channel",
                "Signal/dBm",
                "Noise/dBm",
            ])
            .style(Style::default().fg(palette.accent).bg(palette.surface_2)),
        )
        .row_highlight_style(Style::default().add_modifier(Modifier::UNDERLINED | Modifier::BOLD))
        .highlight_symbol("> ")
        .block(block().title(format!(
            "{shown}/{} APs · {} {} · band {} · {}/{}",
            self.rows.len(),
            ["signal", "SSID", "channel", "security"][self.sort],
            if self.weakest_first {
                "reverse"
            } else {
                "default"
            },
            ["all", "2.4", "5", "6"][self.band],
            if shown == 0 { 0 } else { self.offset + 1 },
            shown
        )));
        let mut state =
            TableState::default().with_selected(if shown == 0 { None } else { Some(self.offset) });
        frame.render_stateful_widget(table, areas[2], &mut state);
        if shown == 0 && areas[2].height > 3 {
            let inner = ratatui::layout::Rect::new(
                areas[2].x + 1,
                areas[2].y + 2,
                areas[2].width.saturating_sub(2),
                1,
            );
            frame.render_widget(
                Paragraph::new(if self.rows.is_empty() {
                    "No scan results yet / OS returned no networks"
                } else {
                    "No SSID matches (restricted identifiers cannot match a name)"
                }),
                inner,
            );
        }
        let actions = [
            "F1  Help",
            "F2  Theme",
            "F3  SSID filter",
            "F4  Sort column",
            "F5  Refresh once",
            "F6  Reverse order",
            "F7  Band filter",
            "F8  Current AP",
            "F9  Pause / resume",
            "F10 Quit",
            "F11 Signal history",
            "F12 Channels",
        ];
        if let Some(index) = self.menu {
            let body = actions
                .iter()
                .enumerate()
                .map(|(i, text)| format!("{} {text}", if i == index { ">" } else { " " }))
                .collect::<Vec<_>>()
                .join("\n");
            frame.render_widget(
                Paragraph::new(body)
                    .scroll((
                        index.saturating_sub(usize::from(areas[2].height.saturating_sub(3))) as u16,
                        0,
                    ))
                    .block(block().title("ACTIONS · arrows + Enter · Esc close")),
                areas[2],
            );
        } else if self.chart == 1 {
            self.history
                .render(frame, areas[2], self.chart_target.as_ref(), palette);
        } else if self.chart == 2 {
            super::wifi_charts::render_channels(
                frame,
                areas[2],
                &self.rows,
                self.channel_offset,
                palette,
            );
        } else if self.help {
            let body = format!("{}\n\nTab: actions menu (no function keys needed)\nArrows / PageUp / PageDown / Home / End: select AP\nEnter: AP details | Space: pause / resume\nDelete: clear filter | Esc: close panel / quit\nF3: type SSID in any language; Enter apply, Esc cancel\nOn Mac, Fn may be needed for F1–F10.\n* Connected: current BSSID; > selected row.\nPausing cancels the scan; manual refresh works while paused.", actions.join("\n"));
            frame.render_widget(
                Paragraph::new(body)
                    .wrap(Wrap { trim: false })
                    .block(block().title("HELP · Enter / Esc close")),
                areas[2],
            );
        } else if self.details {
            let body = rows.get(self.offset).map(|r| format!(
                "SSID: {}\nBSSID: {}\nSecurity: {}\nBand: {} GHz    Channel: {}\nSignal: {} dBm    Noise: {} dBm\nSNR: {} dB\nStatus: {}\n\nValues belong to the last snapshot; missing identifiers are never guessed.",
                r.name, r.bssid, r.security, r.band, number(r.channel), number(r.signal), number(r.noise),
                number(r.signal.zip(r.noise).map(|(signal, noise)| signal - noise)),
                if r.current { "* Connected" } else { "Not identified as current" }
            )).unwrap_or_else(|| "No selected AP. Clear filters or refresh.".into());
            frame.render_widget(
                Paragraph::new(body)
                    .wrap(Wrap { trim: false })
                    .block(block().title("ACCESS POINT · Enter / Esc close")),
                areas[2],
            );
        }
        frame.render_widget(Paragraph::new("Tab Actions | F1 Help | F2 Theme | F3 Filter | F5 Refresh | F9/Space Pause | F10/Esc Quit\nF11 Signal history | F12 Channels | Enter Details | F4 Sort | F7 Band | F8 Current AP")
            .style(Style::default().fg(palette.text_secondary)), areas[3]);
    }
}
fn number(n: Option<impl ToString>) -> String {
    n.map(|n| n.to_string()).unwrap_or_else(|| "?".into())
}
pub struct Dashboard {
    terminal: Terminal<CrosstermBackend<Stdout>>,
    _guard: super::TerminalGuard,
    pub view: View,
}
impl Dashboard {
    pub fn open(filter: String) -> anyhow::Result<Self> {
        anyhow::ensure!(
            io::stdin().is_terminal() && io::stdout().is_terminal(),
            "interactive scan requires a terminal; use --plain for text output"
        );
        enable_raw_mode()?;
        let guard = super::TerminalGuard;
        io::stdout().execute(EnterAlternateScreen)?;
        Ok(Self {
            terminal: Terminal::new(CrosstermBackend::new(io::stdout()))?,
            _guard: guard,
            view: View::new(filter),
        })
    }
    pub fn input(&mut self) -> io::Result<Action> {
        if event::poll(Duration::from_millis(50))? {
            if let Event::Key(key) = event::read()? {
                if key.kind == KeyEventKind::Press {
                    return Ok(self.view.key(key.code, key.modifiers));
                }
            }
        }
        Ok(Action::None)
    }
    pub fn draw(&mut self, status: &str) -> io::Result<()> {
        self.terminal.draw(|f| self.view.render(f, status))?;
        Ok(())
    }
}
#[cfg(test)]
mod tests {
    use super::*;
    fn row(name: Option<&str>, signal: Option<i16>) -> AccessPoint {
        AccessPoint {
            ssid: name.map(str::to_owned),
            name: name.unwrap_or("<restricted>").into(),
            security: "WPA2/WPA3".into(),
            current: false,
            signal,
            bssid: "02:00:00:00:00:01".into(),
            band: "5".into(),
            channel: Some(44),
            noise: None,
        }
    }
    #[test]
    fn signal_sort_filter_and_snapshot_replacement() {
        let mut v = View::default();
        v.replace(vec![
            row(Some("Lab"), Some(-70)),
            row(None, None),
            row(Some("LAB guest"), Some(-30)),
        ]);
        assert_eq!(v.visible()[0].signal, Some(-30));
        v.key(KeyCode::Char('s'), KeyModifiers::NONE);
        assert_eq!(v.visible()[0].signal, Some(-70));
        assert_eq!(v.visible()[2].signal, None);
        v.filter = "lab".into();
        assert_eq!(v.visible().len(), 2);
        v.replace(vec![row(Some("Other"), Some(-20))]);
        assert!(v.visible().is_empty());
        assert!(matches_ssid(Some("Сеть"), "сеть"));
        assert!(!matches_ssid(None, "restricted"));
    }
    #[test]
    fn filter_editing_does_not_trigger_commands_and_can_cancel() {
        let mut v = View::new("Lab".into());
        v.key(KeyCode::Char('/'), KeyModifiers::NONE);
        assert!(matches!(
            v.key(KeyCode::Char('q'), KeyModifiers::NONE),
            Action::None
        ));
        assert_eq!(v.filter, "Labq");
        v.key(KeyCode::Esc, KeyModifiers::NONE);
        assert_eq!(v.filter, "Lab");
        v.key(KeyCode::Char('/'), KeyModifiers::NONE);
        v.key(KeyCode::Char('u'), KeyModifiers::CONTROL);
        v.key(KeyCode::Enter, KeyModifiers::NONE);
        assert!(v.filter.is_empty());
    }
    #[test]
    fn current_network_has_marker_and_style() {
        let mut v = View::default();
        let mut ap = row(Some("Connected"), Some(-30));
        ap.current = true;
        v.replace(vec![ap]);
        let mut t = Terminal::new(ratatui::backend::TestBackend::new(140, 24)).unwrap();
        t.draw(|f| v.render(f, "connected")).unwrap();
        let buffer = t.backend().buffer();
        let text: String = buffer.content.iter().map(|c| c.symbol()).collect();
        assert!(text.contains("Security"));
        assert!(text.contains("WPA2/WPA3"));
        assert!(buffer.content.iter().any(|c| c.symbol() == "*"
            && c.fg == super::super::apex_tokens::DARK.success
            && c.modifier.contains(Modifier::BOLD)));
    }
    #[test]
    fn layout_independent_menu_filter_and_pause() {
        let mut v = View::default();
        v.key(KeyCode::Tab, KeyModifiers::NONE);
        for _ in 0..2 {
            v.key(KeyCode::Down, KeyModifiers::NONE);
        }
        v.key(KeyCode::Enter, KeyModifiers::NONE);
        assert!(v.editing);
        for c in "Сетьq".chars() {
            v.key(KeyCode::Char(c), KeyModifiers::NONE);
        }
        assert_eq!(v.filter, "Сетьq");
        v.key(KeyCode::Delete, KeyModifiers::NONE);
        assert!(v.filter.is_empty());
        v.key(KeyCode::Enter, KeyModifiers::NONE);
        assert!(matches!(
            v.key(KeyCode::Char(' '), KeyModifiers::NONE),
            Action::TogglePause
        ));
        assert!(matches!(
            v.key(KeyCode::F(5), KeyModifiers::NONE),
            Action::Refresh
        ));
        v.key(KeyCode::F(1), KeyModifiers::NONE);
        assert!(v.help);
        v.key(KeyCode::Esc, KeyModifiers::NONE);
        assert!(!v.help);
        assert!(matches!(
            v.key(KeyCode::F(10), KeyModifiers::NONE),
            Action::Quit
        ));
    }
    #[test]
    fn selection_survives_refresh_and_current_jump_clears_filters() {
        let mut v = View::default();
        let mut a = row(Some("First"), Some(-30));
        a.current = true;
        let mut b = row(Some("Second"), Some(-40));
        b.bssid = "02:00:00:00:00:02".into();
        v.replace(vec![a.clone(), b.clone()]);
        v.key(KeyCode::Down, KeyModifiers::NONE);
        b.signal = Some(-20);
        v.replace(vec![a, b]);
        assert_eq!(v.visible()[v.offset].name, "Second");
        v.filter = "missing".into();
        v.band = 1;
        v.key(KeyCode::F(8), KeyModifiers::NONE);
        assert!(v.visible()[v.offset].current);
        v.key(KeyCode::F(4), KeyModifiers::NONE);
        assert_eq!(v.visible()[0].name, "First");
        v.key(KeyCode::F(7), KeyModifiers::NONE);
        assert!(v.visible().is_empty());
    }
    #[test]
    fn chart_menu_pins_bssid_and_panels_render_in_both_themes() {
        let mut v = View::default();
        let a = row(Some("Tracked"), Some(-42));
        v.replace(vec![a]);
        v.key(KeyCode::Tab, KeyModifiers::NONE);
        for _ in 0..10 {
            v.key(KeyCode::Down, KeyModifiers::NONE);
        }
        v.key(KeyCode::Enter, KeyModifiers::NONE);
        assert_eq!(v.chart, 1);
        let target = v.chart_target.clone();
        let mut other = row(Some("Other"), Some(-20));
        other.bssid = "02:00:00:00:00:02".into();
        v.replace(vec![other]);
        assert_eq!(v.chart_target, target);
        assert!(matches!(
            v.key(KeyCode::F(5), KeyModifiers::NONE),
            Action::Refresh
        ));
        assert!(matches!(
            v.key(KeyCode::Char(' '), KeyModifiers::NONE),
            Action::TogglePause
        ));
        for theme in [
            super::super::apex_tokens::Theme::Dark,
            super::super::apex_tokens::Theme::Light,
        ] {
            v.theme = theme;
            for (w, h) in [(140, 30), (40, 10), (5, 2)] {
                let mut t = Terminal::new(ratatui::backend::TestBackend::new(w, h)).unwrap();
                for chart in [1, 2] {
                    v.chart = chart;
                    t.draw(|f| v.render(f, "last snapshot")).unwrap();
                    if w == 140 {
                        let text: String = t
                            .backend()
                            .buffer()
                            .content
                            .iter()
                            .map(|c| c.symbol())
                            .collect();
                        assert!(text.contains(if chart == 1 { "Tracked" } else { "CHANNELS" }));
                    }
                }
            }
        }
        v.key(KeyCode::Esc, KeyModifiers::NONE);
        assert_eq!(v.chart, 0);
        v.key(KeyCode::Tab, KeyModifiers::NONE);
        for _ in 0..11 {
            v.key(KeyCode::Down, KeyModifiers::NONE);
        }
        v.key(KeyCode::Enter, KeyModifiers::NONE);
        assert_eq!(v.chart, 2);
    }
    #[test]
    fn real_layout_handles_small_terminals_and_empty_filters() {
        let mut v = View::new("nothing".into());
        v.replace(vec![row(Some("Lab"), Some(-30))]);
        for (w, h) in [(120, 24), (40, 10), (5, 2)] {
            for theme in [
                super::super::apex_tokens::Theme::Dark,
                super::super::apex_tokens::Theme::Light,
            ] {
                v.theme = theme;
                let mut t = Terminal::new(ratatui::backend::TestBackend::new(w, h)).unwrap();
                t.draw(|f| v.render(f, "Last update 2s ago · connected"))
                    .unwrap();
                if w == 120 {
                    let text: String = t
                        .backend()
                        .buffer()
                        .content
                        .iter()
                        .map(|c| c.symbol())
                        .collect();
                    assert!(text.contains("No SSID matches"));
                    assert!(text.contains("Last update 2s ago"));
                }
            }
        }
    }
}
