//! Bounded snapshot history. No radio I/O; never infer identity from SSID.
use super::{apex_tokens::Palette, wifi_scan::AccessPoint};
use ratatui::{
    layout::Rect,
    style::Style,
    symbols,
    widgets::{Axis, Block, Borders, Chart, Dataset, GraphType, Paragraph, Wrap},
    Frame,
};
use std::collections::{BTreeMap, VecDeque};
use std::time::Instant;

const HISTORY_LIMIT: usize = 60;
#[derive(Default)]
pub struct History {
    started: Option<Instant>,
    samples: VecDeque<(f64, BTreeMap<String, i16>)>,
}
pub fn identity(bssid: &str) -> Option<String> {
    (bssid.len() == 17
        && bssid.split(':').count() == 6
        && bssid
            .split(':')
            .all(|p| p.len() == 2 && p.bytes().all(|b| b.is_ascii_hexdigit())))
    .then(|| bssid.to_ascii_lowercase())
}
impl History {
    pub fn record(&mut self, rows: &[AccessPoint]) {
        let now = Instant::now();
        let start = *self.started.get_or_insert(now);
        self.record_at(now.duration_since(start).as_secs_f64(), rows);
    }
    fn record_at(&mut self, time: f64, rows: &[AccessPoint]) {
        let values = rows
            .iter()
            .take(4096)
            .filter_map(|r| identity(&r.bssid).zip(r.signal))
            .collect();
        self.samples.push_back((time, values));
        while self.samples.len() > HISTORY_LIMIT {
            self.samples.pop_front();
        }
    }
    fn segments(&self, bssid: &str) -> Vec<Vec<(f64, f64)>> {
        let mut segments = vec![Vec::new()];
        for (time, values) in &self.samples {
            if let Some(value) = values.get(bssid) {
                segments
                    .last_mut()
                    .unwrap()
                    .push((*time, f64::from(*value)));
            } else if !segments.last().unwrap().is_empty() {
                segments.push(Vec::new());
            }
        }
        segments.retain(|s| !s.is_empty());
        segments
    }
    pub fn render(
        &self,
        frame: &mut Frame,
        area: Rect,
        target: Option<&(String, String)>,
        p: Palette,
    ) {
        let block = panel(p).title("SIGNAL HISTORY · Esc back · F2 theme · F5 refresh");
        let Some((bssid, name)) = target else {
            frame.render_widget(Paragraph::new("Select an AP with an available BSSID first. Restricted identifiers cannot be tracked.").wrap(Wrap { trim: false }).block(block), area);
            return;
        };
        let segments = self.segments(bssid);
        if segments.is_empty() {
            frame.render_widget(
                Paragraph::new("No signal samples for this BSSID in the last 60 snapshots.")
                    .block(block),
                area,
            );
            return;
        }
        let datasets = segments
            .iter()
            .map(|points| {
                Dataset::default()
                    .data(points)
                    .graph_type(GraphType::Line)
                    .marker(symbols::Marker::Braille)
                    .style(Style::default().fg(p.accent))
            })
            .collect();
        let min = self.samples.front().map(|s| s.0).unwrap_or(0.0);
        let max = self
            .samples
            .back()
            .map(|s| s.0)
            .unwrap_or(min)
            .max(min + 1.0);
        frame.render_widget(
            Chart::new(datasets)
                .block(block.title(format!("SIGNAL · {name} · {bssid} · last 60 snapshots")))
                .style(Style::default().fg(p.text_primary).bg(p.surface_1))
                .x_axis(
                    Axis::default()
                        .title("Snapshot seconds (cache may repeat); gaps = not observed")
                        .bounds([min, max])
                        .labels([format!("{min:.0}"), format!("{max:.0}")])
                        .style(Style::default().fg(p.text_secondary)),
                )
                .y_axis(
                    Axis::default()
                        .title("dBm")
                        .bounds([-127.0, 0.0])
                        .labels(["-127", "-60", "0"])
                        .style(Style::default().fg(p.text_secondary)),
                ),
            area,
        );
    }
}
fn panel(p: Palette) -> Block<'static> {
    Block::default()
        .borders(Borders::ALL)
        .style(Style::default().fg(p.text_primary).bg(p.surface_1))
        .border_style(Style::default().fg(p.border_control))
}
pub fn distribution(rows: &[AccessPoint]) -> BTreeMap<(u8, u16), usize> {
    let mut counts = BTreeMap::new();
    for r in rows {
        let band = match r.band.as_str() {
            "2.4" => 1,
            "5" => 2,
            "6" => 3,
            _ => 0,
        };
        *counts.entry((band, r.channel.unwrap_or(0))).or_default() += 1;
    }
    counts
}
pub fn render_channels(
    frame: &mut Frame,
    area: Rect,
    rows: &[AccessPoint],
    offset: usize,
    p: Palette,
) {
    let counts = distribution(rows);
    let max = counts.values().copied().max().unwrap_or(1);
    let width = usize::from(area.width.saturating_sub(26)).min(80);
    let lines = counts
        .iter()
        .map(|((band, channel), count)| {
            let band = ["?", "2.4", "5", "6"][usize::from(*band)];
            let channel = if *channel == 0 {
                "?".into()
            } else {
                channel.to_string()
            };
            format!(
                "{band:>3} GHz ch {channel:>3}  {count:>4} {}",
                "█".repeat((count * width / max).max(1))
            )
        })
        .collect::<Vec<_>>();
    let offset = offset.min(lines.len().saturating_sub(1));
    let body = if lines.is_empty() {
        "No networks in the latest snapshot".into()
    } else {
        lines.join("\n")
    };
    frame.render_widget(
        Paragraph::new(body)
            .scroll((offset as u16, 0))
            .style(Style::default().fg(p.accent))
            .block(panel(p).title(format!(
                "CHANNELS · {} APs · all rows, not airtime · ↑↓ scroll · Esc back",
                rows.len()
            ))),
        area,
    );
}
#[cfg(test)]
mod tests {
    use super::*;
    fn ap(bssid: &str, band: &str, channel: Option<u16>, signal: Option<i16>) -> AccessPoint {
        AccessPoint {
            ssid: None,
            name: "Test".into(),
            security: "Unknown".into(),
            current: false,
            bssid: bssid.into(),
            band: band.into(),
            channel,
            signal,
            noise: None,
        }
    }
    #[test]
    fn history_has_gaps_is_bounded_and_does_not_merge_private_ids() {
        let mut h = History::default();
        let a = ap("AA:BB:CC:DD:EE:01", "5", Some(44), Some(-40));
        h.record_at(
            0.0,
            &[a.clone(), ap("<restricted>", "5", Some(44), Some(-20))],
        );
        h.record_at(15.0, &[]);
        h.record_at(30.0, std::slice::from_ref(&a));
        assert_eq!(
            h.segments("aa:bb:cc:dd:ee:01"),
            vec![vec![(0.0, -40.0)], vec![(30.0, -40.0)]]
        );
        assert!(h.segments("<restricted>").is_empty());
        for t in 31..100 {
            h.record_at(f64::from(t), std::slice::from_ref(&a));
        }
        assert_eq!(h.samples.len(), HISTORY_LIMIT);
    }
    #[test]
    fn channel_numbers_are_separate_by_band_and_unknown_is_counted() {
        let counts = distribution(&[
            ap("a", "2.4", Some(1), None),
            ap("b", "6", Some(1), None),
            ap("c", "6", Some(1), None),
            ap("d", "?", None, None),
        ]);
        assert_eq!(counts[&(1, 1)], 1);
        assert_eq!(counts[&(3, 1)], 2);
        assert_eq!(counts[&(0, 0)], 1);
    }
}
