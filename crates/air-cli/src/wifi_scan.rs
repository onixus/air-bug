use air_capture::survey::display_bytes;
use air_platform::wifi_scan::{scan, Snapshot};
use anyhow::Result;
use clap::Args;
use std::{
    io::{IsTerminal, Write},
    time::{Duration, Instant},
};

#[derive(Args, Debug)]
pub struct ScanArgs {
    /// macOS Wi-Fi interface; does not enter monitor mode or change association
    #[arg(short, long, default_value = "en0")]
    iface: String,
    /// Read the OS cache without requesting a new scan (age is unknown)
    #[arg(long)]
    cached: bool,
    /// Ask macOS for Location Services consent to reveal SSID/BSSID (optional)
    #[arg(long, conflicts_with = "cached")]
    request_location: bool,
    /// Interactive table (also selected by --watch in a terminal)
    #[arg(long, conflicts_with = "plain")]
    tui: bool,
    /// APEX terminal theme; system uses COLORFGBG with dark fallback
    #[arg(long, default_value = "system", value_parser = ["dark", "light", "system"])]
    theme: String,
    /// Keep plain text output, including for --watch in a terminal
    #[arg(long)]
    plain: bool,
    /// Case-insensitive SSID substring filter
    #[arg(long, default_value = "")]
    ssid: String,
    /// Refresh until Ctrl-C; each snapshot replaces the previous data logically
    #[arg(long)]
    watch: bool,
    /// Delay between completed scans in watch mode
    #[arg(long, default_value = "15", value_parser = clap::value_parser!(u64).range(5..=3600))]
    interval: u64,
}
fn safe(text: &str) -> String {
    text.chars()
        .map(|c| {
            if c.is_control() {
                c.escape_default().to_string()
            } else {
                c.to_string()
            }
        })
        .collect()
}
fn connection(mode: u32) -> &'static str {
    match mode {
        0 => "not associated",
        1 => "connected",
        _ => "other interface mode",
    }
}
fn number(value: Option<impl ToString>) -> String {
    value.map(|n| n.to_string()).unwrap_or_else(|| "?".into())
}
fn render(s: &Snapshot, filter: &str, out: &mut impl Write) -> Result<()> {
    writeln!(
        out,
        "Wi-Fi overview — {} — {} APs — {} → {}",
        if s.source == "cache" {
            "OS cache (age unknown)"
        } else {
            "OS scan"
        },
        s.total,
        connection(s.mode_before),
        connection(s.mode_after)
    )?;
    writeln!(
        out,
        "Current\tSSID\tBSSID\tSecurity\tBand/GHz\tChannel\tSignal/dBm\tNoise/dBm"
    )?;
    for n in &s.networks {
        let decoded = n
            .ssid_hex
            .as_ref()
            .and_then(|h| hex::decode(h).ok())
            .and_then(|b| String::from_utf8(b).ok());
        if !air_tui::wifi_scan::matches_ssid(decoded.as_deref(), filter) {
            continue;
        }
        let ssid = match &n.ssid_hex {
            None => "<unavailable: privacy/hidden>".into(),
            Some(s) if s.is_empty() => "<hidden>".into(),
            Some(s) => {
                let bytes = hex::decode(s)?;
                match std::str::from_utf8(&bytes) {
                    Ok(text) => safe(text),
                    Err(_) => display_bytes(&bytes),
                }
            }
        };
        let band = match n.band {
            Some(1) => "2.4",
            Some(2) => "5",
            Some(3) => "6",
            _ => "?",
        };
        writeln!(
            out,
            "{}\t{}\t{}\t{}\t{}\t{}\t{}\t{}",
            if s.is_current(n) { "*" } else { "" },
            ssid,
            n.bssid
                .as_deref()
                .map(safe)
                .unwrap_or_else(|| "<restricted>".into()),
            n.security_label(),
            band,
            number(n.channel),
            number(n.signal_dbm),
            number(n.noise_dbm)
        )?;
    }
    if s.total > s.networks.len() {
        writeln!(
            out,
            "Showing strongest {} of {} results.",
            s.networks.len(),
            s.total
        )?;
    }
    if s.networks.is_empty() {
        writeln!(out,"macOS returned no networks; an empty cache is not proof of an empty radio environment.")?;
    }
    if s.networks
        .iter()
        .any(|n| n.ssid_hex.is_none() || n.bssid.is_none())
    {
        writeln!(out,"Some identifiers are hidden/unavailable. macOS Location Services permissions may restrict SSID/BSSID; sudo does not replace location consent.")?;
    }
    Ok(())
}
pub fn run(args: ScanArgs) -> Result<()> {
    super::live::install_signals()?;
    if args.tui
        || (args.watch
            && !args.plain
            && std::io::stdin().is_terminal()
            && std::io::stdout().is_terminal())
    {
        return interactive(args);
    }
    let mut request_location = args.request_location;
    loop {
        if super::live::is_interrupted() {
            return Ok(());
        }
        let s = scan(&args.iface, args.cached, request_location)?;
        request_location = false;
        render(&s, &args.ssid, &mut std::io::stdout().lock())?;
        if s.mode_before == 1 && s.mode_after != 1 {
            anyhow::bail!("Wi-Fi association changed during the OS scan; stopping refresh. No reconnection or configuration changes attempted.");
        }
        if !args.watch {
            return Ok(());
        }
        let start = Instant::now();
        while start.elapsed() < Duration::from_secs(args.interval) {
            if super::live::is_interrupted() {
                return Ok(());
            }
            std::thread::sleep(Duration::from_millis(100));
        }
    }
}

struct ScanJob {
    result: std::sync::mpsc::Receiver<std::io::Result<Snapshot>>,
    stop: std::sync::Arc<std::sync::atomic::AtomicBool>,
    thread: Option<std::thread::JoinHandle<()>>,
}
impl ScanJob {
    fn start(iface: String, cached: bool, request_location: bool) -> Self {
        let (sender, result) = std::sync::mpsc::channel();
        let stop = std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false));
        let cancelled = stop.clone();
        let thread = std::thread::spawn(move || {
            let value =
                air_platform::wifi_scan::scan_until(&iface, cached, request_location, || {
                    cancelled.load(std::sync::atomic::Ordering::Relaxed)
                });
            let _ = sender.send(value);
        });
        Self {
            result,
            stop,
            thread: Some(thread),
        }
    }
}
impl Drop for ScanJob {
    fn drop(&mut self) {
        self.stop.store(true, std::sync::atomic::Ordering::Relaxed);
        if let Some(thread) = self.thread.take() {
            let _ = thread.join();
        }
    }
}
fn rows(s: &Snapshot) -> Result<Vec<air_tui::wifi_scan::AccessPoint>> {
    s.networks
        .iter()
        .map(|n| {
            let bytes = n.ssid_hex.as_ref().map(hex::decode).transpose()?;
            let ssid = bytes
                .as_ref()
                .and_then(|b| String::from_utf8(b.clone()).ok());
            let name = match &bytes {
                None => "<unavailable>".into(),
                Some(b) if b.is_empty() => "<hidden>".into(),
                Some(b) => ssid
                    .as_deref()
                    .map(safe)
                    .unwrap_or_else(|| display_bytes(b)),
            };
            Ok(air_tui::wifi_scan::AccessPoint {
                ssid,
                name,
                security: n.security_label(),
                current: s.is_current(n),
                bssid: n
                    .bssid
                    .as_deref()
                    .map(safe)
                    .unwrap_or_else(|| "<restricted>".into()),
                band: match n.band {
                    Some(1) => "2.4",
                    Some(2) => "5",
                    Some(3) => "6",
                    _ => "?",
                }
                .into(),
                channel: n.channel,
                signal: n.signal_dbm,
                noise: n.noise_dbm,
            })
        })
        .collect()
}
fn interactive(args: ScanArgs) -> Result<()> {
    use air_tui::wifi_scan::{Action, Dashboard};
    let mut ui = Dashboard::open(args.ssid.clone())?;
    ui.view.theme = match args.theme.as_str() {
        "light" => air_tui::apex_tokens::Theme::Light,
        "dark" => air_tui::apex_tokens::Theme::Dark,
        _ => air_tui::apex_tokens::Theme::System,
    };
    let mut job: Option<ScanJob> = None;
    let mut next = Instant::now();
    let mut updated: Option<Instant> = None;
    let mut request_location = args.request_location;
    let mut automatic = true;
    let mut manual = false;
    let mut detail = String::from("Waiting for first snapshot");
    let mut error: Option<String> = None;
    loop {
        if super::live::is_interrupted() {
            break;
        }
        match ui.input()? {
            Action::Quit => break,
            Action::Refresh if job.is_none() => {
                manual = true;
            }
            Action::TogglePause => {
                automatic = !automatic;
                if !automatic {
                    drop(job.take());
                    manual = false;
                } else {
                    next = Instant::now();
                }
            }
            _ => {}
        }
        if let Some(active) = &job {
            let result = match active.result.try_recv() {
                Ok(result) => Some(result),
                Err(std::sync::mpsc::TryRecvError::Empty) => None,
                Err(_) => Some(Err(std::io::Error::other(
                    "scan worker stopped unexpectedly",
                ))),
            };
            if let Some(result) = result {
                drop(job.take());
                next = Instant::now() + Duration::from_secs(args.interval);
                match result {
                    Ok(s) => {
                        ui.view.replace(rows(&s)?);
                        updated = Some(Instant::now());
                        error = None;
                        detail = format!(
                            "{} | {} | {} APs returned{}",
                            if s.source == "cache" {
                                "OS cache (age unknown)"
                            } else {
                                "OS scan"
                            },
                            connection(s.mode_after),
                            s.total,
                            if s.total > s.networks.len() {
                                " (result limit reached)"
                            } else {
                                ""
                            }
                        );
                        if s.mode_before == 1 && s.mode_after != 1 {
                            automatic = false;
                            error=Some("Association changed; auto-refresh stopped. No interface changes attempted.".into());
                        }
                    }
                    Err(e) => {
                        error = Some(format!(
                            "Scan failed: {} (showing last snapshot)",
                            safe(&e.to_string())
                        ));
                    }
                }
            }
        }
        if job.is_none() && (manual || (automatic && Instant::now() >= next)) {
            manual = false;
            job = Some(ScanJob::start(
                args.iface.clone(),
                args.cached,
                request_location,
            ));
            request_location = false;
        }
        let activity = if job.is_some() {
            "Scanning… (F9 pauses, F10 exits)".into()
        } else if automatic {
            format!(
                "next refresh in {}s",
                next.saturating_duration_since(Instant::now()).as_secs()
            )
        } else {
            "refresh paused".into()
        };
        let age = updated
            .map(|t| format!("last update {}s ago", t.elapsed().as_secs()))
            .unwrap_or_else(|| "no completed scan".into());
        let status = format!(
            "{} | {detail} | {age} | {activity}{}",
            safe(&args.iface),
            error.as_ref().map(|e| format!("\n{e}")).unwrap_or_default()
        );
        ui.draw(&status)?;
    }
    drop(job); // Cancel/reap the helper before restoring the terminal.
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn rendering_escapes_network_names_and_labels_cache() {
        let s = Snapshot {
            version: 1,
            source: "cache".into(),
            mode_before: 1,
            mode_after: 1,
            current_bssid: None,
            total: 1,
            networks: vec![air_platform::wifi_scan::Network {
                ssid_hex: Some("611b62".into()),
                bssid: None,
                channel: Some(6),
                band: Some(1),
                signal_dbm: Some(-45),
                noise_dbm: None,
                security: vec![],
            }],
        };
        let mut out = Vec::new();
        render(&s, "", &mut out).unwrap();
        let text = String::from_utf8(out).unwrap();
        assert!(!text.contains('\x1b'));
        assert!(text.contains("a\\u{1b}b"));
        assert!(text.contains("age unknown"));
        assert!(text.contains("-45"));
    }
}
