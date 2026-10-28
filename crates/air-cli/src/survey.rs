use crate::exit::{self, Category};
use air_capture::survey::{display_bytes, mac_string, PcapStream, Survey};
use air_platform::channels::Channels;
use air_tui::survey::{Action, Dashboard};
use anyhow::{bail, Context, Result};
use clap::Args;
use std::fs::File;
use std::path::PathBuf;
use std::time::{Duration, Instant};

#[derive(Args, Debug)]
pub struct SurveyArgs {
    /// Existing Linux monitor interface, or macOS Wi-Fi interface (requests monitor mode)
    #[arg(short, long, required_unless_present = "read", conflicts_with = "read")]
    iface: Option<String>,
    /// New private PCAP output (never overwritten)
    #[arg(short, long, required_unless_present_any = ["read", "list_channels"], conflicts_with = "read")]
    output: Option<PathBuf>,
    /// Inspect raw-802.11/Radiotap PCAP or PCAPng without opening any radio
    #[arg(long, conflicts_with_all = ["channel", "channels", "frequency", "frequencies", "list_channels"])]
    read: Option<PathBuf>,
    /// Optional exact BSSID filter; omit for a passive overview of all observed networks
    #[arg(long, value_parser = super::parse_mac)]
    bssid: Option<[u8; 6]>,
    /// Hold this 2.4/5 GHz channel
    #[arg(long, conflicts_with_all = ["channels", "frequency", "frequencies"])]
    channel: Option<u16>,
    /// Hop over this comma-separated list of 2.4/5 GHz channels
    #[arg(long, value_delimiter = ',', num_args = 1.., conflicts_with_all = ["frequency", "frequencies"])]
    channels: Vec<u16>,
    /// Hold an exact frequency in MHz (Linux monitor interface)
    #[arg(long, conflicts_with = "frequencies")]
    frequency: Option<u16>,
    /// Hop over exact frequencies in MHz (Linux monitor interface)
    #[arg(long, value_delimiter = ',', num_args = 1..)]
    frequencies: Vec<u16>,
    /// Print adapter-supported channels and exit (does not start capture)
    #[arg(long)]
    list_channels: bool,
    /// Channel dwell time; adapter command latency is additional
    #[arg(long, default_value = "1000", value_parser = clap::value_parser!(u64).range(250..=60000))]
    dwell_ms: u64,
    #[arg(long, default_value = "300", value_parser = clap::value_parser!(u64).range(1..=86400))]
    duration: u64,
    #[arg(long, default_value = "100000", value_parser = clap::value_parser!(u32).range(1..))]
    max_packets: u32,
    /// Remove rows after this many seconds without observations
    #[arg(long, default_value = "120", value_parser = clap::value_parser!(u64).range(1..=86400))]
    stale_seconds: u64,
    /// Print periodic text snapshots instead of an interactive terminal
    #[arg(long)]
    plain: bool,
    /// Save the final AP/client snapshot as private JSON (new path only)
    #[arg(long, conflicts_with = "list_channels")]
    export_json: Option<PathBuf>,
    /// Save the final AP/client snapshot as private CSV (new path only)
    #[arg(long, conflicts_with = "list_channels")]
    export_csv: Option<PathBuf>,
    /// Write a small machine diagnostic (exit category, counts, error) as private
    /// JSON (new path only). The exit category is also the process exit code.
    /// Use --json=PATH for names starting with a hyphen; "-" is a literal file, not stdout.
    #[arg(long, alias = "json")]
    diagnostic_json: Option<PathBuf>,
}

/// Небольшая сводка счётчиков для диагностического JSON. Отражает финальный
/// снимок наблюдений, без секретов и без построчной телеметрии.
#[derive(Clone, Copy, Debug, Default)]
struct Counts {
    access_points: usize,
    clients: usize,
    packets: u64,
    handshakes: usize,
    pmkid: usize,
}
impl Counts {
    fn from_survey(data: &Survey) -> Self {
        Self {
            access_points: data.aps.len(),
            clients: data.stations.len(),
            packets: data.packets,
            handshakes: data
                .aps
                .values()
                .filter(|ap| ap.handshake_m1m2 || ap.handshake_m2m3 || ap.handshake_m3m4)
                .count(),
            pmkid: data.aps.values().filter(|ap| ap.pmkid).count(),
        }
    }
}

impl Counts {
    /// Сводка счётчиков для диагностического JSON (без секретов).
    fn to_json(self) -> serde_json::Value {
        serde_json::json!({
            "access_points": self.access_points,
            "clients": self.clients,
            "packets": self.packets,
            "handshakes": self.handshakes,
            "pmkid": self.pmkid,
        })
    }
}

/// Относит сбой к стабильной категории исхода. Классификация внутренняя: backend
/// читает уже готовую категорию из кода выхода и JSON, а не парсит текст.
fn classify(error: &anyhow::Error) -> Category {
    if let Some(category) = exit::classify_cause(error) {
        return category;
    }
    let text = error
        .chain()
        .map(|e| e.to_string().to_lowercase())
        .collect::<Vec<_>>()
        .join(" | ");
    let has = |needle: &str| text.contains(needle);
    if has("already exists") || has("refusing to overwrite") {
        Category::PrivilegeOrDevice
    } else if has("is required") {
        Category::Usage
    } else if has("raw 802.11")
        || has("radiotap")
        || (has("pcap") || (has("capture") && has("header")))
    {
        Category::BadContainer
    } else if has("no 802.11 packets") {
        Category::NoSupportedTarget
    } else if has("monitor")
        || has("interface")
        || has("permission")
        || has("denied")
        || has("device")
        || has("channel")
        || has("frequency")
        || has("tcpdump")
        || has("radio")
    {
        Category::PrivilegeOrDevice
    } else {
        Category::Internal
    }
}

/// Внешняя обёртка: резервирует диагностику, запускает survey, фиксирует исход
/// и выставляет код выхода согласно машинному контракту.
pub fn run(args: SurveyArgs) -> Result<()> {
    let diagnostic = args.diagnostic_json.clone();
    exit::run_with_diagnostic(
        diagnostic.as_deref(),
        "survey_diagnostic",
        classify,
        |counts, _| Counts::to_json(counts).into(),
        || execute(args),
    )
}

struct Viewer {
    data: Survey,
    stream: PcapStream,
    file: Option<File>,
    dashboard: Option<Dashboard>,
    started: Instant,
    last_draw: Option<Instant>,
    stopped: bool,
}
impl Viewer {
    fn new(plain: bool) -> Result<Self> {
        Ok(Self {
            data: Survey::default(),
            stream: PcapStream::default(),
            file: None,
            dashboard: if plain {
                None
            } else {
                Some(Dashboard::open()?)
            },
            started: Instant::now(),
            last_draw: None,
            stopped: false,
        })
    }
    fn read(&mut self, filter: Option<[u8; 6]>, drain: bool) -> std::io::Result<()> {
        if let Some(file) = &mut self.file {
            // Limit processing per live tick so key handling and the deadline stay responsive.
            for _ in 0..if drain { usize::MAX } else { 4 } {
                let now = self.started.elapsed();
                let count = self
                    .stream
                    .poll_records(file, |dlt, bytes, original, timestamp| {
                        self.data
                            .observe_record(dlt, bytes, original, timestamp, now, filter)
                    })?;
                if count == 0 {
                    break;
                }
            }
        }
        Ok(())
    }
    fn draw(&mut self, status: &str, force: bool) -> std::io::Result<()> {
        let interval = if self.dashboard.is_some() {
            Duration::from_millis(200)
        } else {
            Duration::from_secs(2)
        };
        if !force && self.last_draw.is_some_and(|last| last.elapsed() < interval) {
            return Ok(());
        }
        let status = format!(
            "{status} | HS={} PMKID={} FT={} | pending-evicted={} | packets={} ignored={} evicted={} truncated={} bad-fcs={} elapsed={}s",
            self.data.aps.values().filter(|ap| ap.handshake_m1m2 || ap.handshake_m2m3 || ap.handshake_m3m4).count(),
            self.data.aps.values().filter(|ap| ap.pmkid).count(),
            self.data.aps.values().filter(|ap|ap.ft).count(),
            self.data.verification_evicted(),
            self.data.packets,
            self.data.ignored,
            self.data.evicted,
            self.data.quality.truncated_records,
            self.data.quality.radiotap_bad_fcs,
            self.started.elapsed().as_secs()
        );
        if let Some(dashboard) = &mut self.dashboard {
            dashboard.draw(&self.data, &status, self.started.elapsed())?;
        } else {
            use std::io::Write;
            let mut out = std::io::stdout().lock();
            writeln!(
                out,
                "{status}\nBSSID\tSSID\tCH\tdBm\tSecurity\tBeacons\tPackets\tEvidence\tPMF\tAudit\tCapture observations\tBand\tMHz"
            )?;
            for (mac, ap) in &self.data.aps {
                writeln!(
                    out,
                    "{}\t{}\t{}\t{}\t{}\t{}\t{}\t{}\t{}\t{}\t{}\t{}\t{}",
                    mac_string(mac),
                    display_bytes(&ap.ssid),
                    optional(ap.channel),
                    optional(ap.signal),
                    if ap.security.is_empty() {
                        "?"
                    } else {
                        &ap.security
                    },
                    ap.beacons,
                    ap.packets,
                    ap.verification_label(),
                    ap.pmf(),
                    ap.security_audit
                        .as_ref()
                        .filter(|_| ap.audit_last_status == Some("valid"))
                        .map(|a| a.advertised.observations.join(";"))
                        .unwrap_or_else(|| "unknown".into()),
                    ap.capture_observations().join(";"),
                    ap.last_direct_observation
                        .as_ref()
                        .and_then(|o| o.radio)
                        .map(|r| r.band)
                        .unwrap_or("?"),
                    optional(
                        ap.last_direct_observation
                            .as_ref()
                            .and_then(|o| o.radio)
                            .map(|r| r.frequency_mhz)
                    )
                )?;
                writeln!(
                    out,
                    "  {} | {}",
                    ap.enterprise.summary(),
                    ap.enterprise.observations().join(";")
                )?;
                if let Some(caps) = &ap.roaming_capabilities {
                    writeln!(out, "  Roaming advertisement: {}", caps.summary())?;
                }
                if let Some(audit) = ap
                    .security_audit
                    .as_ref()
                    .filter(|_| ap.audit_last_status == Some("valid"))
                {
                    writeln!(
                        out,
                        "  Advertised mode: {}",
                        audit.advertised.assessment.advertised_mode
                    )?;
                    for finding in &audit.advertised.assessment.findings {
                        writeln!(
                            out,
                            "  [{}] {}: {} Recommendation: {}",
                            finding.severity, finding.id, finding.evidence, finding.recommendation
                        )?;
                    }
                }
            }
            writeln!(out, "Roaming management observations: {} retained, {} evicted, {} malformed (unauthenticated; retries included)", self.data.roaming.events.len(), self.data.roaming.evicted, self.data.roaming.malformed_management)?;
            for e in &self.data.roaming.events {
                writeln!(out, "  #{} {} AP={} client={} previous={} status={} reason={} auth={} sequence={} retry={} capture_s={}", e.record_index, e.kind, e.bssid, e.station, e.previous_bssid.as_deref().unwrap_or("?"), optional(e.status_code), optional(e.reason_code), optional(e.authentication_algorithm), optional(e.authentication_sequence), e.retry, optional(e.capture_timestamp_seconds))?;
            }
            if !self.data.rnr_neighbors.is_empty() {
                writeln!(out, "RNR (reported, not directly observed): BSSID\tReporter\tClass\tChannel\tBand\tMHz")?;
                for n in self.data.rnr_neighbors.values() {
                    writeln!(
                        out,
                        "{}\t{}\t{}\t{}\t{}\t{}",
                        n.neighbor
                            .bssid
                            .as_ref()
                            .map(mac_string)
                            .unwrap_or_else(|| "?".into()),
                        mac_string(&n.reporter_bssid),
                        n.neighbor.operating_class,
                        n.neighbor.channel,
                        n.neighbor.radio.map(|r| r.band).unwrap_or("?"),
                        optional(n.neighbor.radio.map(|r| r.frequency_mhz))
                    )?;
                }
            }
            writeln!(out, "Client\tLast-BSSID\tdBm\tPackets\tProbe-SSID")?;
            for (mac, sta) in &self.data.stations {
                writeln!(
                    out,
                    "{}\t{}\t{}\t{}\t{}",
                    mac_string(mac),
                    sta.bssid
                        .as_ref()
                        .map(mac_string)
                        .unwrap_or_else(|| "?".into()),
                    optional(sta.signal),
                    sta.packets,
                    display_bytes(&sta.probe)
                )?;
            }
        }
        self.last_draw = Some(Instant::now());
        Ok(())
    }
}
fn optional(value: Option<impl ToString>) -> String {
    value.map(|v| v.to_string()).unwrap_or_else(|| "?".into())
}

fn execute(args: SurveyArgs) -> Result<Counts> {
    super::live::install_signals()?;
    let mut exports = super::survey_export::Exports::reserve(
        args.export_json.as_deref(),
        args.export_csv.as_deref(),
    )?;
    if let Some(path) = args.read {
        let mut view = Viewer::new(true)?;
        for record in air_capture::CaptureReader::open(
            path,
            air_capture::CaptureLimits {
                bytes: 4096 * 1024 * 1024,
                packets: 10_000_000,
            },
        )? {
            let record = record?;
            if !matches!(record.packet.dlt, 105 | 127) {
                bail!("survey needs raw 802.11 or Radiotap");
            }
            view.data.observe_record(
                record.packet.dlt,
                &record.packet.data,
                record.original_len,
                record.timestamp,
                view.started.elapsed(),
                args.bssid,
            );
        }
        view.draw("Offline passive inventory", true)?;
        exports.write(&view.data, view.started.elapsed())?;
        return Ok(Counts::from_survey(&view.data));
    }
    let iface = args.iface.as_deref().context("--iface is required")?;
    let mut radio = Channels::open(iface)?;
    if args.list_channels {
        println!(
            "Available 2.4/5 GHz channels: {}",
            radio
                .available
                .iter()
                .map(u16::to_string)
                .collect::<Vec<_>>()
                .join(",")
        );
        println!("Current channel: {}", optional(radio.current));
        if !radio.available_frequencies.is_empty() {
            println!(
                "Available frequencies (MHz): {}",
                radio
                    .available_frequencies
                    .iter()
                    .map(u16::to_string)
                    .collect::<Vec<_>>()
                    .join(",")
            );
        }
        println!(
            "Current frequency (MHz): {}",
            optional(radio.current_frequency)
        );
        if let Some(mode) = radio.mode {
            println!("CoreWLAN mode: {mode} (0 = unassociated, 1 = associated station)");
        }
        return Ok(Counts::default());
    }
    let output = args.output.context("--output is required")?;
    let diagnostics = air_platform::survey_log_path(&output);
    if output.exists() || diagnostics.exists() {
        bail!("output or diagnostic log already exists; refusing to overwrite");
    }
    radio.validate_survey()?;
    if let Some(channel) = args.channel {
        radio.validate(&[channel])?;
    }
    radio.validate(&args.channels)?;
    let frequency_mode = args.frequency.is_some() || !args.frequencies.is_empty();
    let selected_frequencies = if let Some(freq) = args.frequency {
        vec![freq]
    } else {
        args.frequencies.clone()
    };
    radio.validate_frequencies(&selected_frequencies)?;
    let mut plan = if frequency_mode {
        selected_frequencies
    } else if args.channels.is_empty() {
        radio.available.clone()
    } else {
        args.channels.clone()
    };
    let mut seen = std::collections::BTreeSet::new();
    plan.retain(|c| seen.insert(*c));
    let mut hopping = (args.channels.len() > 1 || args.frequencies.len() > 1) && plan.len() > 1;
    let mut index = (if frequency_mode {
        radio.current_frequency
    } else {
        radio.current
    })
    .and_then(|c| plan.iter().position(|p| *p == c))
    .unwrap_or(0);
    eprintln!("Passive survey on {iface}: monitor capture may disconnect Wi-Fi. No active scans or injection. Output: {}", output.display());
    if (if frequency_mode {
        radio.current_frequency.is_none()
    } else {
        radio.current.is_none()
    }) && (args.channel.is_some() || !args.channels.is_empty() || frequency_mode)
    {
        eprintln!("Original channel is unavailable; it cannot be restored after tuning.");
    }
    let mut view = Viewer::new(args.plain)?;
    let mut initial_tune = args.channel.is_some() || !args.channels.is_empty() || frequency_mode;
    let mut switched = Instant::now();
    let mut status = String::new();
    let options = air_platform::CaptureOptions {
        iface: iface.into(),
        output: output.clone(),
        bssid: args.bssid,
        monitor: cfg!(target_os = "macos"),
        duration: Duration::from_secs(args.duration),
        max_packets: args.max_packets,
    };
    let result = air_platform::survey(&options, || {
        if view.file.is_none() && output.exists() {
            view.file = Some(File::open(&output)?);
        }
        view.read(args.bssid, false)?;
        view.data.expire(
            view.started.elapsed(),
            Duration::from_secs(args.stale_seconds),
        );
        if super::live::is_interrupted() {
            view.stopped = true;
        }
        if view.stopped {
            return Ok(true);
        }
        // tcpdump must enter monitor mode before CoreWLAN can tune the adapter.
        let ready = view.stream.is_ready();
        if initial_tune && ready {
            let first = if frequency_mode {
                args.frequency.unwrap_or(plan[0])
            } else {
                args.channel.unwrap_or(plan[0])
            };
            index = plan.iter().position(|c| *c == first).unwrap_or(0);
            if frequency_mode {
                radio.set_frequency(first)?;
            } else {
                radio.set(first)?;
            }
            initial_tune = false;
            switched = Instant::now();
        }
        if let Some(dashboard) = &mut view.dashboard {
            match dashboard.input()? {
                Action::Quit => view.stopped = true,
                Action::Previous if ready && !plan.is_empty() => {
                    index = (index + plan.len() - 1) % plan.len();
                    if frequency_mode {
                        radio.set_frequency(plan[index])?;
                    } else {
                        radio.set(plan[index])?;
                    }
                    hopping = false;
                    switched = Instant::now();
                }
                Action::Next if ready && !plan.is_empty() => {
                    index = (index + 1) % plan.len();
                    if frequency_mode {
                        radio.set_frequency(plan[index])?;
                    } else {
                        radio.set(plan[index])?;
                    }
                    hopping = false;
                    switched = Instant::now();
                }
                Action::ToggleHop if ready && plan.len() > 1 => {
                    hopping = !hopping;
                    switched = Instant::now();
                }
                _ => {}
            }
        }
        if super::live::is_interrupted() {
            view.stopped = true;
        }
        if view.stopped {
            return Ok(true);
        }
        if ready && hopping && switched.elapsed() >= Duration::from_millis(args.dwell_ms) {
            index = (index + 1) % plan.len();
            if frequency_mode {
                radio.set_frequency(plan[index])?;
            } else {
                radio.set(plan[index])?;
            }
            switched = Instant::now();
        }
        status = format!(
            "{iface} | CH {} | MHz {} | {} | dwell {}ms",
            optional(radio.current),
            optional(radio.current_frequency),
            if hopping { "hopping" } else { "hold" },
            args.dwell_ms
        );
        view.draw(&status, false)?;
        Ok(false)
    });
    // Stop/reap tcpdump before restoring the channel or releasing terminal state.
    let restore = radio.restore();
    if result.is_ok() {
        if view.file.is_none() {
            view.file = Some(File::open(&output)?);
        }
        view.read(args.bssid, true)?;
        view.stream.finish()?;
        view.draw(&format!("Finished | {status}"), true)?;
    }
    let packets = view.data.packets;
    let view_stopped = view.stopped;
    drop(view.dashboard.take());
    result.with_context(|| {
        format!(
            "survey failed; tcpdump diagnostics: {}",
            diagnostics.display()
        )
    })?;
    restore?;
    if initial_tune && !view_stopped {
        bail!("capture ended before the requested channel was configured; inspect the partial capture and diagnostics");
    }
    if packets == 0 {
        bail!("no 802.11 packets received; a PCAP header alone does not confirm working monitor capture. Check adapter state and {}", diagnostics.display());
    }
    exports.write(&view.data, view.started.elapsed())?;
    let counts = Counts::from_survey(&view.data);
    drop(view);
    println!(
        "Survey finalized: {}\nDiagnostics: {}",
        output.display(),
        diagnostics.display()
    );
    Ok(counts)
}
