mod benchmark;
mod capture_output;
mod decap;
mod decap_keys;
mod dictionary;
mod exit;
mod live;
mod multi;
mod offline;
mod survey;
mod survey_export;
mod wifi_scan;
mod wpaclean;

use air_capture::CaptureLimits;
use anyhow::bail;
use clap::{Parser, Subcommand};
use std::path::PathBuf;

#[derive(Parser, Debug)]
#[command(
    name = "aircrack",
    version,
    about = "Passive live capture and offline WPA/WPA2-PSK verification (experimental)",
    long_about = "Capture authorized traffic passively with a bounded tcpdump backend,\nor inspect WPA2 M1/M2, M2/M3 or M3/M4 handshakes and PMKID records and verify a local wordlist.\n\nWPA/WPA2-PSK descriptor v1/v2/v3 verification is implemented. Airdecap supports\nCCMP/TKIP/WEP decryption, authenticated GTK and open traffic. FT personal roaming and imported SAE PMKs are supported. Injection and passive SAE password guessing are not supported. Monitor mode is opt-in\nand may disconnect Wi-Fi. Shadow means an explicit background capture,\nnot stealth or persistence. Use only on networks you are authorized to audit."
)]
struct Cli {
    #[command(subcommand)]
    cmd: Commands,
}

#[derive(Subcommand, Debug)]
enum Commands {
    /// Synthetic PBKDF2, dictionary and persistent-cache benchmark
    Benchmark(benchmark::BenchArgs),
    /// Ordinary macOS Wi-Fi overview without monitor mode or disconnection
    Scan(wifi_scan::ScanArgs),
    /// Passive AP/client dashboard with channel selection and hopping
    Survey(survey::SurveyArgs),
    /// List capture interfaces reported by the local tcpdump
    Interfaces,
    /// Foreground passive capture with an exact authorized BSSID and hard limits
    Live(live::CaptureArgs),
    /// Explicit passive background capture: start, status, stop (no persistence)
    Shadow {
        #[command(subcommand)]
        action: live::Shadow,
    },
    /// Not implemented: monitor-mode interface management
    Airmon {
        #[command(subcommand)]
        action: AirmonAction,
    },
    /// Alias of live: bounded passive capture, not active probing
    Airodump(live::CaptureArgs),
    /// Not implemented: packet injection / replay
    Aireplay {
        #[arg(short = '0', long)]
        deauth: bool,
        #[arg(short, long)]
        iface: Option<String>,
        #[arg(short = 'a', long)]
        bssid: Option<String>,
        #[arg(short = 'c', long)]
        client: Option<String>,
        #[arg(short = 'n', long, default_value = "0")]
        count: u32,
    },
    /// Not implemented: access-point emulation
    Airbase {
        #[arg(short, long)]
        iface: Option<String>,
        #[arg(short = 'e', long)]
        essid: Option<String>,
        #[arg(short, long, default_value = "6")]
        channel: u8,
    },
    /// Decrypt CCMP/TKIP/WEP (pairwise or GTK) or strip open Wi-Fi traffic into a new PCAP
    Airdecap(decap::DecapArgs),
    /// Not implemented: packet forging
    Packetforge {
        #[arg(short, long)]
        arp: bool,
        #[arg(short, long)]
        output: Option<PathBuf>,
    },
    /// Not implemented: IV processing
    Ivstools {
        #[arg(short, long)]
        input: Option<PathBuf>,
    },
    /// Keep supported verification evidence and SSID context in a new PCAP
    Wpaclean(wpaclean::CleanArgs),
    /// Verify personal-network targets across ordered captures and dictionaries
    Aircrack {
        #[arg(short, long, required=true, num_args=1..)]
        capture: Vec<PathBuf>,
        #[arg(short, long, num_args=1..)]
        wordlist: Vec<PathBuf>,
        #[arg(short = 'e', long)]
        essid: Option<String>,
        /// Select BSSIDs explicitly; repeat to include several networks
        #[arg(long, value_parser = parse_mac)]
        bssid: Vec<[u8; 6]>,
        /// JSON list of {bssid, ssid_hex} mappings for hidden/conflicting SSIDs
        #[arg(long)]
        ssid_map: Option<PathBuf>,
        #[command(flatten)]
        dictionary: dictionary::Options,
        /// Maximum capture size in MiB (work budget; memory is bounded independently)
        #[arg(long, default_value = "4096", value_parser = clap::value_parser!(u64).range(1..=1048576))]
        max_capture_mib: u64,
        #[arg(long, default_value = "10000000", value_parser = clap::value_parser!(u32).range(1..))]
        max_packets: u32,
        /// Maximum relevant EAPOL/association records before pairing
        #[arg(long, default_value = "1024", value_parser = clap::value_parser!(u32).range(1..=1024))]
        max_records: u32,
        #[arg(long, default_value = "1024", value_parser = clap::value_parser!(u32).range(1..=1024))]
        max_targets: u32,
        /// Write a small machine diagnostic (exit category, counts, error) as
        /// private JSON (new path only). No password or PMK is ever included.
        /// Use --json=PATH for names starting with a hyphen; "-" is a literal file, not stdout.
        #[arg(long, alias = "json")]
        diagnostic_json: Option<PathBuf>,
    },
    /// Interactive UI preview (not connected to capture or verification)
    Tui,
}

#[derive(Subcommand, Debug)]
enum AirmonAction {
    Start { iface: String },
    Stop { iface: String },
    Check,
}

fn parse_mac(value: &str) -> Result<[u8; 6], String> {
    let parts: Vec<_> = value.split(':').collect();
    if parts.len() != 6 || parts.iter().any(|p| p.len() != 2) {
        return Err("expected BSSID aa:bb:cc:dd:ee:ff".into());
    }
    let mut out = [0; 6];
    for (byte, part) in out.iter_mut().zip(parts) {
        *byte = u8::from_str_radix(part, 16).map_err(|_| "invalid BSSID".to_owned())?;
    }
    Ok(out)
}

fn main() -> anyhow::Result<()> {
    let cli = match Cli::try_parse() {
        Ok(cli) => cli,
        Err(error) => {
            // Keep clap help/version behavior for the Stage 1 commands.
            let args: Vec<_> = std::env::args_os().skip(1).collect();
            let kind = match args.first().and_then(|arg| arg.to_str()) {
                Some("aircrack") => Some("aircrack_diagnostic"),
                Some("airdecap") => Some("airdecap_diagnostic"),
                Some("survey") => Some("survey_diagnostic"),
                _ => None,
            };
            if error.use_stderr() {
                if let Some(kind) = kind {
                    let mut path = None;
                    for (index, arg) in args.iter().enumerate().skip(1) {
                        if arg == "--" {
                            break;
                        }
                        if arg == "--diagnostic-json" || arg == "--json" {
                            path = args
                                .get(index + 1)
                                .filter(|value| {
                                    *value == "-" || !value.to_string_lossy().starts_with('-')
                                })
                                .map(PathBuf::from);
                        } else if let Some(value) = arg.to_str().and_then(|s| {
                            s.strip_prefix("--diagnostic-json=")
                                .or_else(|| s.strip_prefix("--json="))
                        }) {
                            path = Some(PathBuf::from(value));
                        }
                    }
                    let _ = error.print();
                    let result = exit::Diagnostic::reserve(path.as_deref())
                        .map_err(|error| (error, exit::USAGE))
                        .and_then(|mut diagnostic| {
                            diagnostic
                                .write(
                                    kind,
                                    exit::Category::Usage,
                                    exit::Summary {
                                        counts: serde_json::json!({}),
                                        verification: (kind == "aircrack_diagnostic")
                                            .then_some("not_attempted"),
                                    },
                                    Some("invalid command arguments or configuration"),
                                )
                                .map_err(|error| (error, exit::INTERNAL))
                        });
                    if let Err((error, code)) = result {
                        eprintln!("Error: {error:#}");
                        std::process::exit(code);
                    }
                    std::process::exit(exit::USAGE);
                }
            }
            error.exit();
        }
    };
    match cli.cmd {
        Commands::Benchmark(args) => benchmark::run(args),
        Commands::Scan(args) => wifi_scan::run(args),
        Commands::Survey(args) => survey::run(args),
        Commands::Interfaces => {
            print!("{}", air_platform::list_interfaces()?);
            Ok(())
        }
        Commands::Live(args) | Commands::Airodump(args) => live::foreground(args),
        Commands::Shadow { action } => live::shadow(action),
        Commands::Aircrack {
            capture,
            wordlist,
            essid,
            bssid,
            dictionary,
            ssid_map,
            max_capture_mib,
            max_packets,
            max_records,
            max_targets,
            diagnostic_json,
        } => offline::run(
            capture,
            wordlist,
            essid,
            bssid,
            ssid_map,
            dictionary,
            (
                CaptureLimits {
                    bytes: max_capture_mib * 1024 * 1024,
                    packets: max_packets as usize,
                },
                max_records as usize,
                max_targets as usize,
            ),
            diagnostic_json,
        ),
        Commands::Tui => air_tui::run(),
        Commands::Airmon { .. } => bail!("airmon is not implemented; no interface changes made"),
        Commands::Aireplay { .. } => bail!("aireplay injection is not implemented"),
        Commands::Airbase { .. } => bail!("airbase is not implemented"),
        Commands::Airdecap(args) => decap::run(args),
        Commands::Packetforge { .. } => bail!("packetforge is not implemented"),
        Commands::Ivstools { .. } => bail!("ivstools is not implemented"),
        Commands::Wpaclean(args) => wpaclean::run(args),
    }
}
