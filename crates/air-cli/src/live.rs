use anyhow::{bail, Context, Result};
use clap::{Args, Subcommand};
use std::fs::{self, OpenOptions};
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::{Duration, Instant, SystemTime};

static INTERRUPTED: AtomicBool = AtomicBool::new(false);

#[cfg(test)]
#[path = "live_tests.rs"]
mod tests;

#[derive(Args, Clone, Debug)]
pub struct CaptureArgs {
    /// Interface to capture on (use interfaces to list)
    #[arg(short, long)]
    iface: String,
    /// New pcap file; existing files are never overwritten
    #[arg(short, long, visible_alias = "write")]
    output: PathBuf,
    /// Exact authorized unicast BSSID; wildcards are deliberately unsupported
    #[arg(long, value_parser = super::parse_mac)]
    bssid: [u8; 6],
    /// Explicitly request monitor mode; may disconnect Wi-Fi on macOS
    #[arg(long)]
    monitor: bool,
    /// Hard time limit in seconds, 1..86400
    #[arg(long, default_value = "60", value_parser = clap::value_parser!(u64).range(1..=86400))]
    duration: u64,
    /// Stop after this many filtered packets
    #[arg(long, default_value = "10000", value_parser = clap::value_parser!(u32).range(1..))]
    max_packets: u32,
}

#[derive(Subcommand, Debug)]
pub enum Shadow {
    /// Start an explicitly managed, bounded passive background capture
    Start {
        #[command(flatten)]
        capture: CaptureArgs,
        /// New private directory for status, stop request and diagnostic log
        #[arg(long)]
        session: PathBuf,
    },
    /// Show status; stale heartbeat is never reported as running
    Status {
        #[arg(long)]
        session: PathBuf,
    },
    /// Request stop and wait for the worker to finalize its pcap
    Stop {
        #[arg(long)]
        session: PathBuf,
    },
    #[command(hide = true)]
    Worker {
        #[command(flatten)]
        capture: CaptureArgs,
        #[arg(long)]
        session: PathBuf,
    },
}

#[cfg(unix)]
extern "C" fn interrupted(_: libc::c_int) {
    INTERRUPTED.store(true, Ordering::Relaxed);
}

pub(crate) fn install_signals() -> Result<()> {
    #[cfg(unix)]
    unsafe {
        // The handler performs only an atomic store; cleanup runs on the main thread.
        if libc::signal(libc::SIGINT, interrupted as *const () as libc::sighandler_t)
            == libc::SIG_ERR
            || libc::signal(
                libc::SIGTERM,
                interrupted as *const () as libc::sighandler_t,
            ) == libc::SIG_ERR
            || libc::signal(libc::SIGHUP, interrupted as *const () as libc::sighandler_t)
                == libc::SIG_ERR
        {
            return Err(std::io::Error::last_os_error().into());
        }
    }
    air_platform::unblock_shutdown_signals()?;
    Ok(())
}

fn options(args: &CaptureArgs) -> air_platform::CaptureOptions {
    air_platform::CaptureOptions {
        iface: args.iface.clone(),
        output: args.output.clone(),
        bssid: Some(args.bssid),
        monitor: args.monitor,
        duration: Duration::from_secs(args.duration),
        max_packets: args.max_packets,
    }
}

pub fn foreground(args: CaptureArgs) -> Result<()> {
    install_signals()?;
    eprintln!(
        "Passive capture: {} -> {} ({}s maximum). No injection; Ctrl-C stops.",
        args.iface,
        args.output.display(),
        args.duration
    );
    if args.monitor {
        eprintln!("WARNING: explicit monitor mode may disconnect this Mac from Wi-Fi; no channel switching is performed.");
    }
    air_platform::capture(&options(&args), || INTERRUPTED.load(Ordering::Relaxed))?;
    println!("Capture finalized: {}", args.output.display());
    Ok(())
}

fn private_file(path: &Path) -> Result<std::fs::File> {
    let mut opts = OpenOptions::new();
    opts.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        opts.mode(0o600);
    }
    Ok(opts.open(path)?)
}

fn absolute(path: &Path) -> Result<PathBuf> {
    if path.is_absolute() {
        Ok(path.to_owned())
    } else {
        Ok(std::env::current_dir()?.join(path))
    }
}

fn create_session(path: &Path) -> Result<()> {
    #[cfg(unix)]
    let mut builder = fs::DirBuilder::new();
    #[cfg(not(unix))]
    let builder = fs::DirBuilder::new();
    #[cfg(unix)]
    {
        use std::os::unix::fs::DirBuilderExt;
        builder.mode(0o700);
    }
    builder
        .create(path)
        .context("session must be a new directory")?;
    Ok(())
}

fn verify_session(path: &Path) -> Result<()> {
    let meta = fs::symlink_metadata(path).context("cannot read session")?;
    if !meta.is_dir() || meta.file_type().is_symlink() {
        bail!("session must be a real directory");
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;
        if meta.uid() != unsafe { libc::geteuid() } || meta.mode() & 0o077 != 0 {
            bail!("session must be owned by the current user with permissions 0700");
        }
    }
    Ok(())
}

fn atomic_text(session: &Path, name: &str, text: &str) -> Result<()> {
    use std::io::Write;
    let temp = session.join(format!(".{name}.tmp"));
    let mut f = private_file(&temp)?;
    f.write_all(text.as_bytes())?;
    drop(f);
    fs::rename(temp, session.join(name))?;
    Ok(())
}

fn state(session: &Path) -> Result<String> {
    verify_session(session)?;
    if session.join("result").exists() {
        return Ok(fs::read_to_string(session.join("result"))?);
    }
    let heartbeat = fs::metadata(session.join("heartbeat"))
        .context("session has no heartbeat; worker did not start")?;
    let age = SystemTime::now()
        .duration_since(heartbeat.modified()?)
        .unwrap_or_default();
    if age > Duration::from_secs(5) {
        bail!("stale session: worker heartbeat is older than 5 seconds; inspect capture.log (no process was signalled)");
    }
    let pid = fs::read_to_string(session.join("pid")).unwrap_or_else(|_| "starting".into());
    Ok(format!(
        "active worker pid={} (capture may be initializing); see capture.log",
        pid.trim()
    ))
}

pub fn shadow(action: Shadow) -> Result<()> {
    match action {
        Shadow::Start {
            mut capture,
            session,
        } => {
            capture.output = absolute(&capture.output)?;
            let session = absolute(&session)?;
            // Validate before creating any process or session.
            air_platform::validate_options(&options(&capture))?;
            let mac = capture.bssid;
            if capture.output.exists() {
                bail!("output already exists; refusing to overwrite");
            }
            create_session(&session)?;
            let log = private_file(&session.join("capture.log"))?;
            let mut command = Command::new(std::env::current_exe()?);
            #[cfg(unix)]
            {
                use std::os::unix::process::CommandExt;
                command.process_group(0);
            }
            let mut child = command
                .args(["shadow", "worker", "--iface", &capture.iface, "--output"])
                .arg(&capture.output)
                .args([
                    "--bssid",
                    &mac.iter()
                        .map(|b| format!("{b:02x}"))
                        .collect::<Vec<_>>()
                        .join(":"),
                    "--duration",
                    &capture.duration.to_string(),
                    "--max-packets",
                    &capture.max_packets.to_string(),
                ])
                .args(if capture.monitor {
                    vec!["--monitor"]
                } else {
                    vec![]
                })
                .arg("--session")
                .arg(&session)
                .stdin(Stdio::null())
                .stdout(Stdio::from(log.try_clone()?))
                .stderr(Stdio::from(log))
                .spawn()
                .context("cannot launch background worker")?;
            let deadline = Instant::now() + Duration::from_secs(2);
            while Instant::now() < deadline {
                if let Some(status) = child.try_wait()? {
                    println!("{}", state(&session).unwrap_or_else(|e| e.to_string()));
                    if !status.success() {
                        bail!(
                            "background capture failed; inspect {}",
                            session.join("capture.log").display()
                        );
                    }
                    return Ok(());
                }
                std::thread::sleep(Duration::from_millis(100));
            }
            let current = match state(&session) {
                Ok(text) => text,
                Err(e) => {
                    let _ = private_file(&session.join("STOP"));
                    return Err(
                        e.context("startup unconfirmed; requested stop; inspect capture.log")
                    );
                }
            };
            println!("{current}");
            if current.starts_with("failed:") {
                bail!("background capture failed; inspect capture.log");
            }
            println!("Session: {}\nStop explicitly with shadow stop --session <directory>. Hard limit: {}s.", session.display(), capture.duration);
            Ok(())
        }
        Shadow::Status { session } => {
            let text = state(&session)?;
            println!("{text}");
            if text.starts_with("failed:") {
                bail!("capture failed; inspect capture.log");
            }
            Ok(())
        }
        Shadow::Stop { session } => {
            verify_session(&session)?;
            if !session.join("result").exists() {
                // Stop by a private request file, never by an untrusted/reused PID.
                if let Err(e) = private_file(&session.join("STOP")) {
                    if !session.join("STOP").exists() {
                        return Err(e);
                    }
                }
            }
            let deadline = Instant::now() + Duration::from_secs(10);
            while !session.join("result").exists() && Instant::now() < deadline {
                std::thread::sleep(Duration::from_millis(100));
            }
            if !session.join("result").exists() {
                bail!("stop requested but finalization not confirmed; inspect capture.log");
            }
            let text = state(&session)?;
            println!("{text}");
            if text.starts_with("failed:") {
                bail!("capture failed; inspect capture.log");
            }
            Ok(())
        }
        Shadow::Worker { capture, session } => {
            install_signals()?;
            worker(capture, session, |opts, stop| {
                air_platform::capture(opts, stop).map_err(anyhow::Error::from)
            })
        }
    }
}

fn worker(
    capture: CaptureArgs,
    session: PathBuf,
    run: impl FnOnce(&air_platform::CaptureOptions, &dyn Fn() -> bool) -> Result<()>,
) -> Result<()> {
    verify_session(&session)?;
    // Prevent two workers from sharing a session, including hidden manual invocation.
    let _guard = private_file(&session.join("worker.lock"))?;
    atomic_text(&session, "pid", &std::process::id().to_string())?;
    atomic_text(&session, "heartbeat", "active")?;
    let last = std::cell::Cell::new(Instant::now());
    let failed_heartbeat = AtomicBool::new(false);
    let result = run(&options(&capture), &|| {
        if last.get().elapsed() >= Duration::from_secs(1) {
            if atomic_text(&session, "heartbeat", "active").is_err() {
                failed_heartbeat.store(true, Ordering::Relaxed);
            }
            last.set(Instant::now());
        }
        INTERRUPTED.load(Ordering::Relaxed)
            || session.join("STOP").exists()
            || failed_heartbeat.load(Ordering::Relaxed)
    });
    let result = result.and_then(|()| {
        if failed_heartbeat.load(Ordering::Relaxed) {
            bail!("could not update worker heartbeat");
        }
        Ok(())
    });
    let text = match &result {
        Ok(()) => format!(
            "completed: capture finalized at {}",
            capture.output.display()
        ),
        Err(e) => format!("failed: {e:#}"),
    };
    atomic_text(&session, "result", &text)?;
    result
}

pub(crate) fn is_interrupted() -> bool {
    INTERRUPTED.load(Ordering::Relaxed)
}
