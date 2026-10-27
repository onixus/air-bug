pub mod channels;
pub mod wifi_scan;

// Passive, explicitly BSSID-allowlisted tcpdump capture.
//
// A valid PCAP containing only its global header (zero observed packets) is a
// successful capture. Errors may leave a partial output for diagnosis; callers
// must not treat a file's existence as success. No interface configuration or
// monitor-mode enabling is performed beyond tcpdump's explicit `-I` request.

use std::ffi::OsString;
use std::fs::{File, OpenOptions};
use std::io::{Read, Seek, SeekFrom};
use std::path::{Path, PathBuf};
use std::process::{Child, Command, ExitStatus, Stdio};
use std::thread;
use std::time::{Duration, Instant};
use thiserror::Error;

#[derive(Debug, Error)]
pub enum PlatformError {
    #[error("unsupported platform")]
    Unsupported,
    #[error("io: {0}")]
    Io(#[from] std::io::Error),
    #[error("invalid capture options: {0}")]
    InvalidOptions(&'static str),
    #[error("capture cancelled before starting")]
    Cancelled,
    #[error("tcpdump exited unsuccessfully: {0}")]
    TcpdumpFailed(ExitStatus),
    #[error("tcpdump did not stop gracefully and was killed")]
    ForcedTermination,
    #[error("tcpdump output is not a complete, valid PCAP global header")]
    InvalidCapture,
    #[error("tcpdump returned interface names that are not UTF-8")]
    InvalidInterfaceList,
}

#[derive(Debug, Clone)]
pub struct CaptureOptions {
    pub iface: String,
    pub output: PathBuf,
    /// Required in both modes; must be a nonzero unicast MAC address.
    pub bssid: Option<[u8; 6]>,
    pub monitor: bool,
    /// Inclusive range: one second through 24 hours.
    pub duration: Duration,
    pub max_packets: u32,
}

pub trait CaptureBackend {
    fn list_interfaces(&self) -> Vec<String>;
}

pub struct NullPlatform;
impl CaptureBackend for NullPlatform {
    fn list_interfaces(&self) -> Vec<String> {
        vec![]
    }
}

fn tcpdump_path() -> Result<&'static Path, PlatformError> {
    #[cfg(target_os = "macos")]
    {
        Ok(Path::new("/usr/sbin/tcpdump"))
    }
    #[cfg(target_os = "linux")]
    {
        Ok(Path::new("/usr/bin/tcpdump"))
    }
    #[cfg(not(any(target_os = "macos", target_os = "linux")))]
    {
        Err(PlatformError::Unsupported)
    }
}

/// Reports fixed-path tool availability, not capture permissions or monitor support.
pub fn supported() -> bool {
    let Ok(path) = tcpdump_path() else {
        return false;
    };
    let Ok(metadata) = path.metadata() else {
        return false;
    };
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        metadata.is_file() && metadata.permissions().mode() & 0o111 != 0
    }
    #[cfg(not(unix))]
    {
        metadata.is_file()
    }
}

/// List tcpdump interfaces without opening a capture device or invoking a shell.
pub fn list_interfaces() -> Result<String, PlatformError> {
    let output = Command::new(tcpdump_path()?)
        .arg("-D")
        .stdin(Stdio::null())
        .stderr(Stdio::inherit())
        .output()?;
    if !output.status.success() {
        return Err(PlatformError::TcpdumpFailed(output.status));
    }
    String::from_utf8(output.stdout).map_err(|_| PlatformError::InvalidInterfaceList)
}

fn capture_args(options: &CaptureOptions) -> Result<Vec<OsString>, PlatformError> {
    if options.iface.is_empty()
        || options.iface.starts_with('-')
        || !options
            .iface
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b"_.:-".contains(&b))
    {
        return Err(PlatformError::InvalidOptions("unsafe interface name"));
    }
    if !(Duration::from_secs(1)..=Duration::from_secs(86400)).contains(&options.duration) {
        return Err(PlatformError::InvalidOptions(
            "duration must be 1..=86400 seconds",
        ));
    }
    if options.max_packets == 0 {
        return Err(PlatformError::InvalidOptions(
            "max_packets must be positive",
        ));
    }
    let bssid = options.bssid.ok_or(PlatformError::InvalidOptions(
        "an explicit BSSID is required",
    ))?;
    if bssid == [0; 6] || bssid == [255; 6] || bssid[0] & 1 != 0 {
        return Err(PlatformError::InvalidOptions(
            "BSSID must be nonzero unicast",
        ));
    }
    let mac = bssid
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect::<Vec<_>>()
        .join(":");
    let mut args: Vec<OsString> = vec![
        "-U".into(),
        "-n".into(),
        "-i".into(),
        options.iface.clone().into(),
        "-s".into(),
        "0".into(),
        "-c".into(),
        options.max_packets.to_string().into(),
        "-w".into(),
        "-".into(),
    ];
    if options.monitor {
        // Infrastructure BSSID position depends on ToDS/FromDS. WDS frames have
        // no BSSID; include only links whose receiver/transmitter is the selection.
        args.push("-I".into());
        args.push(monitor_filter(&mac).into());
    } else {
        args.extend([
            "-p".into(),
            "ether".into(),
            "proto".into(),
            "0x888e".into(),
            "and".into(),
            "ether".into(),
            "host".into(),
            mac.into(),
        ]);
    }
    Ok(args)
}

fn monitor_filter(mac: &str) -> String {
    format!(
        "(wlan[1] & 3 = 0 and wlan addr3 {mac}) or \
         (wlan[1] & 3 = 1 and wlan addr1 {mac}) or \
         (wlan[1] & 3 = 2 and wlan addr2 {mac}) or \
         (wlan[1] & 3 = 3 and (wlan addr1 {mac} or wlan addr2 {mac}))"
    )
}

/// Validate capture parameters without opening a device or creating output.
pub fn validate_options(options: &CaptureOptions) -> Result<(), PlatformError> {
    capture_args(options).map(|_| ())
}

/// Capture passively with a bounded runtime and an explicit BSSID allowlist.
///
/// The output is exclusively created (0600 on Unix); existing files and symlinks
/// are never followed or overwritten. Cancellation is a successful completion
/// only if tcpdump exits successfully and produces a valid PCAP header. A stop
/// already requested before launch returns `Cancelled` without creating output.
pub fn capture(options: &CaptureOptions, stop: impl Fn() -> bool) -> Result<(), PlatformError> {
    capture_with_program(options, stop, tcpdump_path()?)
}

fn capture_with_program(
    options: &CaptureOptions,
    stop: impl Fn() -> bool,
    program: &Path,
) -> Result<(), PlatformError> {
    run_capture(
        options,
        capture_args(options)?,
        || Ok(stop()),
        program,
        None,
    )
}

/// Broad passive survey; unlike live/shadow, an optional BSSID filter is allowed.
/// The callback runs on the supervisor thread while capture is active.
pub fn survey(
    options: &CaptureOptions,
    tick: impl FnMut() -> std::io::Result<bool>,
) -> Result<(), PlatformError> {
    run_capture(
        options,
        survey_args(options)?,
        tick,
        tcpdump_path()?,
        Some(&survey_log_path(&options.output)),
    )
}

pub fn survey_log_path(output: &Path) -> PathBuf {
    let mut path = output.as_os_str().to_owned();
    path.push(".log");
    PathBuf::from(path)
}

fn survey_args(options: &CaptureOptions) -> Result<Vec<OsString>, PlatformError> {
    let mut validated = options.clone();
    validated.bssid = Some(options.bssid.unwrap_or([2, 0, 0, 0, 0, 1]));
    validated.monitor = true;
    let mut args = capture_args(&validated)?;
    args.pop(); // replace exact-BSSID filter with survey filter
    if !options.monitor {
        args.pop(); // existing Linux monitor interface does not need tcpdump -I
    }
    args[5] = "4096".into(); // bounded record size, enough for management headers
    let filter = match options.bssid {
        Some(mac) => monitor_filter(
            &mac.iter()
                .map(|b| format!("{b:02x}"))
                .collect::<Vec<_>>()
                .join(":"),
        ),
        None => "type mgt or type data".into(),
    };
    args.push(filter.into());
    Ok(args)
}

fn run_capture(
    options: &CaptureOptions,
    args: Vec<OsString>,
    mut tick: impl FnMut() -> std::io::Result<bool>,
    program: &Path,
    diagnostics: Option<&Path>,
) -> Result<(), PlatformError> {
    if tick()? {
        return Err(PlatformError::Cancelled);
    }
    let mut open = OpenOptions::new();
    open.read(true).write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        open.mode(0o600);
    }
    let mut output = open.open(&options.output)?;
    let stderr = if let Some(path) = diagnostics {
        let mut log = OpenOptions::new();
        log.write(true).create_new(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            log.mode(0o600);
        }
        Stdio::from(log.open(path)?)
    } else {
        Stdio::inherit()
    };
    let mut command = Command::new(program);
    command
        .args(args)
        .stdin(Stdio::null())
        .stdout(Stdio::from(output.try_clone()?))
        .stderr(stderr);
    prepare_capture_child(&mut command);
    let child = command.spawn()?;
    let mut child = ChildGuard(Some(child));
    let started = Instant::now();
    let status = loop {
        if let Some(status) = child.0.as_mut().expect("owned child").try_wait()? {
            child.0.take();
            break status;
        }
        if tick()? || started.elapsed() >= options.duration {
            break child.finish()?;
        }
        thread::sleep(Duration::from_millis(25));
    };
    if !status.success() {
        return Err(PlatformError::TcpdumpFailed(status));
    }
    validate_pcap(&mut output)
}

/// Authorization Services / launchers may leave shutdown signals blocked across exec.
/// Installing a handler alone does not unblock them.
pub fn unblock_shutdown_signals() -> std::io::Result<()> {
    #[cfg(unix)]
    unsafe {
        let mut set: libc::sigset_t = std::mem::zeroed();
        libc::sigemptyset(&mut set);
        for signal in [libc::SIGINT, libc::SIGTERM, libc::SIGHUP] {
            libc::sigaddset(&mut set, signal);
        }
        let code = libc::pthread_sigmask(libc::SIG_UNBLOCK, &set, std::ptr::null_mut());
        if code != 0 {
            return Err(std::io::Error::from_raw_os_error(code));
        }
    }
    Ok(())
}

fn prepare_capture_child(command: &mut Command) {
    #[cfg(unix)]
    {
        use std::os::unix::process::CommandExt;
        command.process_group(0);
        // SAFETY: this closure only uses async-signal-safe signal syscalls; no locks,
        // heap allocation or logging between fork and exec.
        unsafe {
            command.pre_exec(|| {
                let mut action: libc::sigaction = std::mem::zeroed();
                action.sa_sigaction = libc::SIG_DFL;
                libc::sigemptyset(&mut action.sa_mask);
                let mut mask: libc::sigset_t = std::mem::zeroed();
                libc::sigemptyset(&mut mask);
                for signal in [libc::SIGINT, libc::SIGTERM, libc::SIGHUP] {
                    if libc::sigaction(signal, &action, std::ptr::null_mut()) == -1 {
                        return Err(std::io::Error::last_os_error());
                    }
                    libc::sigaddset(&mut mask, signal);
                }
                if libc::sigprocmask(libc::SIG_UNBLOCK, &mask, std::ptr::null_mut()) == -1 {
                    return Err(std::io::Error::last_os_error());
                }
                Ok(())
            });
        }
    }
    #[cfg(not(unix))]
    let _ = command;
}

struct ChildGuard(Option<Child>);
impl ChildGuard {
    fn finish(&mut self) -> Result<ExitStatus, PlatformError> {
        let Some(child) = self.0.as_mut() else {
            unreachable!("owned child")
        };
        #[cfg(unix)]
        {
            // Only signal our owned, unreaped child. Never invoke a shell/kill tool.
            if unsafe { libc::kill(child.id() as libc::pid_t, libc::SIGINT) } == -1 {
                let error = std::io::Error::last_os_error();
                if error.raw_os_error() != Some(libc::ESRCH) {
                    return Err(error.into());
                }
            }
        }
        let deadline = Instant::now() + Duration::from_secs(2);
        loop {
            if let Some(status) = child.try_wait()? {
                self.0.take();
                return Ok(status);
            }
            if Instant::now() >= deadline {
                break;
            }
            thread::sleep(Duration::from_millis(25));
        }
        // Retain ownership on any error so Drop still retries kill + wait.
        child.kill()?;
        child.wait()?;
        self.0.take();
        Err(PlatformError::ForcedTermination)
    }
}
impl Drop for ChildGuard {
    fn drop(&mut self) {
        if self.0.is_some() && self.finish().is_err() {
            if let Some(child) = self.0.as_mut() {
                let _ = child.kill();
                let _ = child.wait();
            }
        }
    }
}

fn validate_pcap(output: &mut File) -> Result<(), PlatformError> {
    output.seek(SeekFrom::Start(0))?;
    let mut header = [0u8; 24];
    if let Err(error) = output.read_exact(&mut header) {
        return if error.kind() == std::io::ErrorKind::UnexpectedEof {
            Err(PlatformError::InvalidCapture)
        } else {
            Err(error.into())
        };
    }
    let little = match header[..4] {
        [0xd4, 0xc3, 0xb2, 0xa1] | [0x4d, 0x3c, 0xb2, 0xa1] => true,
        [0xa1, 0xb2, 0xc3, 0xd4] | [0xa1, 0xb2, 0x3c, 0x4d] => false,
        _ => return Err(PlatformError::InvalidCapture),
    };
    let valid_version = if little {
        header[4..8] == [2, 0, 4, 0]
    } else {
        header[4..8] == [0, 2, 0, 4]
    };
    if !valid_version || header[16..20] == [0; 4] {
        return Err(PlatformError::InvalidCapture);
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicU64, Ordering};

    static NEXT: AtomicU64 = AtomicU64::new(0);
    pub(super) struct TestDir(pub(super) PathBuf);
    impl TestDir {
        pub(super) fn new() -> Self {
            let path = std::env::temp_dir().join(format!(
                "air-platform-{}-{}",
                std::process::id(),
                NEXT.fetch_add(1, Ordering::Relaxed)
            ));
            std::fs::create_dir(&path).unwrap();
            Self(path)
        }
    }
    impl Drop for TestDir {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.0);
        }
    }
    fn options(path: PathBuf) -> CaptureOptions {
        CaptureOptions {
            iface: "en0".into(),
            output: path,
            bssid: Some([2, 1, 2, 3, 4, 5]),
            monitor: false,
            // Fork/exec of simultaneous test scripts can take >1s on macOS.
            duration: Duration::from_secs(5),
            max_packets: 10,
        }
    }
    #[test]
    fn validates_capture_boundaries() {
        let base = options("unused".into());
        for name in ["", "-en0", "en 0", "en0;id", "é", "en0\n"] {
            let mut opts = base.clone();
            opts.iface = name.into();
            assert!(capture_args(&opts).is_err(), "{name:?}");
        }
        for name in ["en0", "wlan0", "a_b.c:1-2"] {
            let mut opts = base.clone();
            opts.iface = name.into();
            assert!(capture_args(&opts).is_ok());
        }
        for duration in [
            Duration::ZERO,
            Duration::from_millis(999),
            Duration::from_secs(86401),
        ] {
            let mut opts = base.clone();
            opts.duration = duration;
            assert!(capture_args(&opts).is_err());
        }
        let mut opts = base.clone();
        opts.duration = Duration::from_secs(86400);
        assert!(capture_args(&opts).is_ok());
        opts.max_packets = 0;
        assert!(capture_args(&opts).is_err());
        for bssid in [None, Some([0; 6]), Some([255; 6]), Some([1, 2, 3, 4, 5, 6])] {
            let mut opts = base.clone();
            opts.bssid = bssid;
            assert!(capture_args(&opts).is_err());
        }
    }
    #[test]
    fn constructs_narrow_filters_without_shell() {
        let mut opts = options("unused".into());
        let args = capture_args(&opts).unwrap();
        assert_eq!(
            args,
            [
                "-U",
                "-n",
                "-i",
                "en0",
                "-s",
                "0",
                "-c",
                "10",
                "-w",
                "-",
                "-p",
                "ether",
                "proto",
                "0x888e",
                "and",
                "ether",
                "host",
                "02:01:02:03:04:05"
            ]
            .map(OsString::from)
        );
        opts.monitor = true;
        let args = capture_args(&opts).unwrap();
        assert!(!args.contains(&OsString::from("-p")));
        assert_eq!(
            &args[10..],
            &[
                OsString::from("-I"),
                OsString::from(monitor_filter("02:01:02:03:04:05"))
            ]
        );
    }
    #[test]
    fn does_not_overwrite_output_or_start_when_cancelled() {
        let dir = TestDir::new();
        let opts = options(dir.0.join("capture"));
        std::fs::write(&opts.output, b"keep").unwrap();
        assert!(capture_with_program(&opts, || false, Path::new("/nonexistent")).is_err());
        assert_eq!(std::fs::read(&opts.output).unwrap(), b"keep");
        let opts = options(dir.0.join("cancelled"));
        assert!(matches!(
            capture_with_program(&opts, || true, Path::new("/nonexistent")),
            Err(PlatformError::Cancelled)
        ));
        assert!(!opts.output.exists());
    }
    #[cfg(unix)]
    fn fake(dir: &TestDir, body: &str) -> PathBuf {
        use std::os::unix::fs::PermissionsExt;
        let path = dir.0.join("fake-tcpdump");
        std::fs::write(&path, format!("#!/bin/sh\n{body}\n")).unwrap();
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o700)).unwrap();
        path
    }
    #[cfg(unix)]
    const HEADER: &str = "printf '\\324\\303\\262\\241\\002\\000\\004\\000\\000\\000\\000\\000\\000\\000\\000\\000\\377\\377\\000\\000\\001\\000\\000\\000'";
    #[cfg(unix)]
    #[test]
    fn accepts_header_only_and_rejects_empty_or_failed_capture() {
        use std::os::unix::fs::PermissionsExt;
        let dir = TestDir::new();
        let program = fake(&dir, HEADER);
        let opts = options(dir.0.join("valid"));
        capture_with_program(&opts, || false, &program).unwrap();
        assert_eq!(
            std::fs::metadata(&opts.output)
                .unwrap()
                .permissions()
                .mode()
                & 0o777,
            0o600
        );
        let program = fake(&dir, "exit 0");
        assert!(matches!(
            capture_with_program(&options(dir.0.join("empty")), || false, &program),
            Err(PlatformError::InvalidCapture)
        ));
        let program = fake(&dir, "exit 7");
        assert!(matches!(
            capture_with_program(&options(dir.0.join("failed")), || false, &program),
            Err(PlatformError::TcpdumpFailed(_))
        ));
    }
    #[cfg(unix)]
    #[test]
    fn rejects_output_symlinks() {
        let dir = TestDir::new();
        let target = dir.0.join("target");
        std::fs::write(&target, b"keep").unwrap();
        let opts = options(dir.0.join("link"));
        std::os::unix::fs::symlink(&target, &opts.output).unwrap();
        assert!(capture_with_program(&opts, || false, Path::new("/nonexistent")).is_err());
        assert_eq!(std::fs::read(target).unwrap(), b"keep");
    }
    #[cfg(unix)]
    #[test]
    fn cancellation_interrupts_and_reaps_fake_child() {
        let dir = TestDir::new();
        let program = fake(
            &dir,
            &format!("trap 'exit 0' INT\n{HEADER}\nwhile :; do :; done"),
        );
        let opts = options(dir.0.join("cancel"));
        let started = Instant::now();
        capture_with_program(
            &opts,
            || {
                started.elapsed() > Duration::from_millis(100)
                    && opts
                        .output
                        .metadata()
                        .map(|m| m.len() >= 24)
                        .unwrap_or(false)
            },
            &program,
        )
        .unwrap();
        assert!(started.elapsed() < Duration::from_secs(8));
    }
    #[cfg(unix)]
    #[test]
    fn duration_stops_fake_child_and_nonresponsive_child_is_killed() {
        let dir = TestDir::new();
        let program = fake(
            &dir,
            &format!("trap 'exit 0' INT\n{HEADER}\nwhile :; do :; done"),
        );
        capture_with_program(&options(dir.0.join("duration")), || false, &program).unwrap();
        let program = fake(&dir, &format!("trap '' INT\n{HEADER}\nwhile :; do :; done"));
        let started = Instant::now();
        let opts = options(dir.0.join("forced"));
        assert!(matches!(
            capture_with_program(
                &opts,
                || {
                    started.elapsed() > Duration::from_millis(100)
                        && opts
                            .output
                            .metadata()
                            .map(|m| m.len() >= 24)
                            .unwrap_or(false)
                },
                &program
            ),
            Err(PlatformError::ForcedTermination)
        ));
        assert!(started.elapsed() < Duration::from_secs(10));
    }

    #[test]
    fn real_tcpdump_offline_filter_matches_bssid_not_other_addresses() {
        if !supported() {
            eprintln!("skipping offline tcpdump filter test: fixed-path tool absent");
            return;
        }
        let dir = TestDir::new();
        let fixture = dir.0.join("synthetic-wifi.pcap");
        let target = [2, 1, 2, 3, 4, 5];
        let other = [2, 9, 9, 9, 9, 9];
        let station = [2, 8, 8, 8, 8, 8];
        let endpoint = [2, 7, 7, 7, 7, 7];
        // Native 802.11 linktype (105), with no real captured network traffic.
        let mut pcap = vec![0xd4, 0xc3, 0xb2, 0xa1, 2, 0, 4, 0];
        pcap.extend([0u8; 8]);
        pcap.extend(65535u32.to_le_bytes());
        pcap.extend(105u32.to_le_bytes());
        let cases = [
            (0x80, 0, [255; 6], target, target),  // beacon
            (0x08, 1, target, station, endpoint), // ToDS EAPOL
            (0x08, 2, station, target, endpoint), // FromDS EAPOL
            (0x80, 0, [255; 6], target, other),   // wrong BSSID, matching transmitter
            (0x08, 1, other, target, endpoint),   // wrong BSSID, matching station
            (0x08, 2, target, other, endpoint),   // wrong BSSID, matching station
            (0x08, 3, target, station, endpoint), // WDS receiver selected
            (0x08, 3, station, target, endpoint), // WDS transmitter selected
            (0x08, 3, other, station, target),    // matching WDS DA is insufficient
        ];
        for (index, (kind, ds, addr1, addr2, addr3)) in cases.iter().enumerate() {
            let mut packet = vec![*kind, *ds, 0, 0];
            packet.extend(addr1);
            packet.extend(addr2);
            packet.extend(addr3);
            packet.extend([0, 0]);
            if *ds == 3 {
                packet.extend(station);
            }
            if *kind == 0x08 {
                // LLC SNAP + EAPOL v2 start frame.
                packet.extend([0xaa, 0xaa, 3, 0, 0, 0, 0x88, 0x8e, 2, 1, 0, 0]);
            } else {
                packet.extend([0u8; 12]); // beacon fixed parameters
            }
            pcap.extend(((index + 1) as u32).to_le_bytes());
            pcap.extend(0u32.to_le_bytes());
            pcap.extend((packet.len() as u32).to_le_bytes());
            pcap.extend((packet.len() as u32).to_le_bytes());
            pcap.extend(packet);
        }
        std::fs::write(&fixture, pcap).unwrap();
        // Strictly offline: never uses -i, -I, a device, or elevated privileges.
        let output = Command::new(tcpdump_path().unwrap())
            .args(["-n", "-r"])
            .arg(&fixture)
            .args(["-w", "-"])
            .arg(monitor_filter("02:01:02:03:04:05"))
            .stdin(Stdio::null())
            .stderr(Stdio::inherit())
            .output()
            .unwrap();
        assert!(output.status.success(), "{}", output.status);
        assert!(output.stdout.len() >= 24);
        let mut remaining = &output.stdout[24..];
        let mut timestamps = Vec::new();
        while !remaining.is_empty() {
            assert!(remaining.len() >= 16);
            timestamps.push(u32::from_le_bytes(remaining[..4].try_into().unwrap()));
            let length = u32::from_le_bytes(remaining[8..12].try_into().unwrap()) as usize;
            assert!(remaining.len() >= 16 + length);
            remaining = &remaining[16 + length..];
        }
        assert_eq!(timestamps, [1, 2, 3, 7, 8]);
    }
    #[test]
    fn survey_filter_is_broad_only_when_explicitly_requested() {
        let mut opts = options("unused".into());
        opts.bssid = None;
        let args = survey_args(&opts).unwrap();
        assert_eq!(args[5], "4096");
        assert_eq!(args.last().unwrap(), "type mgt or type data");
        assert!(!args.contains(&OsString::from("-I")));
        assert!(capture_args(&opts).is_err()); // live/shadow still require an exact BSSID
        opts.monitor = true;
        opts.bssid = Some([2, 1, 2, 3, 4, 5]);
        let args = survey_args(&opts).unwrap();
        assert!(args.contains(&OsString::from("-I")));
        assert!(args
            .last()
            .unwrap()
            .to_string_lossy()
            .contains("wlan addr3 02:01:02:03:04:05"));
    }
    #[cfg(unix)]
    #[test]
    fn survey_callback_failure_stops_and_reaps_capture() {
        let dir = TestDir::new();
        let done = dir.0.join("stopped");
        let program = fake(
            &dir,
            &format!(
                "trap 'touch \"{}\"; exit 0' INT\n{HEADER}\nwhile :; do :; done",
                done.display()
            ),
        );
        let opts = options(dir.0.join("survey"));
        let start = Instant::now();
        let result = run_capture(
            &opts,
            survey_args(&opts).unwrap(),
            || {
                if start.elapsed() > Duration::from_millis(150)
                    && opts.output.metadata().is_ok_and(|m| m.len() >= 24)
                {
                    Err(std::io::Error::other("UI failed"))
                } else {
                    Ok(false)
                }
            },
            &program,
            None,
        );
        assert!(matches!(result, Err(PlatformError::Io(_))));
        assert!(
            done.exists(),
            "result={result:?}; files={:?}",
            std::fs::read_dir(&dir.0)
                .unwrap()
                .map(|e| e.unwrap().file_name())
                .collect::<Vec<_>>()
        );
        assert!(start.elapsed() < Duration::from_secs(8));
    }
    #[cfg(unix)]
    #[test]
    fn capture_shutdown_survives_an_inherited_blocked_signal_mask() {
        struct Restore(libc::sigset_t);
        impl Drop for Restore {
            fn drop(&mut self) {
                unsafe {
                    libc::pthread_sigmask(libc::SIG_SETMASK, &self.0, std::ptr::null_mut());
                }
            }
        }
        let dir = TestDir::new();
        let program = fake(
            &dir,
            &format!("trap 'exit 0' INT\n{HEADER}\nwhile :; do :; done"),
        );
        let opts = options(dir.0.join("blocked-mask"));
        let started = Instant::now();
        let _restore = unsafe {
            let mut blocked = std::mem::zeroed();
            let mut original = std::mem::zeroed();
            libc::sigemptyset(&mut blocked);
            libc::sigaddset(&mut blocked, libc::SIGINT);
            assert_eq!(
                libc::pthread_sigmask(libc::SIG_BLOCK, &blocked, &mut original),
                0
            );
            Restore(original)
        };
        capture_with_program(
            &opts,
            || {
                started.elapsed() > Duration::from_millis(100)
                    && opts.output.metadata().is_ok_and(|m| m.len() >= 24)
            },
            &program,
        )
        .unwrap();
        assert!(started.elapsed() < Duration::from_secs(8));
    }
}
