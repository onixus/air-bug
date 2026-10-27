//! Passive tuning only: no active scans, interface creation or association.
use std::io::{self, Read};
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::time::{Duration, Instant};

fn invalid(message: impl Into<String>) -> io::Error {
    io::Error::other(message.into())
}

/// Channel numbers deliberately cover 2.4/5 GHz only (6 GHz numbers overlap).
pub fn frequency(channel: u16) -> Option<u16> {
    match channel {
        1..=13 => Some(2407 + channel * 5),
        14 => Some(2484),
        32..=177 => Some(5000 + channel * 5),
        _ => None,
    }
}

fn run(program: &Path, args: &[&str]) -> io::Result<String> {
    run_timed(program, args, Duration::from_secs(3))
}

pub(super) fn run_timed(program: &Path, args: &[&str], timeout: Duration) -> io::Result<String> {
    run_timed_until(program, args, timeout, || false)
}

pub(super) fn run_timed_until(
    program: &Path,
    args: &[&str],
    timeout: Duration,
    cancelled: impl Fn() -> bool,
) -> io::Result<String> {
    if cancelled() {
        return Err(io::Error::new(io::ErrorKind::Interrupted, "scan cancelled"));
    }
    let child = Command::new(program)
        .args(args)
        .env("LC_ALL", "C")
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()?;
    let mut child = super::ChildGuard(Some(child));
    let process = child.0.as_mut().unwrap();
    let stdout = process.stdout.take().unwrap();
    let stderr = process.stderr.take().unwrap();
    // Drain concurrently: iw phy output can exceed pipe capacity. Keep at most 1 MiB.
    fn drain(mut input: impl Read) -> io::Result<Vec<u8>> {
        let mut kept = Vec::new();
        let mut buf = [0; 4096];
        loop {
            let n = input.read(&mut buf)?;
            if n == 0 {
                return Ok(kept);
            }
            let remaining = (1024 * 1024usize).saturating_sub(kept.len());
            kept.extend_from_slice(&buf[..n.min(remaining)]);
        }
    }
    let out = std::thread::spawn(move || drain(stdout));
    let err = std::thread::spawn(move || drain(stderr));
    let deadline = Instant::now() + timeout;
    let result = loop {
        if let Some(status) = child.0.as_mut().unwrap().try_wait()? {
            child.0.take();
            break Ok(status);
        }
        if cancelled() || Instant::now() >= deadline {
            child.0.as_mut().unwrap().kill()?;
            child.0.as_mut().unwrap().wait()?;
            child.0.take();
            break Err(if cancelled() {
                io::Error::new(io::ErrorKind::Interrupted, "scan cancelled")
            } else {
                invalid("Wi-Fi helper timed out")
            });
        }
        std::thread::sleep(Duration::from_millis(10));
    };
    let out = out
        .join()
        .map_err(|_| invalid("channel stdout reader failed"))??;
    let err = err
        .join()
        .map_err(|_| invalid("channel stderr reader failed"))??;
    let status = result?;
    if !status.success() {
        return Err(invalid(format!(
            "Wi-Fi helper failed ({status}): {}",
            String::from_utf8_lossy(&err).trim()
        )));
    }
    String::from_utf8(out).map_err(|_| invalid("invalid channel command output"))
}

#[derive(Debug)]
pub struct Channels {
    iface: String,
    program: PathBuf,
    mac: bool,
    pub available: Vec<u16>,
    pub current: Option<u16>,
    pub available_frequencies: Vec<u16>,
    pub current_frequency: Option<u16>,
    original_frequency: Option<u16>,
    pub mode: Option<u32>,
    pub powered: Option<bool>,
    original: Option<u16>,
    changed: bool,
}

impl Channels {
    pub fn open(iface: &str) -> io::Result<Self> {
        if iface.is_empty()
            || iface.starts_with('-')
            || !iface
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || b"_.:-".contains(&b))
        {
            return Err(invalid("unsafe interface name"));
        }
        if cfg!(target_os = "linux") {
            let program = ["/usr/sbin/iw", "/sbin/iw", "/usr/bin/iw"]
                .iter()
                .map(PathBuf::from)
                .find(|p| p.is_file())
                .ok_or_else(|| {
                    invalid("iw is required for survey; install iw and prepare a monitor interface")
                })?;
            let info = run(&program, &["dev", iface, "info"])?;
            if !info.lines().any(|l| l.trim() == "type monitor") {
                return Err(invalid("survey requires an existing Linux monitor interface; interface mode was not changed"));
            }
            let phy = info
                .lines()
                .find_map(|l| l.trim().strip_prefix("wiphy "))
                .and_then(|p| p.parse::<u32>().ok())
                .ok_or_else(|| invalid("iw did not report a wiphy"))?;
            let phy_info = run(&program, &["phy", &format!("phy{phy}"), "info"])?;
            let available = parse_iw_channels(&phy_info);
            let available_frequencies = parse_iw_frequencies(&phy_info);
            let current_frequency = parse_iw_current_frequency(&info);
            let current = info
                .lines()
                .find_map(|l| l.trim().strip_prefix("channel "))
                .and_then(|l| l.split_whitespace().next())
                .and_then(|c| c.parse().ok())
                .filter(|c| current_frequency.is_some_and(|f| frequency(*c) == Some(f)));
            Ok(Self {
                iface: iface.into(),
                program,
                mac: false,
                available,
                current,
                original: current,
                available_frequencies,
                current_frequency,
                original_frequency: current_frequency,
                mode: None,
                powered: None,
                changed: false,
            })
        } else if cfg!(target_os = "macos") {
            let program = std::env::current_exe()?.with_file_name("air-channel-macos");
            if !program.is_file() {
                return Err(invalid("build the CoreWLAN helper beside aircrack: see tools/air-channel-macos.swift and README survey setup"));
            }
            let info = run(&program, &[iface, "info"])?;
            let state = MacState::parse(&info);
            let available = state.available;
            let current = state.current;
            Ok(Self {
                iface: iface.into(),
                program,
                mac: true,
                available,
                current,
                original: current,
                available_frequencies: Vec::new(),
                current_frequency: current.and_then(frequency),
                original_frequency: current.and_then(frequency),
                mode: state.mode,
                powered: state.powered,
                changed: false,
            })
        } else {
            Err(invalid("live survey is supported on Linux and macOS only"))
        }
    }

    /// Refuse monitor capture on an associated Mac interface before opening BPF.
    /// A monitor request can leave it associated but supply no frames, or disconnect it.
    pub fn validate_survey(&self) -> io::Result<()> {
        if self.mac {
            if self.powered != Some(true) {
                return Err(invalid(
                    "Wi-Fi power is off or unknown; no interface changes made",
                ));
            }
            match self.mode {
                Some(0) => {},
                Some(1) => return Err(invalid("Wi-Fi interface is associated (station mode); refusing monitor capture on the connected adapter. Use a dedicated/unassociated adapter. No disconnection or channel changes were made.")),
                _ => return Err(invalid("Wi-Fi interface is not confirmed unassociated; refusing monitor capture. Rebuild the CoreWLAN helper if state is unknown.")),
            }
        }
        Ok(())
    }

    pub fn validate(&self, channels: &[u16]) -> io::Result<()> {
        for c in channels {
            if !self.available.contains(c) || frequency(*c).is_none() {
                return Err(invalid(format!(
                    "channel {c} is not available for passive 2.4/5 GHz tuning on this adapter"
                )));
            }
        }
        Ok(())
    }

    pub fn set(&mut self, channel: u16) -> io::Result<()> {
        self.validate(&[channel])?;
        // Mark before execution: a command can change the radio then fail/timeout.
        self.changed = true;
        if self.mac {
            let result = run(&self.program, &[&self.iface, "set", &channel.to_string()])?;
            if MacState::parse(&result).current != Some(channel) {
                self.current = None;
                return Err(invalid("channel command did not confirm the requested channel; rebuild the CoreWLAN helper"));
            }
        } else {
            run(
                &self.program,
                &[
                    "dev",
                    &self.iface,
                    "set",
                    "freq",
                    &frequency(channel).unwrap().to_string(),
                ],
            )?;
        }
        self.current = Some(channel);
        self.current_frequency = frequency(channel);
        Ok(())
    }

    /// Linux only: use the exact frequency reported by iw, avoiding channel overlap.
    pub fn validate_frequencies(&self, frequencies: &[u16]) -> io::Result<()> {
        if self.mac && !frequencies.is_empty() {
            return Err(invalid(
                "frequency tuning is not supported by the macOS helper",
            ));
        }
        for freq in frequencies {
            if !self.available_frequencies.contains(freq) {
                return Err(invalid(format!(
                    "frequency {freq} MHz is not available for passive tuning on this adapter"
                )));
            }
        }
        Ok(())
    }
    pub fn set_frequency(&mut self, freq: u16) -> io::Result<()> {
        self.validate_frequencies(&[freq])?;
        self.changed = true;
        run(
            &self.program,
            &["dev", &self.iface, "set", "freq", &freq.to_string()],
        )?;
        self.current_frequency = Some(freq);
        self.current = self
            .available
            .iter()
            .copied()
            .find(|c| frequency(*c) == Some(freq));
        Ok(())
    }
    pub fn restore(&mut self) -> io::Result<()> {
        if self.changed {
            // A rejected tuning call may not have changed anything. Read the actual
            // state first; do not issue a spurious restore on an associated adapter.
            if self.mac {
                let state = MacState::parse(&run(&self.program, &[&self.iface, "info"])?);
                self.current = state.current;
                self.mode = state.mode;
                self.powered = state.powered;
                if self.original.is_some() && self.current == self.original {
                    self.changed = false;
                    return Ok(());
                }
            }
            if let Some(freq) = self.original_frequency.filter(|_| !self.mac) {
                run(
                    &self.program,
                    &["dev", &self.iface, "set", "freq", &freq.to_string()],
                )?;
                self.current_frequency = Some(freq);
            } else if let Some(original) = self.original {
                self.set(original)?;
            }
            self.changed = false;
        }
        Ok(())
    }
}
impl Drop for Channels {
    fn drop(&mut self) {
        if let Err(error) = self.restore() {
            eprintln!("Could not restore original channel: {error}");
        }
    }
}

#[derive(Default)]
struct MacState {
    available: Vec<u16>,
    current: Option<u16>,
    mode: Option<u32>,
    powered: Option<bool>,
}
impl MacState {
    fn parse(text: &str) -> Self {
        let mut state = Self::default();
        for line in text.lines() {
            let Some((key, value)) = line.split_once(' ') else {
                continue;
            };
            match key {
                "channel" => {
                    if let Ok(channel) = value.parse() {
                        state.available.push(channel);
                    }
                }
                "current" => state.current = value.parse().ok(),
                "mode" => state.mode = value.parse().ok(),
                "power" => {
                    state.powered = match value {
                        "on" => Some(true),
                        "off" => Some(false),
                        _ => None,
                    }
                }
                _ => {}
            }
        }
        state.available.sort_unstable();
        state.available.dedup();
        state
    }
}

fn parse_iw_current_frequency(text: &str) -> Option<u16> {
    text.lines().find_map(|line| {
        let line = line.trim().strip_prefix("channel ")?;
        let (_, rest) = line.split_once('(')?;
        rest.split_whitespace().next()?.parse().ok()
    })
}
fn parse_iw_frequencies(text: &str) -> Vec<u16> {
    let mut values = Vec::new();
    for line in text.lines().filter(|l| !l.contains("disabled")) {
        if let Some((left, _)) = line.split_once(" MHz [") {
            if let Some(freq) = left
                .split_whitespace()
                .last()
                .and_then(|v| v.parse::<u16>().ok())
            {
                if matches!(freq,2412..=2484 | 5160..=5885 | 5935 | 5955..=7115) {
                    values.push(freq);
                }
            }
        }
    }
    values.sort_unstable();
    values.dedup();
    values
}
fn parse_iw_channels(text: &str) -> Vec<u16> {
    let mut channels = Vec::new();
    for line in text.lines().filter(|l| !l.contains("disabled")) {
        let Some((left, rest)) = line.split_once(" MHz [") else {
            continue;
        };
        let Some(freq) = left
            .split_whitespace()
            .last()
            .and_then(|s| s.parse::<u16>().ok())
        else {
            continue;
        };
        let Some(channel) = rest.split(']').next().and_then(|s| s.parse::<u16>().ok()) else {
            continue;
        };
        if frequency(channel) == Some(freq) {
            channels.push(channel);
        }
    }
    channels.sort_unstable();
    channels.dedup();
    channels
}

#[cfg(test)]
mod tests {
    #[test]
    fn cancellation_interrupts_helper_wait() {
        let start = std::time::Instant::now();
        let error = super::run_timed_until(
            std::path::Path::new("/bin/sleep"),
            &["10"],
            std::time::Duration::from_secs(15),
            || start.elapsed() >= std::time::Duration::from_millis(100),
        )
        .unwrap_err();
        assert_eq!(error.kind(), std::io::ErrorKind::Interrupted);
        assert!(start.elapsed() < std::time::Duration::from_secs(3));
    }

    use super::*;
    #[test]
    fn regulatory_channels_exclude_disabled_and_overlapping_six_ghz() {
        let text = "* 2412 MHz [1] (20.0 dBm)\n* 2437 MHz [6] (disabled)\n* 5180 MHz [36] (no IR)\n* 5955 MHz [1] (20.0 dBm)";
        assert_eq!(parse_iw_channels(text), [1, 36]);
        assert_eq!(frequency(14), Some(2484));
        assert_eq!(frequency(0), None);
    }
    #[test]
    fn linux_frequencies_do_not_conflate_6ghz_and_legacy_channels() {
        let text="* 2412 MHz [1] (20.0 dBm)\n* 5955 MHz [1] (no IR)\n* 5975 MHz [5] (disabled)\n* 5935 MHz [2] (20.0 dBm)";
        assert_eq!(parse_iw_frequencies(text), [2412, 5935, 5955]);
        assert_eq!(parse_iw_channels(text), [1]);
        assert_eq!(
            parse_iw_current_frequency("\tchannel 1 (5955 MHz), width: 20 MHz"),
            Some(5955)
        );
    }
    #[cfg(unix)]
    #[test]
    fn frequency_tuning_checks_driver_list_and_restores_original() {
        use std::os::unix::fs::PermissionsExt;
        let dir = super::super::tests::TestDir::new();
        let log = dir.0.join("calls");
        let program = dir.0.join("fake-iw");
        std::fs::write(
            &program,
            format!("#!/bin/sh\nprintf '%s\\n' \"$*\" >> '{}'\n", log.display()),
        )
        .unwrap();
        std::fs::set_permissions(&program, std::fs::Permissions::from_mode(0o700)).unwrap();
        let mut radio = Channels {
            iface: "mon0".into(),
            program,
            mac: false,
            available: vec![1],
            current: Some(1),
            available_frequencies: vec![2412, 5955],
            current_frequency: Some(2412),
            original_frequency: Some(2412),
            mode: None,
            powered: None,
            original: Some(1),
            changed: false,
        };
        assert!(radio.set_frequency(5975).is_err());
        assert!(!log.exists());
        radio.set_frequency(5955).unwrap();
        assert_eq!(radio.current, None);
        radio.restore().unwrap();
        assert_eq!(
            std::fs::read_to_string(log).unwrap(),
            "dev mon0 set freq 5955\ndev mon0 set freq 2412\n"
        );
    }
    #[cfg(unix)]
    #[test]
    fn tuning_uses_passive_frequency_commands_and_restores_original() {
        use std::os::unix::fs::PermissionsExt;
        let dir = super::super::tests::TestDir::new();
        let log = dir.0.join("calls");
        let program = dir.0.join("fake-iw");
        std::fs::write(
            &program,
            format!("#!/bin/sh\nprintf '%s\\n' \"$*\" >> '{}'\n", log.display()),
        )
        .unwrap();
        std::fs::set_permissions(&program, std::fs::Permissions::from_mode(0o700)).unwrap();
        let mut radio = Channels {
            iface: "mon0".into(),
            program,
            mac: false,
            available: vec![1, 6, 36],
            current: Some(1),
            mode: None,
            powered: None,
            original: Some(1),
            available_frequencies: vec![2412, 2437, 5180, 5955],
            current_frequency: Some(2412),
            original_frequency: Some(2412),
            changed: false,
        };
        assert!(radio.set(149).is_err());
        assert!(!log.exists());
        radio.set(6).unwrap();
        radio.set(36).unwrap();
        radio.restore().unwrap();
        drop(radio);
        assert_eq!(
            std::fs::read_to_string(log).unwrap(),
            "dev mon0 set freq 2437\ndev mon0 set freq 5180\ndev mon0 set freq 2412\n"
        );
    }
    fn mac_radio(mode: Option<u32>, powered: Option<bool>) -> Channels {
        Channels {
            iface: "en0".into(),
            program: "/nonexistent-helper".into(),
            mac: true,
            available: vec![1, 6, 44],
            current: Some(44),
            mode,
            powered,
            original: Some(44),
            available_frequencies: vec![],
            current_frequency: Some(5220),
            original_frequency: Some(5220),
            changed: false,
        }
    }
    #[test]
    fn mac_preflight_refuses_associated_off_and_unknown_states_without_io() {
        assert!(mac_radio(Some(0), Some(true)).validate_survey().is_ok());
        for (mode, power) in [
            (Some(1), Some(true)),
            (Some(2), Some(true)),
            (None, Some(true)),
            (Some(0), Some(false)),
            (Some(0), None),
        ] {
            assert!(mac_radio(mode, power).validate_survey().is_err());
        }
        let message = mac_radio(Some(1), Some(true))
            .validate_survey()
            .unwrap_err()
            .to_string();
        assert!(message.contains("No disconnection or channel changes"));
    }
    #[test]
    fn mac_state_parser_keeps_unknown_state_unknown() {
        let state = MacState::parse(
            "power on\nmode 1\nwidth 3\ncurrent 44\nchannel 6\nchannel 1\nchannel 6\n",
        );
        assert_eq!(state.current, Some(44));
        assert_eq!(state.mode, Some(1));
        assert_eq!(state.powered, Some(true));
        assert_eq!(state.available, [1, 6]);
        let unknown = MacState::parse("power redacted\nmode redacted\ncurrent unavailable");
        assert_eq!(unknown.powered, None);
        assert_eq!(unknown.mode, None);
        assert_eq!(unknown.current, None);
    }
    #[cfg(unix)]
    #[test]
    fn mac_failed_set_does_not_issue_spurious_restore_when_channel_unchanged() {
        use std::os::unix::fs::PermissionsExt;
        let dir = super::super::tests::TestDir::new();
        let log = dir.0.join("calls");
        let program = dir.0.join("fake-corewlan");
        std::fs::write(&program, format!("#!/bin/sh\nprintf '%s\\n' \"$*\" >> '{}'\nif [ \"$2\" = info ]; then printf 'power on\\nmode 1\\ncurrent 44\\n'; else exit 1; fi\n", log.display())).unwrap();
        std::fs::set_permissions(&program, std::fs::Permissions::from_mode(0o700)).unwrap();
        let mut radio = mac_radio(Some(0), Some(true));
        radio.program = program;
        assert!(radio.set(6).is_err());
        radio.restore().unwrap();
        drop(radio);
        assert_eq!(
            std::fs::read_to_string(log).unwrap(),
            "en0 set 6\nen0 info\n"
        );
    }
    #[cfg(unix)]
    #[test]
    fn mac_set_requires_readback_confirmation() {
        use std::os::unix::fs::PermissionsExt;
        let dir = super::super::tests::TestDir::new();
        let program = dir.0.join("fake-corewlan");
        std::fs::write(&program, "#!/bin/sh\nprintf 'current 44\\n'\n").unwrap();
        std::fs::set_permissions(&program, std::fs::Permissions::from_mode(0o700)).unwrap();
        let mut radio = mac_radio(Some(0), Some(true));
        radio.program = program;
        assert!(radio
            .set(6)
            .unwrap_err()
            .to_string()
            .contains("did not confirm"));
        assert_eq!(radio.current, None);
        radio.restore().unwrap();
    }
}
