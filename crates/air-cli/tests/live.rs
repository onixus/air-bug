//! No live network is opened by these tests: only parser validation and rejected
//! options/paths are exercised. Backend lifecycle tests use private fake tools.
use std::path::PathBuf;
use std::process::{Command, Output};
use std::sync::atomic::{AtomicUsize, Ordering};

fn cli(args: &[&str]) -> Output {
    Command::new(env!("CARGO_BIN_EXE_aircrack"))
        .args(args)
        .output()
        .unwrap()
}
struct TempDir(PathBuf);
impl TempDir {
    fn new() -> Self {
        static NEXT: AtomicUsize = AtomicUsize::new(0);
        let path = std::env::temp_dir().join(format!(
            "air-live-cli-{}-{}",
            std::process::id(),
            NEXT.fetch_add(1, Ordering::Relaxed)
        ));
        std::fs::create_dir(&path).unwrap();
        Self(path)
    }
}
impl Drop for TempDir {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}
#[test]
fn capture_help_and_required_scope() {
    for command in ["live", "airodump"] {
        let p = cli(&[command, "--help"]);
        assert!(p.status.success());
        let text = String::from_utf8_lossy(&p.stdout);
        for token in ["--bssid", "--duration", "--max-packets", "--monitor"] {
            assert!(text.contains(token));
        }
        let p = cli(&[command, "--iface", "en0"]);
        assert_eq!(p.status.code(), Some(2));
    }
    for command in ["start", "status", "stop"] {
        assert!(cli(&["shadow", command, "--help"]).status.success());
    }
}
#[test]
fn cli_rejects_unbounded_or_wildcard_capture_before_io() {
    for extra in [
        vec!["--duration", "0"],
        vec!["--duration", "86401"],
        vec!["--max-packets", "0"],
        vec!["--bssid", "MGTS*"],
    ] {
        let mut args = vec![
            "live",
            "--iface",
            "en0",
            "--output",
            "must-not-create.pcap",
            "--bssid",
            "02:00:00:00:00:01",
        ];
        args.extend(extra);
        assert_eq!(cli(&args).status.code(), Some(2));
    }
}
#[test]
fn validation_rejects_before_creating_output() {
    let dir = TempDir::new();
    let output = dir.0.join("capture.pcap");
    for (iface, mac) in [
        ("-bad", "02:00:00:00:00:01"),
        ("bad iface", "02:00:00:00:00:01"),
        ("en0", "ff:ff:ff:ff:ff:ff"),
        ("en0", "00:00:00:00:00:00"),
    ] {
        let p = cli(&[
            "live",
            "--iface",
            iface,
            "--output",
            output.to_str().unwrap(),
            "--bssid",
            mac,
        ]);
        assert!(!p.status.success());
        assert!(!output.exists());
    }
}
#[test]
fn refuses_existing_capture_and_session() {
    let dir = TempDir::new();
    let output = dir.0.join("existing.pcap");
    std::fs::write(&output, b"sentinel").unwrap();
    let p = cli(&[
        "live",
        "--iface",
        "en0",
        "--output",
        output.to_str().unwrap(),
        "--bssid",
        "02:00:00:00:00:01",
    ]);
    assert!(!p.status.success());
    assert_eq!(std::fs::read(&output).unwrap(), b"sentinel");
    let p = cli(&[
        "shadow",
        "start",
        "--session",
        dir.0.to_str().unwrap(),
        "--iface",
        "en0",
        "--output",
        dir.0.join("new.pcap").to_str().unwrap(),
        "--bssid",
        "02:00:00:00:00:01",
    ]);
    assert!(!p.status.success());
    assert!(!dir.0.join("new.pcap").exists());
}
#[test]
fn missing_session_is_not_running() {
    let dir = TempDir::new();
    for action in ["status", "stop"] {
        let p = cli(&[
            "shadow",
            action,
            "--session",
            dir.0.join("missing").to_str().unwrap(),
        ]);
        assert_eq!(p.status.code(), Some(1));
    }
}
