use std::path::PathBuf;
use std::process::Command;
fn cli(args: &[&str]) -> std::process::Output {
    Command::new(env!("CARGO_BIN_EXE_aircrack"))
        .args(args)
        .output()
        .unwrap()
}
fn fixture(name: &str) -> String {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../../tests/fixtures")
        .join(name)
        .to_string_lossy()
        .into()
}
#[test]
fn survey_offline_lists_fixture_without_radio() {
    let result = cli(&["survey", "--read", &fixture("wpa2-radiotap.pcap")]);
    assert!(
        result.status.success(),
        "{}",
        String::from_utf8_lossy(&result.stderr)
    );
    let output = String::from_utf8(result.stdout).unwrap();
    for text in [
        "BSSID\tSSID\tCH",
        "Client\tLast-BSSID",
        "Offline passive inventory",
    ] {
        assert!(output.contains(text));
    }
    assert!(!output.contains("found:"));
}
#[test]
fn survey_rejects_ethernet_and_invalid_options() {
    assert!(!cli(&["survey", "--read", &fixture("wpa2-ethernet.pcap")])
        .status
        .success());
    for args in [
        vec!["survey"],
        vec!["survey", "--iface", "mon0"],
        vec![
            "survey",
            "--iface",
            "mon0",
            "--output",
            "unused",
            "--channel",
            "1",
            "--channels",
            "1,6",
        ],
        vec![
            "survey",
            "--iface",
            "mon0",
            "--output",
            "unused",
            "--dwell-ms",
            "0",
        ],
        vec!["survey", "--read", "unused", "--channels", "1,6"],
    ] {
        assert!(!cli(&args).status.success());
    }
}
#[test]
fn survey_help_explains_scope() {
    let result = cli(&["survey", "--help"]);
    assert!(result.status.success());
    let help = String::from_utf8(result.stdout).unwrap();
    for flag in [
        "--channel",
        "--channels",
        "--list-channels",
        "--bssid",
        "--plain",
        "--read",
    ] {
        assert!(help.contains(flag));
    }
}

struct TempDir(PathBuf);
impl TempDir {
    fn new() -> Self {
        use std::sync::atomic::{AtomicUsize, Ordering};
        static NEXT: AtomicUsize = AtomicUsize::new(0);
        let path = std::env::temp_dir().join(format!(
            "survey-export-{}-{}",
            std::process::id(),
            NEXT.fetch_add(1, Ordering::Relaxed)
        ));
        std::fs::create_dir(&path).unwrap();
        Self(path)
    }
    fn path(&self, name: &str) -> String {
        self.0.join(name).to_str().unwrap().to_owned()
    }
}
impl Drop for TempDir {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

#[test]
fn survey_exports_final_snapshot_with_handshake_and_pmkid_flags() {
    for (name, field) in [
        ("wpa2-radiotap.pcap", "handshake_m1m2"),
        ("wpa2-m2m3-radiotap.pcap", "handshake_m2m3"),
        ("wpa2-pmkid-assoc-radiotap.pcap", "pmkid"),
    ] {
        let temp = TempDir::new();
        let json = temp.path("snapshot.json");
        let csv = temp.path("snapshot.csv");
        let result = cli(&[
            "survey",
            "--read",
            &fixture(name),
            "--export-json",
            &json,
            "--export-csv",
            &csv,
        ]);
        assert!(
            result.status.success(),
            "{}",
            String::from_utf8_lossy(&result.stderr)
        );
        let data: serde_json::Value =
            serde_json::from_slice(&std::fs::read(&json).unwrap()).unwrap();
        assert_eq!(data["schema_version"], 1);
        assert_eq!(data["access_points"][0][field], true);
        assert_eq!(data["access_points"][0]["bssid"], "02:00:00:00:00:01");
        let csv = std::fs::read_to_string(&csv).unwrap();
        assert!(csv.starts_with("kind,mac,last_bssid,ssid,ssid_hex"));
        assert!(csv.contains("handshake_m1m2,handshake_m2m3,pmkid"));
        assert!(csv.contains("ap,\"02:00:00:00:00:01\""));
        assert!(
            String::from_utf8_lossy(&result.stdout).contains(if field == "pmkid" {
                "PMKID"
            } else {
                "HS"
            })
        );
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            assert_eq!(
                std::fs::metadata(&json).unwrap().permissions().mode() & 0o777,
                0o600
            );
        }
    }
}
#[test]
fn export_refuses_overwrite_and_cleans_reserved_files_after_failure() {
    let temp = TempDir::new();
    let json = temp.path("result.json");
    let csv = temp.path("existing.csv");
    std::fs::write(&csv, b"keep").unwrap();
    let result = cli(&[
        "survey",
        "--read",
        &fixture("wpa2-raw.pcap"),
        "--export-json",
        &json,
        "--export-csv",
        &csv,
    ]);
    assert!(!result.status.success());
    assert_eq!(std::fs::read(&csv).unwrap(), b"keep");
    assert!(!std::path::Path::new(&json).exists());
    let result = cli(&[
        "survey",
        "--read",
        &fixture("wpa2-ethernet.pcap"),
        "--export-json",
        &json,
    ]);
    assert!(!result.status.success());
    assert!(!std::path::Path::new(&json).exists());
    let result = cli(&[
        "survey",
        "--read",
        &fixture("wpa2-raw.pcap"),
        "--export-json",
        &json,
        "--export-csv",
        &json,
    ]);
    assert!(!result.status.success());
    assert!(!std::path::Path::new(&json).exists());
}
#[test]
fn filtered_exports_have_no_evidence_from_other_networks() {
    let temp = TempDir::new();
    let json = temp.path("snapshot.json");
    let result = cli(&[
        "survey",
        "--read",
        &fixture("wpa2-raw.pcap"),
        "--bssid",
        "02:11:22:33:44:55",
        "--export-json",
        &json,
    ]);
    assert!(result.status.success());
    let data: serde_json::Value = serde_json::from_slice(&std::fs::read(&json).unwrap()).unwrap();
    assert_eq!(data["access_points"].as_array().unwrap().len(), 0);
    assert_eq!(data["clients"].as_array().unwrap().len(), 0);
}

#[test]
fn ft_indicator_and_exports_use_completed_reassembled_management_frames() {
    let temp = TempDir::new();
    let json = temp.path("ft.json");
    let csv = temp.path("ft.csv");
    let result = cli(&[
        "survey",
        "--read",
        &fixture("ft-psk-fragmented.pcap"),
        "--export-json",
        &json,
        "--export-csv",
        &csv,
    ]);
    assert!(
        result.status.success(),
        "{}",
        String::from_utf8_lossy(&result.stderr)
    );
    let snapshot: serde_json::Value =
        serde_json::from_slice(&std::fs::read(&json).unwrap()).unwrap();
    assert_eq!(snapshot["access_points"][0]["ft"], true);
    assert!(String::from_utf8_lossy(&result.stdout).contains("FT=1"));
    assert!(std::fs::read_to_string(&csv)
        .unwrap()
        .lines()
        .next()
        .unwrap()
        .contains(",ft,handshake_m3m4,audit_status"));
}

#[test]
fn survey_audits_configuration_and_capture_quality_in_exports() {
    let temp = TempDir::new();
    let capture = temp.path("audit.pcap");
    let json = temp.path("audit.json");
    let csv = temp.path("audit.csv");
    let mut file = vec![0xd4, 0xc3, 0xb2, 0xa1, 2, 0, 4, 0];
    file.extend([0; 8]);
    file.extend(65535u32.to_le_bytes());
    file.extend(105u32.to_le_bytes());
    let mut beacon = vec![0x80, 0, 0, 0];
    beacon.extend([255; 6]);
    beacon.extend([2, 1, 2, 3, 4, 5]);
    beacon.extend([2, 1, 2, 3, 4, 5]);
    beacon.extend([0; 2]);
    beacon.extend([0; 12]);
    beacon[34] = 0x10;
    beacon.extend([
        0, 4, b't', b'e', b's', b't', 48, 24, 1, 0, 0, 15, 172, 4, 1, 0, 0, 15, 172, 4, 2, 0, 0,
        15, 172, 2, 0, 15, 172, 8, 0x80, 0,
    ]);
    beacon.extend([201, 12, 0, 8, 131, 5, 1, 2, 9, 8, 7, 6, 5, 2]);
    file[16..20].copy_from_slice(&(beacon.len() as u32).to_le_bytes());
    let mut push = |seconds: u32, bytes: &[u8], original: u32| {
        file.extend(seconds.to_le_bytes());
        file.extend(0u32.to_le_bytes());
        file.extend((bytes.len() as u32).to_le_bytes());
        file.extend(original.to_le_bytes());
        file.extend(bytes);
    };
    push(5, &beacon, beacon.len() as u32);
    push(4, &beacon, beacon.len() as u32 + 4);
    std::fs::write(&capture, file).unwrap();
    let result = cli(&[
        "survey",
        "--read",
        &capture,
        "--export-json",
        &json,
        "--export-csv",
        &csv,
    ]);
    assert!(
        result.status.success(),
        "{}",
        String::from_utf8_lossy(&result.stderr)
    );
    let v: serde_json::Value = serde_json::from_slice(&std::fs::read(json).unwrap()).unwrap();
    let ap = &v["access_points"][0];
    assert_eq!(ap["security_audit"]["last_status"], "valid");
    assert_eq!(
        ap["security_audit"]["last_valid"]["advertised"]["rsn"]["pmf"],
        "optional"
    );
    assert!(
        ap["security_audit"]["last_valid"]["advertised"]["observations"]
            .as_array()
            .unwrap()
            .iter()
            .any(|x| x == "sae_psk_transition_advertised")
    );
    assert_eq!(v["access_points"].as_array().unwrap().len(), 1);
    assert_eq!(ap["last_direct_observation"]["kind"], "beacon");
    assert_eq!(
        ap["last_direct_observation"]["capture_timestamp_seconds"],
        5.0
    );
    let neighbor = &v["rnr_neighbors"][0];
    assert_eq!(neighbor["neighbor_bssid"], "02:09:08:07:06:05");
    assert_eq!(neighbor["reporter_bssid"], "02:01:02:03:04:05");
    assert_eq!(neighbor["radio"]["frequency_mhz"], 5975);
    assert_eq!(neighbor["directly_observed"], false);
    assert_eq!(v["capture_quality"]["truncated_records"], 1);
    assert_eq!(v["capture_quality"]["timestamp_regressions"], 1);
    assert_eq!(ap["beacons"], 1);
    let text = std::fs::read_to_string(csv).unwrap();
    let lines: Vec<_> = text.lines().collect();
    assert!(lines[0].contains("audit_status,pmf,akms,ciphers"));
    assert!(lines[1].contains("SAE:000fac08"));
    fn csv_count(line: &str) -> usize {
        let mut quoted = false;
        let mut count = 1;
        let mut chars = line.chars().peekable();
        while let Some(ch) = chars.next() {
            if ch == '"' {
                if quoted && chars.peek() == Some(&'"') {
                    chars.next();
                } else {
                    quoted = !quoted;
                }
            } else if ch == ',' && !quoted {
                count += 1;
            }
        }
        count
    }
    for line in &lines[1..] {
        assert_eq!(csv_count(lines[0]), csv_count(line));
    }
    assert!(lines.iter().any(|line| line.starts_with("rnr,")));
    assert_eq!(
        ap["security_audit"]["current_assessment"]["advertised_mode"],
        "sae_psk_transition"
    );
    let findings = ap["security_audit"]["current_assessment"]["findings"]
        .as_array()
        .unwrap();
    assert!(findings.iter().any(|f| f["id"] == "sae_psk_transition"
        && f["recommendation"].as_str().unwrap().contains("SAE-only")));
    assert!(!findings
        .iter()
        .any(|f| f["id"] == "modern_akm_pmf_optional"));
    assert!(String::from_utf8_lossy(&result.stdout).contains("Recommendation:"));
    assert!(text.contains("audit_recommendations"));
}
