//! Process-level checks of the Stage 1 machine contract and redaction boundary.
use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::atomic::{AtomicUsize, Ordering};

struct Temp(PathBuf);
impl Temp {
    fn new() -> Self {
        static NEXT: AtomicUsize = AtomicUsize::new(0);
        let path = std::env::temp_dir().join(format!(
            "machine-contract-{}-{}",
            std::process::id(),
            NEXT.fetch_add(1, Ordering::Relaxed)
        ));
        std::fs::create_dir(&path).unwrap();
        Self(path)
    }
    fn path(&self, name: &str) -> PathBuf {
        self.0.join(name)
    }
}
impl Drop for Temp {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}
fn fixture(name: &str) -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../tests/fixtures")
        .join(name)
}
fn check(command: &str, args: &[&str], code: i32, category: &str) -> serde_json::Value {
    let temp = Temp::new();
    let diagnostic = temp.path("summary.json");
    let output = Command::new(env!("CARGO_BIN_EXE_aircrack"))
        .arg(command)
        .args(args)
        .arg(if command == "survey" {
            "--diagnostic-json"
        } else {
            "--json"
        })
        .arg(&diagnostic)
        .output()
        .unwrap();
    assert_eq!(output.status.code(), Some(code), "{output:?}");
    let raw = std::fs::read_to_string(diagnostic).unwrap();
    // Deliberately use this sentinel in paths and credentials below.
    assert!(!raw.contains("secret-sentinel"), "{raw}");
    let json: serde_json::Value = serde_json::from_str(&raw).unwrap();
    assert_eq!(json["command"], command);
    assert_eq!(json["schema_version"], 1);
    assert_eq!(json["exit_code"], code);
    assert_eq!(json["exit_category"], category);
    assert!(json["counts"].is_object());
    assert_eq!(json["error"].is_null(), code == 0);
    json
}

#[test]
fn malformed_and_missing_inputs_have_distinct_categories() {
    let temp = Temp::new();
    for bytes in [b"".as_slice(), b"bad", b"not a pcap header"] {
        let input = temp.path("bad.pcap");
        std::fs::write(&input, bytes).unwrap();
        for (command, input_flag) in [("aircrack", "--capture"), ("airdecap", "--input")] {
            check(
                command,
                &[input_flag, input.to_str().unwrap()],
                4,
                "bad_container",
            );
        }
    }
    let missing = temp.path("secret-sentinel.pcap");
    for (command, input_flag) in [("aircrack", "--capture"), ("airdecap", "--input")] {
        check(
            command,
            &[input_flag, missing.to_str().unwrap()],
            5,
            "privilege_or_device",
        );
    }
}

#[test]
fn argument_errors_use_usage_category_and_help_remains_successful() {
    for command in ["aircrack", "airdecap", "survey"] {
        check(command, &["--unknown=secret-sentinel"], 64, "usage");
        let output = Command::new(env!("CARGO_BIN_EXE_aircrack"))
            .args([command, "--help"])
            .output()
            .unwrap();
        assert!(output.status.success());
        let output = Command::new(env!("CARGO_BIN_EXE_aircrack"))
            .arg(command)
            .output()
            .unwrap();
        assert_eq!(output.status.code(), Some(64));
    }
}

#[test]
fn exhausted_dictionary_retains_observed_counts() {
    let json = check(
        "aircrack",
        &[
            "--capture",
            fixture("wpa2-v3.pcap").to_str().unwrap(),
            "--wordlist",
            fixture("wrong-words.txt").to_str().unwrap(),
        ],
        2,
        "password_not_found",
    );
    assert!(json["counts"]["packets"].as_u64().unwrap() > 0);
    assert_eq!(json["counts"]["networks"], 1);
}

#[test]
fn decap_failures_do_not_export_credentials_and_retain_rejection_counts() {
    let temp = Temp::new();
    let input = fixture("decap-ccmp.pcap");
    let output = temp.path("decoded.pcap");
    let base = [
        "--input",
        input.to_str().unwrap(),
        "--output",
        output.to_str().unwrap(),
    ];
    let mut args = base.to_vec();
    args.extend(["--essid", "Test Network", "--pass", "secret-sentinel"]);
    let json = check("airdecap", &args, 3, "no_supported_target");
    assert_eq!(json["counts"]["data_frames"], 0);
    let json = check("airdecap", &base, 3, "no_supported_target");
    assert!(json["counts"]["rejected"].as_u64().unwrap() > 0);
    assert!(!output.exists());
    for flag in ["--pmk", "--wep-key"] {
        let mut args = base.to_vec();
        args.extend([flag, "secret-sentinel"]);
        check("airdecap", &args, 64, "usage");
    }
}

#[test]
fn decap_output_collision_is_device_category_and_preserves_file() {
    let temp = Temp::new();
    let output = temp.path("existing.pcap");
    std::fs::write(&output, b"keep").unwrap();
    check(
        "airdecap",
        &[
            "--input",
            fixture("decap-open.pcap").to_str().unwrap(),
            "--output",
            output.to_str().unwrap(),
        ],
        5,
        "privilege_or_device",
    );
    assert_eq!(std::fs::read(output).unwrap(), b"keep");
}

#[test]
fn successful_decap_diagnostics_exclude_password_pmk_and_wep_key() {
    let expected: serde_json::Value =
        serde_json::from_slice(&std::fs::read(fixture("decap-expected.json")).unwrap()).unwrap();
    let pmk = expected["pmk"].as_str().unwrap();
    for (name, key_args, secret) in [
        (
            "decap-ccmp.pcap",
            vec!["--essid", "Test Network", "--pass", "correct horse battery"],
            "correct horse battery",
        ),
        ("decap-ccmp.pcap", vec!["--pmk", pmk], pmk),
        (
            "decap-wep40.pcap",
            vec!["--wep-key", "0102030405"],
            "0102030405",
        ),
    ] {
        let temp = Temp::new();
        let input = fixture(name);
        let output = temp.path("decoded.pcap");
        let mut args = vec![
            "--input",
            input.to_str().unwrap(),
            "--output",
            output.to_str().unwrap(),
        ];
        args.extend(key_args);
        let json = check("airdecap", &args, 0, "success");
        assert!(!json.to_string().contains(secret));
        assert!(json["counts"]["decrypted"].as_u64().unwrap() > 0);
        assert!(output.exists());
    }
}

#[test]
fn invalid_runtime_configuration_is_usage() {
    let input = fixture("wpa2-v3.pcap");
    check(
        "aircrack",
        &["--capture", input.to_str().unwrap(), "--progress"],
        64,
        "usage",
    );
    let temp = Temp::new();
    let map = temp.path("ssid-map.json");
    std::fs::write(&map, br#"[{"bssid":"secret-sentinel","ssid_hex":"01"}]"#).unwrap();
    check(
        "aircrack",
        &[
            "--capture",
            input.to_str().unwrap(),
            "--ssid-map",
            map.to_str().unwrap(),
        ],
        64,
        "usage",
    );
}

#[test]
fn verification_distinguishes_inspection_found_and_exhaustion() {
    let capture = fixture("wpa2-v3.pcap");
    let base = ["--capture", capture.to_str().unwrap()];
    assert_eq!(
        check("aircrack", &base, 0, "success")["verification"],
        "not_attempted"
    );
    for (words, code, category, verification) in [
        ("words.txt", 0, "success", "found"),
        ("wrong-words.txt", 2, "password_not_found", "not_found"),
    ] {
        let words = fixture(words);
        let mut args = base.to_vec();
        args.extend(["--wordlist", words.to_str().unwrap()]);
        let json = check("aircrack", &args, code, category);
        assert_eq!(json["verification"], verification);
        assert!(!json.to_string().contains("correct horse battery"));
    }
    assert_eq!(
        check("aircrack", &["--bogus"], 64, "usage")["verification"],
        "not_attempted"
    );
}

#[test]
fn wordlist_bad_input_is_usage_in_single_and_multi_paths() {
    let temp = Temp::new();
    let invalid = temp.path("secret-sentinel-words.txt");
    std::fs::write(&invalid, b"incorrect password\n\xff\n").unwrap();
    for words in [invalid, temp.path("secret-sentinel-missing.txt")] {
        for multi in [false, true] {
            let capture = fixture("wpa2-v3.pcap");
            let other = fixture("wrong-words.txt");
            let mut args = vec![
                "--capture",
                capture.to_str().unwrap(),
                "--wordlist",
                words.to_str().unwrap(),
            ];
            if multi {
                args.extend(["--wordlist", other.to_str().unwrap()]);
            }
            check("aircrack", &args, 64, "usage");
        }
    }
}

#[test]
fn candidate_limit_is_partial_in_single_and_multi_paths() {
    let capture = fixture("wpa2-v3.pcap");
    let words = fixture("words.txt");
    let other = fixture("wrong-words.txt");
    for multi in [false, true] {
        let mut args = vec![
            "--capture",
            capture.to_str().unwrap(),
            "--wordlist",
            words.to_str().unwrap(),
            "--max-candidates",
            "1",
        ];
        if multi {
            args.extend(["--wordlist", other.to_str().unwrap()]);
        }
        let json = check("aircrack", &args, 6, "partial");
        assert_eq!(json["verification"], "partial");
        assert!(json["counts"]["packets"].as_u64().unwrap() > 0);
    }
}

#[test]
fn cache_failure_is_internal_in_single_and_multi_paths() {
    let temp = Temp::new();
    let cache = temp.path("secret-sentinel-cache");
    std::fs::create_dir(&cache).unwrap();
    let capture = fixture("wpa2-v3.pcap");
    let words = fixture("words.txt");
    let other = fixture("wrong-words.txt");
    for multi in [false, true] {
        let mut args = vec![
            "--capture",
            capture.to_str().unwrap(),
            "--wordlist",
            words.to_str().unwrap(),
            "--pmk-cache",
            cache.to_str().unwrap(),
        ];
        if multi {
            args.extend(["--wordlist", other.to_str().unwrap()]);
        }
        check("aircrack", &args, 70, "internal");
    }
}

#[test]
fn survey_export_collision_has_device_category_and_hides_paths() {
    let temp = Temp::new();
    let path = temp.path("secret-sentinel-existing.json");
    std::fs::write(&path, b"keep").unwrap();
    for flag in ["--export-json", "--export-csv"] {
        let json = check(
            "survey",
            &[
                "--read",
                fixture("wpa2-v3.pcap").to_str().unwrap(),
                "--plain",
                flag,
                path.to_str().unwrap(),
            ],
            5,
            "privilege_or_device",
        );
        assert!(!json.to_string().contains(temp.0.to_str().unwrap()));
        assert_eq!(std::fs::read(&path).unwrap(), b"keep");
    }
}

#[cfg(unix)]
#[test]
fn sigint_is_partial_and_leaves_resumable_checkpoint() {
    use std::time::{Duration, Instant};
    for multi in [false, true] {
        let temp = Temp::new();
        let words = temp.path("words.txt");
        std::fs::write(&words, "incorrect password\n".repeat(100_000)).unwrap();
        let session = temp.path("session.json");
        let diagnostic = temp.path("diagnostic.json");
        let mut command = Command::new(env!("CARGO_BIN_EXE_aircrack"));
        command
            .arg("aircrack")
            .arg("--capture")
            .arg(fixture("wpa2-v3.pcap"))
            .arg("--wordlist")
            .arg(&words)
            .arg("--session")
            .arg(&session)
            .arg("--threads")
            .arg("1")
            .arg("--json")
            .arg(&diagnostic)
            .stdout(std::process::Stdio::null())
            .stderr(std::process::Stdio::null());
        if multi {
            command.arg("--wordlist").arg(fixture("wrong-words.txt"));
        }
        let mut child = command.spawn().unwrap();
        let deadline = Instant::now() + Duration::from_secs(30);
        let status = loop {
            if let Some(status) = child.try_wait().unwrap() {
                break status;
            }
            let completed = std::fs::read(&session)
                .ok()
                .and_then(|bytes| serde_json::from_slice::<serde_json::Value>(&bytes).ok())
                .and_then(|json| json["completed_lines"].as_u64())
                .unwrap_or(0);
            if completed > 0 {
                assert!(Command::new("kill")
                    .args(["-INT", &child.id().to_string()])
                    .status()
                    .unwrap()
                    .success());
                break child.wait().unwrap();
            }
            if Instant::now() > deadline {
                child.kill().unwrap();
                child.wait().unwrap();
                panic!("dictionary did not checkpoint before deadline");
            }
            std::thread::sleep(Duration::from_millis(10));
        };
        assert_eq!(status.code(), Some(6));
        let json: serde_json::Value =
            serde_json::from_slice(&std::fs::read(diagnostic).unwrap()).unwrap();
        assert_eq!(json["exit_category"], "partial");
        assert_eq!(json["verification"], "partial");
        assert!(session.exists());
    }
}
