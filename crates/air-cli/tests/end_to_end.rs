use air_capture::{decode_packet, read_pcap};
use air_crack::{wordlist::Wordlist, Engine};
use air_handshake::extract;
use std::path::{Path, PathBuf};
use std::process::{Command, Output};
use std::sync::atomic::{AtomicUsize, Ordering};

fn fixture(name: &str) -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../tests/fixtures")
        .join(name)
}
fn cli(args: &[&str]) -> Output {
    Command::new(env!("CARGO_BIN_EXE_aircrack"))
        .args(args)
        .output()
        .unwrap()
}
struct Temp(PathBuf);
impl Temp {
    fn new(bytes: &[u8]) -> Self {
        static NEXT: AtomicUsize = AtomicUsize::new(0);
        let p = std::env::temp_dir().join(format!(
            "aircrack-test-{}-{}",
            std::process::id(),
            NEXT.fetch_add(1, Ordering::Relaxed)
        ));
        std::fs::write(&p, bytes).unwrap();
        Self(p)
    }
    fn path(&self) -> &str {
        self.0.to_str().unwrap()
    }
}
impl Drop for Temp {
    fn drop(&mut self) {
        let _ = std::fs::remove_file(&self.0);
    }
}

fn pcap(frames: &[air_capture::Packet]) -> Vec<u8> {
    let mut out = vec![0xd4, 0xc3, 0xb2, 0xa1, 2, 0, 4, 0];
    for v in [0u32, 0, 65535, 105] {
        out.extend_from_slice(&v.to_le_bytes());
    }
    for f in frames {
        for v in [0u32, 0, f.data.len() as u32, f.data.len() as u32] {
            out.extend_from_slice(&v.to_le_bytes());
        }
        out.extend_from_slice(&f.data);
    }
    out
}

#[test]
fn independent_capture_to_handshake_to_password_for_all_link_types() {
    for name in [
        "wpa2-raw.pcap",
        "wpa2-radiotap.pcap",
        "wpa2-ethernet.pcap",
        "wpa2-mixed.pcapng",
        "wpa2-simple.pcapng",
    ] {
        let packets = read_pcap(fixture(name)).unwrap();
        let frames: Vec<_> = packets
            .iter()
            .filter_map(|p| decode_packet(p).ok())
            .collect();
        let sessions = extract(&frames);
        assert_eq!(sessions.len(), 1, "{name}");
        let session = sessions.into_iter().next().unwrap();
        assert_eq!(session.bssid, [2, 0, 0, 0, 0, 1]);
        assert_eq!(session.sta, [2, 0, 0, 0, 0, 2]);
        assert_eq!(
            session.anonce.unwrap(),
            std::array::from_fn(|i| i as u8 + 1)
        );
        assert_eq!(
            session.snonce.unwrap(),
            std::array::from_fn(|i| i as u8 + 33)
        );
        let engine = Engine::new(session, b"Test Network".to_vec()).unwrap();
        assert!(!engine.verify_candidate("incorrect password"));
        let found = engine
            .crack_wordlist(Wordlist::from_file(fixture("words.txt")).unwrap())
            .unwrap();
        assert_eq!(found.as_deref(), Some("correct horse battery"), "{name}");
    }
}

#[test]
fn cli_finds_password_with_discovered_or_explicit_ssid() {
    for name in [
        "wpa2-raw.pcap",
        "wpa2-radiotap.pcap",
        "wpa2-mixed.pcapng",
        "wpa2-simple.pcapng",
        "wpa2-ethernet.pcap",
    ] {
        let capture = fixture(name);
        let words = fixture("words.txt");
        let mut args = vec![
            "aircrack",
            "--capture",
            capture.to_str().unwrap(),
            "--wordlist",
            words.to_str().unwrap(),
        ];
        if name == "wpa2-ethernet.pcap" {
            args.extend(["--essid", "Test Network"]);
        }
        let result = cli(&args);
        assert!(
            result.status.success(),
            "{name}: {}",
            String::from_utf8_lossy(&result.stderr)
        );
        assert!(
            String::from_utf8_lossy(&result.stdout).contains("[+] found: correct horse battery")
        );
    }
}

#[test]
fn cli_reports_wrong_password_and_missing_or_wrong_ssid() {
    for (name, words, extra, error) in [
        (
            "wpa2-raw.pcap",
            "wrong-words.txt",
            vec![],
            "password not found",
        ),
        ("wpa2-ethernet.pcap", "words.txt", vec![], "SSID is missing"),
        (
            "wpa2-raw.pcap",
            "words.txt",
            vec!["--essid", "Wrong Network"],
            "no complete",
        ),
        (
            "wpa2-ethernet.pcap",
            "words.txt",
            vec!["--essid", "Wrong Network"],
            "password not found",
        ),
        (
            "wpa2-raw.pcap",
            "words.txt",
            vec!["--bssid", "02:00:00:00:00:03"],
            "no complete",
        ),
    ] {
        let capture = fixture(name);
        let words = fixture(words);
        let mut args = vec![
            "aircrack",
            "--capture",
            capture.to_str().unwrap(),
            "--wordlist",
            words.to_str().unwrap(),
        ];
        args.extend(extra);
        let result = cli(&args);
        assert!(!result.status.success());
        assert!(
            String::from_utf8_lossy(&result.stderr).contains(error),
            "{}",
            String::from_utf8_lossy(&result.stderr)
        );
        assert!(!String::from_utf8_lossy(&result.stdout).contains("[+] found:"));
    }
}

#[test]
fn malformed_incomplete_mismatched_and_tampered_captures_fail() {
    let packets = read_pcap(fixture("wpa2-raw.pcap")).unwrap();
    let words = fixture("words.txt");
    let mut mismatch = packets.clone();
    mismatch[4].data[26 + 8 + 16] ^= 1; // M2 replay counter
    let mut tampered = packets.clone();
    tampered[4].data[26 + 8 + 81] ^= 1; // MIC
    let mut unsupported = packets.clone();
    unsupported[4].data[26 + 8 + 6] = 9; // descriptor v1
    for (data, error) in [
        (vec![0; 10], "cannot read capture"),
        (pcap(&packets[..4]), "no complete"),
        (pcap(&mismatch), "no complete"),
        (pcap(&unsupported), "no complete"),
        (pcap(&tampered), "password not found"),
    ] {
        let temp = Temp::new(&data);
        let result = cli(&[
            "aircrack",
            "--capture",
            temp.path(),
            "--wordlist",
            words.to_str().unwrap(),
        ]);
        assert!(!result.status.success());
        assert!(
            String::from_utf8_lossy(&result.stderr).contains(error),
            "{}",
            String::from_utf8_lossy(&result.stderr)
        );
    }
}

#[test]
fn multiple_networks_report_independent_results_and_never_mix_sessions() {
    let mut packets = read_pcap(fixture("wpa2-raw.pcap")).unwrap();
    let mut other = packets.clone();
    for (index, offset) in [(1, 16), (2, 10), (4, 4), (5, 10)] {
        other[index].data[offset + 5] = 3;
    }
    packets.extend(other);
    let temp = Temp::new(&pcap(&packets));
    let words = fixture("words.txt");
    let args = [
        "aircrack",
        "--capture",
        temp.path(),
        "--wordlist",
        words.to_str().unwrap(),
    ];
    let result = cli(&args);
    assert!(!result.status.success());
    assert!(String::from_utf8_lossy(&result.stderr).contains("matched 1/2"));
    assert!(String::from_utf8_lossy(&result.stdout).contains("status=not_found"));
    let mut selected = args.to_vec();
    selected.extend(["--bssid", "02:00:00:00:00:01"]);
    assert!(cli(&selected).status.success());
}

#[test]
fn conflicting_ssids_require_explicit_selection() {
    let mut packets = read_pcap(fixture("wpa2-raw.pcap")).unwrap();
    let mut beacon = packets[1].clone();
    // The fixture beacon has a 24-byte header, 12 fixed bytes, then the SSID IE.
    beacon.data[38] ^= 1;
    packets.push(beacon);
    let capture = Temp::new(&pcap(&packets));
    let words = fixture("words.txt");
    let args = [
        "aircrack",
        "--capture",
        capture.path(),
        "--wordlist",
        words.to_str().unwrap(),
    ];
    let result = cli(&args);
    assert!(!result.status.success());
    assert!(String::from_utf8_lossy(&result.stderr).contains("conflicting SSIDs"));
    let mut explicit = args.to_vec();
    explicit.extend(["--essid", "Test Network"]);
    assert!(cli(&explicit).status.success());
}

#[test]
fn help_describes_actual_support() {
    let result = cli(&["--help"]);
    assert!(result.status.success());
    let text = String::from_utf8_lossy(&result.stdout);
    assert!(text.contains("not supported"));
    assert!(text.contains("authorized"));
}

#[test]
fn inspection_needs_no_wordlist() {
    let capture = fixture("wpa2-raw.pcap");
    let result = cli(&["aircrack", "--capture", capture.to_str().unwrap()]);
    assert!(result.status.success());
    assert!(String::from_utf8_lossy(&result.stdout).contains("selected BSSID: 02:00:00:00:00:01"));
    assert!(!String::from_utf8_lossy(&result.stdout).contains("[+] found:"));
}

#[test]
fn dictionary_read_errors_are_not_silently_ignored() {
    let words = Temp::new(b"incorrect password\n\xff\n");
    let capture = fixture("wpa2-raw.pcap");
    let result = cli(&[
        "aircrack",
        "--capture",
        capture.to_str().unwrap(),
        "--wordlist",
        words.path(),
    ]);
    assert!(!result.status.success());
    assert!(String::from_utf8_lossy(&result.stderr).contains("wordlist:"));
}

#[test]
fn tui_rejects_noninteractive_execution() {
    let result = cli(&["tui"]);
    assert!(!result.status.success());
    assert!(String::from_utf8_lossy(&result.stderr).contains("interactive terminal"));
    assert!(
        !result.stdout.contains(&0x1b),
        "must not emit terminal control codes"
    );
}

#[test]
fn stubs_fail_explicitly_and_do_not_print_secrets() {
    for args in [
        vec!["airmon", "check"],
        vec!["aireplay"],
        vec!["airbase"],
        vec!["packetforge"],
        vec!["ivstools"],
    ] {
        let result = cli(&args);
        assert!(!result.status.success());
        assert!(String::from_utf8_lossy(&result.stderr).contains("not implemented"));
        assert!(!String::from_utf8_lossy(&result.stdout).contains("secret-value"));
        assert!(!String::from_utf8_lossy(&result.stderr).contains("secret-value"));
    }
}

#[test]
fn invalid_session_is_rejected_and_wordlist_crosses_batch_boundary() {
    assert!(Engine::new(Default::default(), b"Test Network".to_vec()).is_err());
    let frames: Vec<_> = read_pcap(fixture("wpa2-raw.pcap"))
        .unwrap()
        .iter()
        .filter_map(|p| decode_packet(p).ok())
        .collect();
    let session = extract(&frames).remove(0);
    assert!(Engine::new(session.clone(), vec![]).is_err());
    assert!(Engine::new(session.clone(), vec![b'x'; 33]).is_err());
    let mut invalid = session.clone();
    invalid.anonce = None;
    assert!(Engine::new(invalid, b"Test Network".to_vec()).is_err());
    let engine = Engine::new(session, b"Test Network".to_vec()).unwrap();
    let words = (0..256)
        .map(|_| Ok(String::from("short")))
        .chain([Ok("correct horse battery".to_owned())]);
    assert_eq!(
        engine.crack_wordlist(words).unwrap().as_deref(),
        Some("correct horse battery")
    );
    assert!(engine
        .crack_wordlist([Err(std::io::Error::other("read failure"))])
        .is_err());
}

#[test]
fn m2m3_and_pmkid_capture_to_password_library_and_cli() {
    use air_handshake::{extract_targets, VerificationTarget};
    for (stem, is_pmkid) in [
        ("wpa2-m2m3", false),
        ("wpa2-pmkid", true),
        ("wpa2-pmkid-assoc", true),
        ("wpa2-pmkid-reassoc", true),
    ] {
        let mut names = vec![
            format!("{stem}.pcap"),
            format!("{stem}-radiotap.pcap"),
            format!("{stem}.pcapng"),
        ];
        if !stem.ends_with("assoc") {
            names.push(format!("{stem}-ethernet.pcap"));
        }
        for name in names {
            let capture = fixture(&name);
            let frames: Vec<_> = read_pcap(&capture)
                .unwrap()
                .iter()
                .filter_map(|p| decode_packet(p).ok())
                .collect();
            let targets = extract_targets(&frames);
            assert_eq!(targets.len(), 1, "{name}");
            assert_eq!(matches!(targets[0], VerificationTarget::Pmkid(_)), is_pmkid);
            let engine = Engine::from_target(targets[0].clone(), b"Test Network".to_vec()).unwrap();
            assert!(engine.verify_candidate("correct horse battery"), "{name}");
            assert!(!engine.verify_candidate("incorrect password"), "{name}");
            for (words, found) in [("words.txt", true), ("wrong-words.txt", false)] {
                let words = fixture(words);
                let mut args = vec![
                    "aircrack",
                    "--capture",
                    capture.to_str().unwrap(),
                    "--wordlist",
                    words.to_str().unwrap(),
                ];
                if name.contains("ethernet") {
                    args.extend(["--essid", "Test Network"]);
                }
                let result = cli(&args);
                assert_eq!(
                    result.status.success(),
                    found,
                    "{name}: {}",
                    String::from_utf8_lossy(&result.stderr)
                );
                assert_eq!(
                    String::from_utf8_lossy(&result.stdout)
                        .contains("[+] found: correct horse battery"),
                    found,
                    "{name}"
                );
                if is_pmkid {
                    assert!(String::from_utf8_lossy(&result.stdout).contains("PMKID targets: 1"));
                }
            }
        }
    }
}

#[test]
fn new_targets_tampering_selection_and_order_regressions() {
    use air_handshake::{extract_targets, PmkidSession, VerificationTarget};
    let words = fixture("words.txt");
    for name in ["wpa2-m2m3-bad-mic.pcap", "wpa2-pmkid-bad-id.pcap"] {
        let capture = fixture(name);
        let r = cli(&[
            "aircrack",
            "--capture",
            capture.to_str().unwrap(),
            "--wordlist",
            words.to_str().unwrap(),
        ]);
        assert!(!r.status.success());
        assert!(String::from_utf8_lossy(&r.stderr).contains("password not found"));
    }
    for name in ["wpa2-m2m3.pcap", "wpa2-pmkid.pcap"] {
        let capture = fixture(name);
        for (key, value) in [("--essid", "wrong"), ("--bssid", "02:00:00:00:00:03")] {
            let r = cli(&[
                "aircrack",
                "--capture",
                capture.to_str().unwrap(),
                "--wordlist",
                words.to_str().unwrap(),
                key,
                value,
            ]);
            assert!(!r.status.success());
        }
        let mut packets = read_pcap(capture).unwrap();
        packets.reverse();
        packets.extend(packets.clone());
        let frames: Vec<_> = packets
            .iter()
            .filter_map(|p| decode_packet(p).ok())
            .collect();
        assert_eq!(extract_targets(&frames).len(), 1);
    }
    assert!(Engine::from_target(
        VerificationTarget::Pmkid(PmkidSession {
            bssid: [2, 0, 0, 0, 0, 1],
            sta: [2, 0, 0, 0, 0, 2],
            pmkid: [0; 16]
        }),
        b"Test Network".to_vec()
    )
    .is_err());
    let packets = read_pcap(fixture("wpa2-pmkid.pcap")).unwrap();
    let frames: Vec<_> = packets
        .iter()
        .filter_map(|p| decode_packet(p).ok())
        .collect();
    let VerificationTarget::Pmkid(mut target) = extract_targets(&frames).remove(0) else {
        panic!("PMKID target expected")
    };
    std::mem::swap(&mut target.bssid, &mut target.sta);
    assert!(
        !Engine::from_target(VerificationTarget::Pmkid(target), b"Test Network".to_vec())
            .unwrap()
            .verify_candidate("correct horse battery")
    );
}

#[test]
fn resource_limits_fail_without_partial_success() {
    for (name, option, value, error) in [
        ("wpa2-raw.pcap", "--max-packets", "1", "packet limit"),
        ("wpa2-simple.pcapng", "--max-packets", "1", "packet limit"),
        ("wpa2-raw.pcap", "--max-records", "1", "record/target limit"),
    ] {
        let result = cli(&[
            "aircrack",
            "--capture",
            fixture(name).to_str().unwrap(),
            option,
            value,
        ]);
        assert!(!result.status.success());
        assert!(
            String::from_utf8_lossy(&result.stderr).contains(error),
            "{}",
            String::from_utf8_lossy(&result.stderr)
        );
    }
    let large = Temp::new(&vec![0; 1024 * 1024 + 1]);
    let result = cli(&[
        "aircrack",
        "--capture",
        large.path(),
        "--max-capture-mib",
        "1",
    ]);
    assert!(String::from_utf8_lossy(&result.stderr).contains("byte limit"));
}

#[test]
fn dictionary_single_pass_handles_a_bad_target_before_a_good_one() {
    let mut packets = read_pcap(fixture("wpa2-raw.pcap")).unwrap();
    let mut bad = packets[4].clone();
    bad.data[26 + 8 + 81] ^= 1;
    packets.insert(4, bad);
    let input = Temp::new(&pcap(&packets));
    let result = cli(&[
        "aircrack",
        "--capture",
        input.path(),
        "--wordlist",
        fixture("words.txt").to_str().unwrap(),
        "--progress",
    ]);
    assert!(
        result.status.success(),
        "{}",
        String::from_utf8_lossy(&result.stderr)
    );
    assert!(String::from_utf8_lossy(&result.stdout).contains("[+] found:"));
    assert!(String::from_utf8_lossy(&result.stderr).contains("dictionary lines completed"));
}

#[test]
fn stdin_verifies_and_propagates_invalid_encoding() {
    use std::io::Write;
    use std::process::Stdio;
    for (bytes, success) in [
        (
            b"incorrect password\ncorrect horse battery\n".as_slice(),
            true,
        ),
        (b"\xff\n".as_slice(), false),
    ] {
        let mut child = Command::new(env!("CARGO_BIN_EXE_aircrack"))
            .args([
                "aircrack",
                "--capture",
                fixture("wpa2-raw.pcap").to_str().unwrap(),
                "--wordlist",
                "-",
                "--progress",
            ])
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .unwrap();
        child.stdin.take().unwrap().write_all(bytes).unwrap();
        let result = child.wait_with_output().unwrap();
        assert_eq!(
            result.status.success(),
            success,
            "{}",
            String::from_utf8_lossy(&result.stderr)
        );
        if !success {
            assert!(String::from_utf8_lossy(&result.stderr).contains("cannot read wordlist"));
        }
    }
}

#[test]
fn checkpoint_resume_identity_privacy_and_no_overwrite() {
    let words = Temp::new(b"incorrect password\ncorrect horse battery\n");
    let session = Temp::new(b"");
    std::fs::remove_file(&session.0).unwrap();
    let capture = fixture("wpa2-raw.pcap");
    let base = [
        "aircrack",
        "--capture",
        capture.to_str().unwrap(),
        "--wordlist",
        words.path(),
    ];
    let mut args = base.to_vec();
    args.extend([
        "--session",
        session.path(),
        "--max-candidates",
        "1",
        "--progress",
    ]);
    let result = cli(&args);
    assert!(!result.status.success());
    assert!(String::from_utf8_lossy(&result.stderr).contains("verification paused"));
    let saved = std::fs::read(&session.0).unwrap();
    let state: serde_json::Value = serde_json::from_slice(&saved).unwrap();
    assert_eq!(state["completed_lines"], 1);
    assert!(!String::from_utf8_lossy(&saved).contains("incorrect password"));
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        assert_eq!(
            std::fs::metadata(&session.0).unwrap().permissions().mode() & 0o777,
            0o600
        );
    }
    let mut args = base.to_vec();
    args.extend(["--session", session.path()]);
    assert!(!cli(&args).status.success());
    assert_eq!(std::fs::read(&session.0).unwrap(), saved);
    let mut args = base.to_vec();
    args.extend(["--resume", session.path(), "--progress"]);
    let result = cli(&args);
    assert!(
        result.status.success(),
        "{}",
        String::from_utf8_lossy(&result.stderr)
    );
    assert!(String::from_utf8_lossy(&result.stdout).contains("correct horse battery"));
    // A successful batch must remain replayable, without storing the password.
    assert_eq!(std::fs::read(&session.0).unwrap(), saved);
    assert!(cli(&args).status.success());
    std::fs::write(&words.0, b"changed dictionary\ncorrect horse battery\n").unwrap();
    let result = cli(&args);
    assert!(String::from_utf8_lossy(&result.stderr).contains("input mismatch"));
    assert_eq!(std::fs::read(&session.0).unwrap(), saved);
}

#[test]
fn stdin_checkpoint_options_are_rejected_before_reading() {
    let result = cli(&[
        "aircrack",
        "--capture",
        "missing.pcap",
        "--wordlist",
        "-",
        "--resume",
        "missing.session",
    ]);
    assert!(String::from_utf8_lossy(&result.stderr).contains("stdin cannot be checkpointed"));
}

#[test]
fn checkpoint_lock_and_changed_capture_are_rejected() {
    let words = Temp::new(b"incorrect password\ncorrect horse battery\n");
    let mut packets = read_pcap(fixture("wpa2-raw.pcap")).unwrap();
    let capture = Temp::new(&pcap(&packets));
    let session = Temp::new(b"");
    std::fs::remove_file(&session.0).unwrap();
    let base = [
        "aircrack",
        "--capture",
        capture.path(),
        "--wordlist",
        words.path(),
    ];
    let mut args = base.to_vec();
    args.extend(["--session", session.path(), "--max-candidates", "1"]);
    assert!(!cli(&args).status.success());
    let mut args = base.to_vec();
    args.extend(["--resume", session.path()]);
    let lock = PathBuf::from(format!("{}.lock", session.path()));
    std::fs::write(&lock, b"test lock").unwrap();
    let result = cli(&args);
    assert!(String::from_utf8_lossy(&result.stderr).contains("session is locked"));
    assert_eq!(std::fs::read(&lock).unwrap(), b"test lock");
    std::fs::remove_file(lock).unwrap();
    packets[4].data[26 + 8 + 81] ^= 1;
    std::fs::write(&capture.0, pcap(&packets)).unwrap();
    let result = cli(&args);
    assert!(String::from_utf8_lossy(&result.stderr).contains("input mismatch"));
}

#[cfg(unix)]
#[test]
fn termination_checkpoints_only_completed_batches_and_releases_lock() {
    use std::process::Stdio;
    use std::time::{Duration, Instant};
    let words = Temp::new("incorrect password\n".repeat(100_000).as_bytes());
    let session = Temp::new(b"");
    std::fs::remove_file(&session.0).unwrap();
    let mut child = Command::new(env!("CARGO_BIN_EXE_aircrack"))
        .args([
            "aircrack",
            "--capture",
            fixture("wpa2-raw.pcap").to_str().unwrap(),
            "--wordlist",
            words.path(),
            "--session",
            session.path(),
        ])
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .unwrap();
    let deadline = Instant::now() + Duration::from_secs(15);
    let before = loop {
        let completed = std::fs::read(&session.0)
            .ok()
            .and_then(|s| serde_json::from_slice::<serde_json::Value>(&s).ok())
            .and_then(|s| s["completed_lines"].as_u64())
            .unwrap_or(0);
        if completed > 0 {
            break completed;
        }
        if Instant::now() > deadline {
            let _ = child.kill();
            let _ = child.wait();
            panic!("first checkpoint was not written");
        }
        std::thread::sleep(Duration::from_millis(20));
    };
    assert_eq!(unsafe { libc::kill(child.id() as i32, libc::SIGTERM) }, 0);
    loop {
        if let Some(status) = child.try_wait().unwrap() {
            assert!(!status.success());
            break;
        }
        if Instant::now() > deadline {
            let _ = child.kill();
            let _ = child.wait();
            panic!("SIGTERM did not stop verification");
        }
        std::thread::sleep(Duration::from_millis(20));
    }
    let saved: serde_json::Value =
        serde_json::from_slice(&std::fs::read(&session.0).unwrap()).unwrap();
    let completed = saved["completed_lines"].as_u64().unwrap();
    assert!(completed >= before);
    assert_eq!(completed % 256, 0);
    assert!(!PathBuf::from(format!("{}.lock", session.path())).exists());
}
