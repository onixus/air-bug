use air_capture::{read_pcap, read_pcap_records, CaptureLimits, Packet};
use std::path::{Path, PathBuf};
use std::process::{Command, Output};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::Duration;
struct Temp(PathBuf);
impl Temp {
    fn new() -> Self {
        static NEXT: AtomicUsize = AtomicUsize::new(0);
        let p = std::env::temp_dir().join(format!(
            "decap-test-{}-{}",
            std::process::id(),
            NEXT.fetch_add(1, Ordering::Relaxed)
        ));
        std::fs::create_dir(&p).unwrap();
        Self(p)
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
fn cli(input: &Path, output: &Path, extra: &[&str]) -> Output {
    Command::new(env!("CARGO_BIN_EXE_aircrack"))
        .args([
            "airdecap",
            "--input",
            input.to_str().unwrap(),
            "--output",
            output.to_str().unwrap(),
        ])
        .args(extra)
        .output()
        .unwrap()
}
fn aircrack(args: &[&str]) -> Output {
    Command::new(env!("CARGO_BIN_EXE_aircrack"))
        .arg("aircrack")
        .args(args)
        .output()
        .unwrap()
}
fn expected() -> serde_json::Value {
    serde_json::from_slice(&std::fs::read(fixture("decap-expected.json")).unwrap()).unwrap()
}
fn pcap(packets: &[Packet]) -> Vec<u8> {
    let mut out = vec![0xd4, 0xc3, 0xb2, 0xa1, 2, 0, 4, 0];
    for n in [0u32, 0, 65535, 105] {
        out.extend(n.to_le_bytes());
    }
    for p in packets {
        for n in [123u32, 456, p.data.len() as u32, p.data.len() as u32] {
            out.extend(n.to_le_bytes());
        }
        out.extend(&p.data);
    }
    out
}
#[test]
fn ccmp_both_directions_qos_radiotap_and_pcapng_preserve_payload_and_time() {
    let temp = Temp::new();
    let want = expected();
    for (i, name) in [
        "decap-ccmp.pcap",
        "decap-ccmp-radiotap.pcap",
        "decap-ccmp.pcapng",
        "decap-ccmp-tsresol.pcapng",
    ]
    .iter()
    .enumerate()
    {
        let output = temp.path(&format!("{i}.pcap"));
        let result = cli(
            &fixture(name),
            &output,
            &["-e", "Test Network", "-p", "correct horse battery"],
        );
        assert!(
            result.status.success(),
            "{}",
            String::from_utf8_lossy(&result.stderr)
        );
        let records = read_pcap_records(&output, CaptureLimits::default()).unwrap();
        assert_eq!(records.len(), 2);
        assert_eq!(records[0].packet.dlt, 1);
        assert_eq!(
            hex::encode(&records[0].packet.data),
            want["ethernet_from_ap"].as_str().unwrap()
        );
        assert_eq!(
            hex::encode(&records[1].packet.data),
            want["ethernet_to_ap"].as_str().unwrap()
        );
        let time = if i == 3 {
            Duration::new(125, 500_000_000)
        } else {
            Duration::new(126, 456_000)
        };
        assert_eq!(records[0].timestamp, Some(time));
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            assert_eq!(
                std::fs::metadata(&output).unwrap().permissions().mode() & 0o777,
                0o600
            );
        }
    }
}
#[test]
fn ccmp_accepts_pmk_and_can_keep_wireless_headers() {
    let temp = Temp::new();
    let output = temp.path("raw.pcap");
    let want = expected();
    let result = cli(
        &fixture("decap-ccmp.pcap"),
        &output,
        &["--pmk", want["pmk"].as_str().unwrap(), "--keep-wireless"],
    );
    assert!(
        result.status.success(),
        "{}",
        String::from_utf8_lossy(&result.stderr)
    );
    let packets = read_pcap(&output).unwrap();
    assert_eq!(packets.len(), 2);
    for p in packets {
        assert_eq!(p.dlt, 105);
        assert_eq!(p.data[1] & 0x40, 0);
        let f = air_frames::parse_dot11(&p.data).unwrap();
        assert_eq!(hex::encode(f.payload), want["payload"].as_str().unwrap());
    }
}
#[test]
fn wep40_wep104_and_open_data_decode() {
    let temp = Temp::new();
    let want = expected();
    for (name, args) in [
        ("decap-wep40.pcap", vec!["-w", "0102030405"]),
        (
            "decap-wep104.pcap",
            vec!["-w", "0102030405060708090a0b0c0d"],
        ),
        ("decap-open.pcap", vec![]),
    ] {
        let output = temp.path(name);
        let result = cli(&fixture(name), &output, &args);
        assert!(
            result.status.success(),
            "{}",
            String::from_utf8_lossy(&result.stderr)
        );
        let packets = read_pcap(&output).unwrap();
        assert_eq!(packets.len(), 1);
        assert_eq!(
            hex::encode(&packets[0].data),
            want["ethernet_from_ap"].as_str().unwrap()
        );
    }
}
#[test]
fn wrong_credentials_missing_handshake_and_integrity_failures_never_emit_plaintext() {
    let temp = Temp::new();
    let output = temp.path("out.pcap");
    for (name, args) in [
        (
            "decap-ccmp.pcap",
            vec!["-e", "Test Network", "-p", "incorrect password"],
        ),
        (
            "decap-ccmp-bad-tag.pcap",
            vec!["-e", "Test Network", "-p", "correct horse battery"],
        ),
        (
            "decap-ccmp-no-handshake.pcap",
            vec!["-e", "Test Network", "-p", "correct horse battery"],
        ),
        ("decap-wep40-bad-icv.pcap", vec!["-w", "0102030405"]),
        (
            "decap-wep104-bad-icv.pcap",
            vec!["-w", "0102030405060708090a0b0c0d"],
        ),
        ("decap-wep40.pcap", vec!["-w", "0000000000"]),
        ("decap-ccmp.pcap", vec!["-k", "bad-secret-value"]),
        (
            "decap-ccmp.pcap",
            vec![
                "-b",
                "02:00:00:00:00:03",
                "-e",
                "Test Network",
                "-p",
                "correct horse battery",
            ],
        ),
    ] {
        let result = cli(&fixture(name), &output, &args);
        assert!(!result.status.success(), "{name}");
        assert!(!output.exists(), "{name}");
        assert!(!String::from_utf8_lossy(&result.stderr).contains("bad-secret-value"));
        assert!(!String::from_utf8_lossy(&result.stderr).contains("incorrect password"));
    }
}
#[test]
fn ccmp_authenticates_addresses_priority_packet_number_and_key_id() {
    let temp = Temp::new();
    let output = temp.path("out.pcap");
    let input = temp.path("mutated.pcap");
    let original = read_pcap(fixture("decap-ccmp.pcap")).unwrap();
    for offset in [4, 10, 16, 24, 26, 29, 34, original[3].data.len() - 1] {
        let mut packets = original[..4].to_vec();
        packets[3].data[offset] ^= 1;
        std::fs::write(&input, pcap(&packets)).unwrap();
        let result = cli(
            &input,
            &output,
            &["-e", "Test Network", "-p", "correct horse battery"],
        );
        assert!(!result.status.success(), "offset {offset}");
        assert!(!output.exists());
    }
}
#[test]
fn output_and_input_are_never_overwritten() {
    let temp = Temp::new();
    let input = temp.path("input.pcap");
    let output = temp.path("output.pcap");
    let bytes = std::fs::read(fixture("decap-open.pcap")).unwrap();
    std::fs::write(&input, &bytes).unwrap();
    std::fs::write(&output, b"keep").unwrap();
    assert!(!cli(&input, &output, &[]).status.success());
    assert_eq!(std::fs::read(&output).unwrap(), b"keep");
    assert!(!cli(&input, &input, &[]).status.success());
    assert_eq!(std::fs::read(&input).unwrap(), bytes);
}
#[test]
fn wpa1_hmac_md5_and_raw_psk_dictionary_are_supported() {
    let temp = Temp::new();
    let dict = temp.path("pmk.txt");
    std::fs::write(&dict, format!("{}\n", expected()["pmk"].as_str().unwrap())).unwrap();
    for name in ["wpa1-m1m2.pcap", "wpa1-m2m3.pcap", "wpa2-m1m2-compat.pcap"] {
        for words in [fixture("words.txt"), dict.clone()] {
            let result = Command::new(env!("CARGO_BIN_EXE_aircrack"))
                .args([
                    "aircrack",
                    "--capture",
                    fixture(name).to_str().unwrap(),
                    "--wordlist",
                    words.to_str().unwrap(),
                    "--essid",
                    "Test Network",
                ])
                .output()
                .unwrap();
            assert!(
                result.status.success(),
                "{name}: {}",
                String::from_utf8_lossy(&result.stderr)
            );
        }
    }
}

#[test]
fn old_checkpoint_version_is_rejected_after_candidate_semantics_change() {
    let temp = Temp::new();
    let session = temp.path("session.json");
    let capture = fixture("wpa2-raw.pcap");
    let words = fixture("words.txt");
    let base = [
        "aircrack",
        "--capture",
        capture.to_str().unwrap(),
        "--wordlist",
        words.to_str().unwrap(),
    ];
    let result = Command::new(env!("CARGO_BIN_EXE_aircrack"))
        .args(base)
        .args([
            "--session",
            session.to_str().unwrap(),
            "--max-candidates",
            "1",
        ])
        .output()
        .unwrap();
    assert!(!result.status.success());
    let mut state: serde_json::Value =
        serde_json::from_slice(&std::fs::read(&session).unwrap()).unwrap();
    state["version"] = serde_json::json!(1);
    std::fs::write(&session, serde_json::to_vec(&state).unwrap()).unwrap();
    let result = Command::new(env!("CARGO_BIN_EXE_aircrack"))
        .args(base)
        .args(["--resume", session.to_str().unwrap()])
        .output()
        .unwrap();
    assert!(!result.status.success());
    assert!(String::from_utf8_lossy(&result.stderr).contains("unsupported checkpoint version"));
}

#[test]
fn tkip_and_gtk_return_exact_ethernet_bytes_including_rekeys() {
    let temp = Temp::new();
    let want = expected();
    let advanced: serde_json::Value =
        serde_json::from_slice(&std::fs::read(fixture("advanced-vectors.json")).unwrap()).unwrap();
    for (name, count, group) in [
        ("decap-tkip", 2, false),
        ("decap-tkip-wpa2", 1, false),
        ("decap-v3", 1, false),
        ("decap-gtk-ccmp", 1, true),
        ("decap-gtk-tkip", 1, true),
        ("decap-gtk-wpa1", 1, true),
        ("decap-gtk-v3", 1, true),
        ("decap-gtk-ccmp-rekey", 2, true),
        ("decap-gtk-ccmp-same-id-rekey", 2, true),
        ("decap-gtk-tkip-rekey", 2, true),
    ] {
        let output = temp.path(name);
        let result = cli(
            &fixture(&format!("{name}.pcap")),
            &output,
            &["-e", "Test Network", "-p", "correct horse battery"],
        );
        assert!(
            result.status.success(),
            "{name}: {}",
            String::from_utf8_lossy(&result.stderr)
        );
        let packets = read_pcap(&output).unwrap();
        assert_eq!(packets.len(), count, "{name}");
        for (index, p) in packets.iter().enumerate() {
            let key = if group {
                "group_ethernet"
            } else if index == 1 {
                "ethernet_to_ap"
            } else {
                "ethernet_from_ap"
            };
            let value = if group { &advanced[key] } else { &want[key] };
            assert_eq!(
                hex::encode(&p.data),
                value.as_str().unwrap(),
                "{name}/{index}"
            );
        }
    }
}
#[test]
fn group_keys_require_authentication_wrap_integrity_and_correct_kde() {
    let temp = Temp::new();
    let output = temp.path("out.pcap");
    for name in [
        "decap-tkip-bad-michael",
        "decap-tkip-bad-icv",
        "decap-gtk-ccmp-missing",
        "decap-gtk-ccmp-wrong-nonce",
        "decap-gtk-ccmp-wrong-replay",
        "decap-gtk-ccmp-wrong-peer",
        "decap-gtk-wpa1-bad-mic",
        "decap-gtk-tkip-missing",
        "decap-gtk-wpa1-missing",
        "decap-gtk-ccmp-bad-mic",
        "decap-gtk-ccmp-bad-wrap",
        "decap-gtk-ccmp-bad-kde",
        "decap-gtk-tkip-bad-mic",
        "decap-gtk-tkip-bad-wrap",
        "decap-gtk-tkip-bad-kde",
    ] {
        let result = cli(
            &fixture(&format!("{name}.pcap")),
            &output,
            &["-e", "Test Network", "-p", "correct horse battery"],
        );
        assert!(!result.status.success(), "{name}");
        assert!(!output.exists(), "{name}");
    }
}
#[test]
fn group_keys_are_bound_to_ap_key_id_and_michael_covers_qos_priority() {
    let temp = Temp::new();
    let input = temp.path("mutated.pcap");
    let output = temp.path("out.pcap");
    for (name, offset) in [
        ("decap-gtk-ccmp.pcap", 29),
        ("decap-gtk-ccmp.pcap", 15),
        ("decap-gtk-tkip.pcap", 24),
    ] {
        let mut packets = read_pcap(fixture(name)).unwrap();
        let packet = packets.last_mut().unwrap();
        if offset == 29 {
            packet.data[29] ^= 0x40;
        } else {
            packet.data[offset] ^= 1;
        }
        std::fs::write(&input, pcap(&packets)).unwrap();
        let result = cli(
            &input,
            &output,
            &["-e", "Test Network", "-p", "correct horse battery"],
        );
        assert!(!result.status.success(), "{name}/{offset}");
        assert!(!output.exists());
    }
}
#[test]
fn v3_password_verification_and_akm_gating() {
    let temp = Temp::new();
    let input = temp.path("bad-akm.pcap");
    for name in ["wpa2-v3.pcap", "wpa2-v3-m2m3.pcap"] {
        for (words, success) in [("words.txt", true), ("wrong-words.txt", false)] {
            let result = Command::new(env!("CARGO_BIN_EXE_aircrack"))
                .args([
                    "aircrack",
                    "--capture",
                    fixture(name).to_str().unwrap(),
                    "--wordlist",
                    fixture(words).to_str().unwrap(),
                ])
                .output()
                .unwrap();
            assert_eq!(
                result.status.success(),
                success,
                "{name}: {}",
                String::from_utf8_lossy(&result.stderr)
            );
        }
    }
    let original = read_pcap(fixture("wpa2-v3.pcap")).unwrap();
    // Mutate the negotiated M2 RSN AKM to FT-PSK / SAE / enterprise; a v3
    // label must never silently choose a PSK KDF for these protocols.
    for akm in [1, 2, 4, 5, 8] {
        let mut packets = original.clone();
        packets[2].data[24 + 8 + 99 + 2 + 17] = akm;
        std::fs::write(&input, pcap(&packets)).unwrap();
        let result = Command::new(env!("CARGO_BIN_EXE_aircrack"))
            .args(["aircrack", "--capture", input.to_str().unwrap()])
            .output()
            .unwrap();
        assert!(!result.status.success());
    }
}

#[test]
fn multicast_msdu_to_ap_uses_pairwise_tkip_key() {
    let temp = Temp::new();
    let output = temp.path("multicast.pcap");
    let result = cli(
        &fixture("decap-tkip-to-ds-multicast.pcap"),
        &output,
        &["-e", "Test Network", "-p", "correct horse battery"],
    );
    assert!(
        result.status.success(),
        "{}",
        String::from_utf8_lossy(&result.stderr)
    );
    let packets = read_pcap(&output).unwrap();
    assert_eq!(packets.len(), 1);
    assert_eq!(&packets[0].data[..6], &[1, 0, 0x5e, 1, 2, 3]);
    assert_eq!(&packets[0].data[6..12], &[2, 0, 0, 0, 0, 2]);
}

fn roaming() -> serde_json::Value {
    serde_json::from_slice(&std::fs::read(fixture("roaming-vectors.json")).unwrap()).unwrap()
}
#[test]
fn ft_psk_sae_and_ft_sae_decrypt_with_the_right_key_provenance() {
    let temp = Temp::new();
    let v = roaming();
    let want = expected();
    let advanced: serde_json::Value =
        serde_json::from_slice(&std::fs::read(fixture("advanced-vectors.json")).unwrap()).unwrap();
    for (name, extra, count) in [
        (
            "decap-ft-psk",
            vec!["--essid", "Test Network", "--pass", "correct horse battery"],
            2,
        ),
        (
            "decap-ft-sae",
            vec![
                "--essid",
                "Test Network",
                "--pmk",
                v["sae_pmk"].as_str().unwrap(),
            ],
            2,
        ),
        (
            "decap-sae-pmk",
            vec!["--pmk", v["sae_pmk"].as_str().unwrap()],
            1,
        ),
        (
            "decap-sae-gtk",
            vec!["--pmk", v["sae_pmk"].as_str().unwrap()],
            1,
        ),
    ] {
        let output = temp.path(name);
        let result = cli(&fixture(&format!("{name}.pcap")), &output, &extra);
        assert!(
            result.status.success(),
            "{name}: {}",
            String::from_utf8_lossy(&result.stderr)
        );
        let packets = read_pcap(&output).unwrap();
        assert_eq!(packets.len(), count);
        for (i, p) in packets.iter().enumerate() {
            let value = if i == 1 || name == "decap-sae-gtk" {
                &advanced["group_ethernet"]
            } else {
                &want["ethernet_from_ap"]
            };
            assert_eq!(hex::encode(&p.data), value.as_str().unwrap(), "{name}/{i}");
        }
    }
}
#[test]
fn ft_signed_records_and_fragmented_eapol_can_verify_a_password() {
    for name in [
        "ft-psk",
        "ft-psk-request",
        "ft-psk-fragmented",
        "wpa2-fragmented-m2",
    ] {
        for (words, found) in [("words.txt", true), ("wrong-words.txt", false)] {
            let result = Command::new(env!("CARGO_BIN_EXE_aircrack"))
                .args([
                    "aircrack",
                    "--capture",
                    fixture(&format!("{name}.pcap")).to_str().unwrap(),
                    "--wordlist",
                    fixture(words).to_str().unwrap(),
                ])
                .output()
                .unwrap();
            assert_eq!(
                result.status.success(),
                found,
                "{name}: {}",
                String::from_utf8_lossy(&result.stderr)
            );
        }
    }
}
#[test]
fn sae_passphrases_are_never_used_as_pbkdf2_keys() {
    let temp = Temp::new();
    let output = temp.path("out");
    for name in ["decap-sae-pmk", "decap-ft-sae"] {
        let result = cli(
            &fixture(&format!("{name}.pcap")),
            &output,
            &["-e", "Test Network", "-p", "correct horse battery"],
        );
        assert!(!result.status.success());
        assert!(String::from_utf8_lossy(&result.stderr).contains("exported PMK"));
        assert!(!output.exists());
    }
    for name in ["sae-pmk", "ft-sae"] {
        for (words, found) in [("words.txt", false), ("sae-pmk-words.txt", true)] {
            let result = Command::new(env!("CARGO_BIN_EXE_aircrack"))
                .args([
                    "aircrack",
                    "--capture",
                    fixture(&format!("{name}.pcap")).to_str().unwrap(),
                    "--wordlist",
                    fixture(words).to_str().unwrap(),
                ])
                .output()
                .unwrap();
            assert_eq!(
                result.status.success(),
                found,
                "{name}: {}",
                String::from_utf8_lossy(&result.stderr)
            );
            if !found {
                assert!(String::from_utf8_lossy(&result.stderr).contains("exported PMK"));
            }
        }
    }
}
#[test]
fn fragments_are_authenticated_before_emitting_exact_msdu() {
    let temp = Temp::new();
    let want = expected();
    for name in [
        "decap-frag-open",
        "decap-frag-ccmp",
        "decap-frag-ccmp-reordered",
        "decap-frag-tkip",
        "decap-frag-wep",
    ] {
        let output = temp.path(name);
        let extra = if name.ends_with("wep") {
            vec!["--wep-key", "0102030405"]
        } else if name.ends_with("open") {
            vec![]
        } else {
            vec!["-e", "Test Network", "-p", "correct horse battery"]
        };
        let result = cli(&fixture(&format!("{name}.pcap")), &output, &extra);
        assert!(
            result.status.success(),
            "{name}: {}",
            String::from_utf8_lossy(&result.stderr)
        );
        let packets = read_pcap_records(&output, CaptureLimits::default()).unwrap();
        assert_eq!(packets.len(), 1);
        assert_eq!(
            hex::encode(&packets[0].packet.data),
            want["ethernet_from_ap"].as_str().unwrap()
        );
        assert!(String::from_utf8_lossy(&result.stdout).contains("reassembled=1"));
        if name == "decap-frag-ccmp-reordered" {
            assert_eq!(packets[0].timestamp.unwrap().as_secs(), 127);
        }
    }
}
#[test]
fn partial_conflicting_or_pn_mismatched_fragments_do_not_leak_partial_plaintext() {
    let temp = Temp::new();
    let output = temp.path("out");
    for name in [
        "decap-frag-ccmp-missing",
        "decap-frag-ccmp-bad-tag",
        "decap-frag-ccmp-expired",
        "decap-frag-tkip-bad-michael",
        "decap-frag-ccmp-pn-gap",
        "decap-frag-ccmp-conflict",
        "decap-ft-psk-bad-mic",
    ] {
        let result = cli(
            &fixture(&format!("{name}.pcap")),
            &output,
            &["-e", "Test Network", "-p", "correct horse battery"],
        );
        assert!(!result.status.success(), "{name}");
        assert!(!output.exists());
    }
}

#[test]
fn sae_provenance_is_enforced_even_if_a_pmk_coincides_with_pbkdf2_output() {
    let temp = Temp::new();
    let pmks = temp.path("keys.txt");
    std::fs::write(&pmks, format!("{}\n", expected()["pmk"].as_str().unwrap())).unwrap();
    for name in ["sae-pmk-provenance", "ft-sae-pmk-provenance"] {
        for (words, found) in [(fixture("words.txt"), false), (pmks.clone(), true)] {
            let result = Command::new(env!("CARGO_BIN_EXE_aircrack"))
                .args([
                    "aircrack",
                    "--capture",
                    fixture(&format!("{name}.pcap")).to_str().unwrap(),
                    "--wordlist",
                    words.to_str().unwrap(),
                ])
                .output()
                .unwrap();
            assert_eq!(
                result.status.success(),
                found,
                "{name}: {}",
                String::from_utf8_lossy(&result.stderr)
            );
        }
    }
}
#[test]
fn ft_hierarchy_matches_independent_vectors_and_binds_domain_holder_and_nonce() {
    let packets = read_pcap(fixture("ft-psk.pcap")).unwrap();
    let frame = air_capture::decode_packet(&packets[1]).unwrap();
    let session = air_handshake::ft::parse(&frame).unwrap();
    let key: [u8; 32] = hex::decode(expected()["pmk"].as_str().unwrap())
        .unwrap()
        .try_into()
        .unwrap();
    assert_eq!(
        hex::encode(&session.verified_ptk(&key, b"Test Network").unwrap()[..48]),
        roaming()["ft_ptk"].as_str().unwrap()
    );
    let mut bad = session.clone();
    bad.mdid[0] ^= 1;
    assert!(bad.verified_ptk(&key, b"Test Network").is_none());
    let mut bad = session.clone();
    bad.r1kh[0] ^= 1;
    assert!(bad.verified_ptk(&key, b"Test Network").is_none());
    let mut bad = session.clone();
    bad.anonce[0] ^= 1;
    assert!(bad.verified_ptk(&key, b"Test Network").is_none());
    let mut bad = session;
    bad.bssid[5] ^= 1;
    assert!(bad.verified_ptk(&key, b"Test Network").is_none());
}

#[test]
fn resume_identity_includes_timestamps_used_by_fragment_expiry() {
    let temp = Temp::new();
    let capture = temp.path("capture.pcap");
    let session = temp.path("checkpoint.json");
    let words = fixture("words.txt");
    let bytes = std::fs::read(fixture("wpa2-raw.pcap")).unwrap();
    std::fs::write(&capture, &bytes).unwrap();
    let base = [
        "aircrack",
        "--capture",
        capture.to_str().unwrap(),
        "--wordlist",
        words.to_str().unwrap(),
    ];
    let first = Command::new(env!("CARGO_BIN_EXE_aircrack"))
        .args(base)
        .args([
            "--session",
            session.to_str().unwrap(),
            "--max-candidates",
            "1",
        ])
        .output()
        .unwrap();
    assert!(!first.status.success());
    assert!(session.exists());
    let mut changed = bytes;
    changed[24] ^= 1;
    std::fs::write(&capture, changed).unwrap();
    let result = Command::new(env!("CARGO_BIN_EXE_aircrack"))
        .args(base)
        .args(["--resume", session.to_str().unwrap()])
        .output()
        .unwrap();
    assert!(!result.status.success());
    assert!(String::from_utf8_lossy(&result.stderr).contains("input mismatch"));
}

#[test]
fn fragmented_simple_packet_blocks_keep_unknown_timestamps_explicit() {
    let temp = Temp::new();
    let output = temp.path("out.pcap");
    let result = cli(
        &fixture("decap-frag-ccmp-spb.pcapng"),
        &output,
        &["-e", "Test Network", "-p", "correct horse battery"],
    );
    assert!(
        result.status.success(),
        "{}",
        String::from_utf8_lossy(&result.stderr)
    );
    let packets = read_pcap_records(&output, CaptureLimits::default()).unwrap();
    assert_eq!(packets.len(), 1);
    assert_eq!(packets[0].timestamp, Some(Duration::ZERO));
    assert_eq!(
        hex::encode(&packets[0].packet.data),
        expected()["ethernet_from_ap"].as_str().unwrap()
    );
    assert!(String::from_utf8_lossy(&result.stdout).contains("missing-timestamps=1"));
}

#[test]
fn airdecap_diagnostic_reports_success_counts_without_secrets() {
    let temp = Temp::new();
    let output = temp.path("out.pcap");
    let diag = temp.path("diag.json");
    let result = cli(
        &fixture("decap-open.pcap"),
        &output,
        &["--diagnostic-json", diag.to_str().unwrap()],
    );
    assert!(
        result.status.success(),
        "{}",
        String::from_utf8_lossy(&result.stderr)
    );
    assert_eq!(result.status.code(), Some(0));
    let v: serde_json::Value = serde_json::from_slice(&std::fs::read(&diag).unwrap()).unwrap();
    assert_eq!(v["schema_version"], 1);
    assert_eq!(v["kind"], "airdecap_diagnostic");
    assert_eq!(v["exit_category"], "success");
    assert_eq!(v["exit_code"], 0);
    assert!(v["error"].is_null());
    assert_eq!(v["counts"]["data_frames"], 1);
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        assert_eq!(
            std::fs::metadata(&diag).unwrap().permissions().mode() & 0o777,
            0o600
        );
    }
}

#[test]
fn airdecap_diagnostic_records_bad_container_and_exit_code() {
    let temp = Temp::new();
    let output = temp.path("out.pcap");
    let diag = temp.path("diag.json");
    let result = cli(
        &fixture("wpa2-ethernet.pcap"),
        &output,
        &["--diagnostic-json", diag.to_str().unwrap()],
    );
    assert_eq!(result.status.code(), Some(4));
    assert!(!output.exists());
    let v: serde_json::Value = serde_json::from_slice(&std::fs::read(&diag).unwrap()).unwrap();
    assert_eq!(v["exit_category"], "bad_container");
    assert_eq!(v["exit_code"], 4);
    assert!(v["error"].as_str().unwrap().contains("raw 802.11"));
}

#[test]
fn airdecap_diagnostic_refuses_to_overwrite_existing_path() {
    let temp = Temp::new();
    let output = temp.path("out.pcap");
    let diag = temp.path("exists.json");
    std::fs::write(&diag, b"keep").unwrap();
    let result = cli(
        &fixture("decap-open.pcap"),
        &output,
        &["--diagnostic-json", diag.to_str().unwrap()],
    );
    assert_eq!(result.status.code(), Some(64));
    assert_eq!(std::fs::read(&diag).unwrap(), b"keep");
}

#[test]
fn aircrack_diagnostic_reports_success_without_leaking_password() {
    let temp = Temp::new();
    let diag = temp.path("diag.json");
    let result = aircrack(&[
        "--capture",
        fixture("wpa2-v3.pcap").to_str().unwrap(),
        "--wordlist",
        fixture("words.txt").to_str().unwrap(),
        "--diagnostic-json",
        diag.to_str().unwrap(),
    ]);
    assert!(
        result.status.success(),
        "{}",
        String::from_utf8_lossy(&result.stderr)
    );
    let raw = std::fs::read_to_string(&diag).unwrap();
    let v: serde_json::Value = serde_json::from_str(&raw).unwrap();
    assert_eq!(v["schema_version"], 1);
    assert_eq!(v["kind"], "aircrack_diagnostic");
    assert_eq!(v["exit_category"], "success");
    assert_eq!(v["exit_code"], 0);
    assert!(v["error"].is_null());
    assert!(v["counts"]["networks"].as_u64().unwrap() >= 1);
    assert!(
        v["counts"]["handshake_sessions"].as_u64().unwrap()
            + v["counts"]["pmkid_targets"].as_u64().unwrap()
            >= 1
    );
    // The found passphrase is printed to stdout but must never reach the
    // machine diagnostic.
    assert!(
        !raw.contains("horse"),
        "diagnostic must not contain the password: {raw}"
    );
}

#[test]
fn aircrack_diagnostic_marks_password_not_found() {
    let temp = Temp::new();
    let diag = temp.path("diag.json");
    let result = aircrack(&[
        "--capture",
        fixture("wpa2-v3.pcap").to_str().unwrap(),
        "--wordlist",
        fixture("wrong-words.txt").to_str().unwrap(),
        "--diagnostic-json",
        diag.to_str().unwrap(),
    ]);
    assert_eq!(result.status.code(), Some(2));
    let v: serde_json::Value = serde_json::from_slice(&std::fs::read(&diag).unwrap()).unwrap();
    assert_eq!(v["exit_category"], "password_not_found");
    assert_eq!(v["exit_code"], 2);
    assert!(v["error"].as_str().unwrap().contains("password not found"));
}

#[test]
fn aircrack_diagnostic_marks_no_supported_target() {
    let temp = Temp::new();
    let diag = temp.path("diag.json");
    let result = aircrack(&[
        "--capture",
        fixture("decap-open.pcap").to_str().unwrap(),
        "--diagnostic-json",
        diag.to_str().unwrap(),
    ]);
    assert_eq!(result.status.code(), Some(3));
    let v: serde_json::Value = serde_json::from_slice(&std::fs::read(&diag).unwrap()).unwrap();
    assert_eq!(v["exit_category"], "no_supported_target");
    assert_eq!(v["exit_code"], 3);
}
