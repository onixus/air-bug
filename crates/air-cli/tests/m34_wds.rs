use air_capture::{read_pcap_records, CaptureLimits, FrameDecoder};
use std::path::{Path, PathBuf};
use std::process::{Command, Output};
use std::sync::atomic::{AtomicUsize, Ordering};
struct Temp(PathBuf);
impl Temp {
    fn new() -> Self {
        static NEXT: AtomicUsize = AtomicUsize::new(0);
        let path = std::env::temp_dir().join(format!(
            "air-m34-wds-{}-{}",
            std::process::id(),
            NEXT.fetch_add(1, Ordering::Relaxed)
        ));
        std::fs::create_dir(&path).unwrap();
        Self(path)
    }
    fn file(&self, name: &str) -> PathBuf {
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
        .join(format!("{name}.pcap"))
}
fn cli() -> Command {
    Command::new(env!("CARGO_BIN_EXE_aircrack"))
}
fn success(output: &Output) {
    assert!(
        output.status.success(),
        "{}\n{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
}
fn crack(path: &Path) -> Output {
    cli()
        .args(["aircrack", "--capture"])
        .arg(path)
        .args(["--essid", "Test Network", "--wordlist"])
        .arg(fixture("words").with_extension("txt"))
        .output()
        .unwrap()
}
fn frames(name: &str) -> Vec<air_frames::Dot11Frame> {
    let mut decoder = FrameDecoder::default();
    read_pcap_records(fixture(name), CaptureLimits::default())
        .unwrap()
        .iter()
        .filter_map(|r| {
            decoder
                .decode(&r.packet, r.timestamp.unwrap_or_default())
                .ok()
                .flatten()
        })
        .collect()
}
#[test]
fn m34_verifies_only_consistent_nonce_counter_descriptor_and_peer_context() {
    for name in [
        "wpa2-m3m4",
        "wpa2-m3m4-reordered",
        "wpa1-m3m4",
        "wpa2-m234-zero",
        "wpa2-m234-zero-padded",
        "wpa2-v3-m234-zero",
        "wds-m3m4",
    ] {
        success(&crack(&fixture(name)));
    }
    for name in [
        "wpa2-m3m4-zero",
        "wpa2-m3m4-bad-mic",
        "wpa2-m3m4-replay-mismatch",
        "wpa2-m3m4-peer-mismatch",
        "wpa2-m3m4-version-mismatch",
        "wpa2-v3-m3m4-no-context",
    ] {
        assert!(!crack(&fixture(name)).status.success(), "{name}");
    }
    let input = frames("wpa2-m3m4");
    assert!(air_handshake::extract_targets_limited(&input, 1, 1024).is_err());
    assert!(air_handshake::extract_targets_limited(&input, 1024, 0).is_err());
    let mut session = air_handshake::extract(&frames("wpa2-m234-zero"))
        .pop()
        .unwrap();
    assert!(session.nonce_source.is_some());
    session.nonce_source.as_mut().unwrap()[9] ^= 1;
    assert!(air_crack::Engine::new(session, b"Test Network".to_vec()).is_err());
}
#[test]
fn wds_addresses_qos_and_truncation_are_distinct_from_radio_endpoints() {
    let input = frames("wds-m3m4");
    assert_eq!(input[1].addr4, Some([2, 0, 0, 0, 0, 4]));
    assert_eq!(
        input[1].endpoints(),
        Some(([2, 0, 0, 0, 0, 1], [2, 0, 0, 0, 0, 2], true))
    );
    let records = read_pcap_records(fixture("decap-wds-ccmp"), CaptureLimits::default()).unwrap();
    let raw = &records[3].packet.data;
    assert_eq!(air_frames::wire_header_len(raw).unwrap(), 32);
    assert_eq!(air_frames::qos_tid(raw), Some(5));
    assert_eq!(
        air_frames::data_addresses(raw),
        Some(([2, 0, 0, 0, 0, 3], [2, 0, 0, 0, 0, 4]))
    );
    assert!(air_frames::wire_header_len(&raw[..29]).is_err());
    assert!(air_frames::wire_header_len(&raw[..31]).is_err());
    let mut aggregate = raw.clone();
    aggregate[30] |= 0x80;
    assert!(air_frames::wire_header_len(&aggregate).is_err());
}
#[test]
fn wds_decryption_preserves_bridged_addresses_in_both_directions() {
    let temp = Temp::new();
    let expected: serde_json::Value = serde_json::from_slice(
        &std::fs::read(fixture("m34-wds-expected").with_extension("json")).unwrap(),
    )
    .unwrap();
    let known: Vec<Vec<u8>> = expected["ethernet"]
        .as_array()
        .unwrap()
        .iter()
        .map(|v| hex::decode(v.as_str().unwrap()).unwrap())
        .collect();
    for (name, count) in [
        ("decap-wds-ccmp", 3),
        ("decap-wds-radiotap", 3),
        ("decap-wds-m3m4", 3),
        ("decap-wds-tkip", 2),
        ("decap-wds-tkip-fragments", 1),
        ("decap-wds-fragments", 1),
        ("decap-wds-open", 2),
        ("decap-wds-wep", 2),
    ] {
        let out = temp.file(name);
        let mut command = cli();
        command
            .args(["airdecap", "-i"])
            .arg(fixture(name))
            .arg("-o")
            .arg(&out);
        if name.ends_with("wep") {
            command.args(["-w", "0102030405"]);
        } else if !name.ends_with("open") {
            command.args(["-e", "Test Network", "-p", "correct horse battery"]);
        }
        success(&command.output().unwrap());
        let packets = read_pcap_records(&out, CaptureLimits::default()).unwrap();
        assert_eq!(packets.len(), count, "{name}");
        for (i, p) in packets.iter().enumerate() {
            assert_eq!(p.packet.data, known[i], "{name} packet {i}");
        }
    }
    let out = temp.file("raw");
    success(
        &cli()
            .args(["airdecap", "-i"])
            .arg(fixture("decap-wds-ccmp"))
            .arg("-o")
            .arg(&out)
            .args(["-l", "-e", "Test Network", "-p", "correct horse battery"])
            .output()
            .unwrap(),
    );
    let packets = read_pcap_records(&out, CaptureLimits::default()).unwrap();
    assert_eq!(packets[0].packet.dlt, 105);
    assert_eq!(&packets[0].packet.data[24..30], &[2, 0, 0, 0, 0, 4]);
    assert_eq!(packets[0].packet.data[1] & 0x40, 0);
}
#[test]
fn wds_rejects_changed_aad_unknown_peer_and_fragment_address_mix() {
    let temp = Temp::new();
    for name in [
        "decap-wds-bad-addr4",
        "decap-wds-wrong-peer",
        "decap-wds-fragments-address-mix",
        "decap-wds-tkip-bad-michael",
    ] {
        let out = temp.file(name);
        let result = cli()
            .args(["airdecap", "-i"])
            .arg(fixture(name))
            .arg("-o")
            .arg(&out)
            .args(["-e", "Test Network", "-p", "correct horse battery"])
            .output()
            .unwrap();
        assert!(!result.status.success(), "{name}");
        assert!(!out.exists());
    }
}
#[test]
fn cleaner_preserves_m34_and_nonce_source_including_wds() {
    let temp = Temp::new();
    for name in [
        "wpa2-m3m4",
        "wpa2-m234-zero",
        "wpa2-m234-zero-padded",
        "wpa2-v3-m234-zero",
        "wds-m3m4",
    ] {
        let out = temp.file(name);
        success(
            &cli()
                .args(["wpaclean", "-i"])
                .arg(fixture(name))
                .arg("-o")
                .arg(&out)
                .output()
                .unwrap(),
        );
        success(&crack(&out));
    }
}
#[test]
fn survey_marks_usable_m34_and_exports_compatible_column_positions() {
    let temp = Temp::new();
    for (name, usable) in [
        ("wpa2-m3m4", true),
        ("wpa2-m234-zero", true),
        ("wds-m3m4", true),
        ("wpa2-m3m4-zero", false),
    ] {
        let out = temp.file(name);
        let csv = temp.file(&format!("{name}.csv"));
        success(
            &cli()
                .args(["survey", "--read"])
                .arg(fixture(name))
                .arg("--export-json")
                .arg(&out)
                .arg("--export-csv")
                .arg(&csv)
                .output()
                .unwrap(),
        );
        let json: serde_json::Value =
            serde_json::from_slice(&std::fs::read(&out).unwrap()).unwrap();
        assert_eq!(json["access_points"][0]["handshake_m3m4"], usable, "{name}");
        let text = std::fs::read_to_string(csv).unwrap();
        assert!(text
            .lines()
            .next()
            .unwrap()
            .contains(",ft,handshake_m3m4,audit_status"));
    }
}

#[test]
fn sae_m4_nonce_context_cannot_bypass_exported_pmk_requirement() {
    assert!(!crack(&fixture("sae-m234-provenance")).status.success());
    success(
        &cli()
            .args(["aircrack", "--capture"])
            .arg(fixture("sae-m234-provenance"))
            .args(["-e", "Test Network", "--wordlist"])
            .arg(fixture("m34-pmk-words").with_extension("txt"))
            .output()
            .unwrap(),
    );
    let temp = Temp::new();
    let out = temp.file("clean");
    success(
        &cli()
            .args(["wpaclean", "-i"])
            .arg(fixture("sae-m234-provenance"))
            .arg("-o")
            .arg(&out)
            .output()
            .unwrap(),
    );
    assert!(!crack(&out).status.success());
}
