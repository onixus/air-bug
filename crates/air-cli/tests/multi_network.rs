use air_capture::{read_pcap_records, CaptureLimits, PacketRecord};
use serde_json::Value;
use std::{
    path::{Path, PathBuf},
    process::{Command, Output},
    sync::atomic::{AtomicUsize, Ordering},
};
struct Temp(PathBuf);
impl Temp {
    fn new() -> Self {
        static NEXT: AtomicUsize = AtomicUsize::new(0);
        let p = std::env::temp_dir().join(format!(
            "air-multi-{}-{}",
            std::process::id(),
            NEXT.fetch_add(1, Ordering::Relaxed)
        ));
        std::fs::create_dir(&p).unwrap();
        Self(p)
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
        .join(name)
}
fn captures() -> Vec<PathBuf> {
    (1..=4)
        .map(|i| fixture(&format!("multi-network-{i}.pcap")))
        .collect()
}
fn words() -> Vec<PathBuf> {
    [
        "multi-words-1.txt",
        "multi-words-empty.txt",
        "multi-words-2.txt",
    ]
    .into_iter()
    .map(fixture)
    .collect()
}
fn command(caps: &[PathBuf], words: &[PathBuf], out: &Path) -> Command {
    let mut command = Command::new(env!("CARGO_BIN_EXE_aircrack"));
    command.arg("aircrack");
    for cap in caps {
        command.arg("--capture").arg(cap);
    }
    for path in words {
        command.arg("--wordlist").arg(path);
    }
    command
        .arg("--results-json")
        .arg(out)
        .args(["--threads", "2"]);
    command
}
fn success(out: &Output) {
    assert!(
        out.status.success(),
        "stdout={} stderr={}",
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr)
    );
}
fn json(path: &Path) -> Value {
    serde_json::from_slice(&std::fs::read(path).unwrap()).unwrap()
}
fn check_all(data: &Value) {
    let expected = json(&fixture("multi-networks-expected.json"));
    assert_eq!(data["status"], "complete");
    assert_eq!(data["completed_lines"], 4);
    let rows = data["networks"].as_array().unwrap();
    assert_eq!(rows.len(), 4);
    for (got, want) in rows.iter().zip(expected["networks"].as_array().unwrap()) {
        assert_eq!(got["bssid"], want["bssid"]);
        assert_eq!(got["ssid_hex"], want["ssid_hex"]);
        assert_eq!(got["candidate"], want["candidate"]);
        assert_eq!(got["status"], "found");
    }
    assert_eq!(rows[0]["found_at"]["global_line"], 2);
    assert_eq!(rows[1]["found_at"]["global_line"], 2);
    assert_eq!(rows[2]["found_at"]["dictionary_index"], 2);
    assert_eq!(rows[2]["found_at"]["line"], 1);
    assert_eq!(rows[3]["found_at"]["global_line"], 4);
}
#[test]
fn ordered_inputs_share_pmk_per_ssid_and_report_every_bssid() {
    let temp = Temp::new();
    let out = temp.file("results.json");
    let cache = temp.file("keys.pmk-cache");
    let first = command(&captures(), &words(), &out)
        .arg("--pmk-cache")
        .arg(&cache)
        .args(["--pmk-cache-mib", "1"])
        .output()
        .unwrap();
    success(&first);
    check_all(&json(&out));
    assert!(String::from_utf8_lossy(&first.stderr).contains("derived=8"));
    let second = temp.file("again.json");
    let hit = command(&captures(), &words(), &second)
        .arg("--pmk-cache")
        .arg(&cache)
        .args(["--pmk-cache-mib", "1"])
        .output()
        .unwrap();
    success(&hit);
    check_all(&json(&second));
    assert!(String::from_utf8_lossy(&hit.stderr).contains("hits=8 misses=0 derived=0"));
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        assert_eq!(
            std::fs::metadata(out).unwrap().permissions().mode() & 0o777,
            0o600
        );
    }
}
#[test]
fn common_checkpoint_restores_found_positions_without_storing_credentials() {
    let temp = Temp::new();
    let checkpoint = temp.file("session");
    let out = temp.file("paused.json");
    let paused = command(&captures(), &words(), &out)
        .arg("--session")
        .arg(&checkpoint)
        .args(["--max-candidates", "2"])
        .output()
        .unwrap();
    assert!(!paused.status.success());
    let data = json(&out);
    assert_eq!(data["status"], "paused");
    assert_eq!(data["networks"][0]["status"], "found");
    assert_eq!(data["networks"][3]["status"], "pending");
    let state = json(&checkpoint);
    assert_eq!(state["version"], 6);
    assert_eq!(state["completed_lines"], 2);
    assert_eq!(state["found"][0]["global_line"], 2);
    let raw = std::fs::read_to_string(&checkpoint).unwrap();
    for pass in [
        "first shared password",
        "second different password",
        "other shared password",
    ] {
        assert!(!raw.contains(pass));
    }
    let resumed = temp.file("resumed.json");
    success(
        &command(&captures(), &words(), &resumed)
            .arg("--resume")
            .arg(&checkpoint)
            .output()
            .unwrap(),
    );
    check_all(&json(&resumed));
    let complete = std::fs::read(&checkpoint).unwrap();
    let repeat = temp.file("repeat.json");
    success(
        &command(&captures(), &words(), &repeat)
            .arg("--resume")
            .arg(&checkpoint)
            .output()
            .unwrap(),
    );
    check_all(&json(&repeat));
    assert_eq!(std::fs::read(checkpoint).unwrap(), complete);
}
#[test]
fn resume_binds_capture_dictionary_order_and_contents_and_selected_networks() {
    let temp = Temp::new();
    let checkpoint = temp.file("session");
    let words = words();
    let caps = captures();
    assert!(!command(&caps, &words, &temp.file("paused"))
        .arg("--session")
        .arg(&checkpoint)
        .args(["--max-candidates", "1"])
        .output()
        .unwrap()
        .status
        .success());
    let original = std::fs::read(&checkpoint).unwrap();
    let mut reversed = caps.clone();
    reversed.reverse();
    let mut reordered = words.clone();
    reordered.swap(0, 2);
    for (i, (caps, words)) in [(reversed, words.clone()), (caps.clone(), reordered)]
        .into_iter()
        .enumerate()
    {
        let out = temp.file(&format!("rejected{i}"));
        let run = command(&caps, &words, &out)
            .arg("--resume")
            .arg(&checkpoint)
            .output()
            .unwrap();
        assert!(!run.status.success());
        assert!(String::from_utf8_lossy(&run.stderr).contains("input mismatch"));
        assert!(!out.exists());
    }
    let mut changed = caps.clone();
    let copy = temp.file("changed.pcap");
    let mut packets = read_pcap_records(&caps[0], CaptureLimits::default()).unwrap();
    packets[1].packet.data[49] ^= 1;
    write_pcap(&copy, &packets);
    changed[0] = copy;
    let run = command(&changed, &words, &temp.file("changed-out"))
        .arg("--resume")
        .arg(&checkpoint)
        .output()
        .unwrap();
    assert!(!run.status.success());
    assert!(String::from_utf8_lossy(&run.stderr).contains("input mismatch"));
    let run = command(&caps, &words, &temp.file("selected-out"))
        .arg("--resume")
        .arg(&checkpoint)
        .args(["--bssid", "02:00:00:10:00:01"])
        .output()
        .unwrap();
    assert!(!run.status.success());
    assert!(String::from_utf8_lossy(&run.stderr).contains("input mismatch"));
    assert_eq!(std::fs::read(checkpoint).unwrap(), original);
}
fn write_pcap(path: &Path, records: &[PacketRecord]) {
    use std::io::Write;
    let mut file = std::io::BufWriter::new(std::fs::File::create(path).unwrap());
    file.write_all(&[0x4d, 0x3c, 0xb2, 0xa1, 2, 0, 4, 0])
        .unwrap();
    for n in [0u32, 0, 65535, 105] {
        file.write_all(&n.to_le_bytes()).unwrap();
    }
    for r in records {
        let t = r.timestamp.unwrap_or_default();
        for n in [
            t.as_secs() as u32,
            t.subsec_nanos(),
            r.packet.data.len() as u32,
            r.original_len,
        ] {
            file.write_all(&n.to_le_bytes()).unwrap();
        }
        file.write_all(&r.packet.data).unwrap();
    }
    file.flush().unwrap();
}
#[test]
fn selected_bssid_and_ssid_are_filtered_before_evidence_budget() {
    let temp = Temp::new();
    let source = fixture("multi-networks.pcap");
    let mut records = read_pcap_records(&source, CaptureLimits::default()).unwrap();
    for i in 0..100u64 {
        let mut noise =
            read_pcap_records(fixture("multi-network-3.pcap"), CaptureLimits::default())
                .unwrap()
                .pop()
                .unwrap();
        noise.packet.data[41..49].copy_from_slice(&i.to_be_bytes());
        records.push(noise);
    }
    let input = temp.file("noise.pcap");
    write_pcap(&input, &records);
    let selected = temp.file("one.json");
    success(
        &command(std::slice::from_ref(&input), &words(), &selected)
            .args(["--bssid", "02:00:00:10:00:01", "--max-records", "1"])
            .output()
            .unwrap(),
    );
    assert_eq!(json(&selected)["networks"].as_array().unwrap().len(), 1);
    let shared = temp.file("shared.json");
    success(
        &command(std::slice::from_ref(&input), &words(), &shared)
            .args(["--essid", "Shared Network", "--max-records", "3"])
            .output()
            .unwrap(),
    );
    assert_eq!(json(&shared)["networks"].as_array().unwrap().len(), 3);
    let rejected = temp.file("rejected.json");
    assert!(!command(&[input], &words(), &rejected)
        .args(["--max-records", "3"])
        .output()
        .unwrap()
        .status
        .success());
    assert!(!rejected.exists());
}
#[test]
fn hidden_octet_ssids_require_an_explicit_mapping() {
    let temp = Temp::new();
    let capture = vec![fixture("multi-hidden.pcap")];
    let words = vec![fixture("multi-words-1.txt")];
    let out = temp.file("hidden.json");
    let missing = command(&capture, &words, &out).output().unwrap();
    assert!(!missing.status.success());
    assert!(String::from_utf8_lossy(&missing.stderr).contains("SSID is missing or hidden"));
    assert!(!out.exists());
    success(
        &command(&capture, &words, &out)
            .arg("--ssid-map")
            .arg(fixture("multi-ssid-map.json"))
            .output()
            .unwrap(),
    );
    let got = json(&out);
    let expected = json(&fixture("multi-networks-expected.json"));
    assert_eq!(
        got["networks"][0]["ssid_hex"],
        expected["hidden"]["ssid_hex"]
    );
    assert_eq!(
        got["networks"][0]["candidate"],
        expected["hidden"]["candidate"]
    );
}
#[test]
fn exhausted_partial_results_resume_without_losing_found_networks() {
    let temp = Temp::new();
    let checkpoint = temp.file("session");
    let words = vec![fixture("multi-words-1.txt")];
    let out = temp.file("partial");
    let result = command(&captures(), &words, &out)
        .arg("--session")
        .arg(&checkpoint)
        .output()
        .unwrap();
    assert!(!result.status.success());
    assert!(String::from_utf8_lossy(&result.stderr).contains("matched 2/4"));
    assert_eq!(json(&out)["status"], "exhausted");
    assert_eq!(json(&out)["networks"][2]["status"], "not_found");
    let original = std::fs::read(&checkpoint).unwrap();
    let repeated = temp.file("repeated");
    assert!(!command(&captures(), &words, &repeated)
        .arg("--resume")
        .arg(&checkpoint)
        .output()
        .unwrap()
        .status
        .success());
    assert_eq!(
        json(&repeated)["networks"][0]["candidate"],
        "first shared password"
    );
    assert_eq!(std::fs::read(checkpoint).unwrap(), original);
}
#[test]
fn later_dictionary_errors_leave_checkpoint_and_output_unchanged() {
    let temp = Temp::new();
    let first = temp.file("first");
    let bad = temp.file("bad");
    std::fs::write(&first, b"first shared password\n").unwrap();
    std::fs::write(&bad, [0xff, b'\n']).unwrap();
    let words = vec![first, bad];
    let checkpoint = temp.file("session");
    assert!(!command(&captures(), &words, &temp.file("paused"))
        .arg("--session")
        .arg(&checkpoint)
        .args(["--max-candidates", "1"])
        .output()
        .unwrap()
        .status
        .success());
    let original = std::fs::read(&checkpoint).unwrap();
    let rejected = temp.file("rejected");
    let result = command(&captures(), &words, &rejected)
        .arg("--resume")
        .arg(&checkpoint)
        .output()
        .unwrap();
    assert!(!result.status.success());
    assert!(String::from_utf8_lossy(&result.stderr).contains("cannot read wordlist"));
    assert!(!rejected.exists());
    assert_eq!(std::fs::read(checkpoint).unwrap(), original);
}
#[test]
fn sae_provenance_is_preserved_while_other_ssid_groups_progress() {
    let temp = Temp::new();
    let words = temp.file("words");
    let raw = std::fs::read_to_string(fixture("m34-pmk-words.txt")).unwrap();
    std::fs::write(
        &words,
        format!("first shared password\ncorrect horse battery\n{raw}"),
    )
    .unwrap();
    let caps = vec![
        fixture("multi-network-1.pcap"),
        fixture("sae-pmk-provenance.pcap"),
    ];
    let checkpoint = temp.file("session");
    let paused = temp.file("paused");
    let cache = temp.file("keys.pmk-cache");
    let result = command(&caps, std::slice::from_ref(&words), &paused)
        .arg("--session")
        .arg(&checkpoint)
        .args(["--max-candidates", "2", "--pmk-cache"])
        .arg(&cache)
        .args(["--pmk-cache-mib", "1"])
        .output()
        .unwrap();
    assert!(!result.status.success());
    let data = json(&paused);
    assert_eq!(data["networks"][0]["requires_exported_pmk"], true);
    assert_eq!(data["networks"][0]["status"], "pending");
    assert!(String::from_utf8_lossy(&result.stderr).contains("derived=2"));
    let done = temp.file("done");
    success(
        &command(&caps, &[words], &done)
            .arg("--resume")
            .arg(&checkpoint)
            .arg("--pmk-cache")
            .arg(&cache)
            .args(["--pmk-cache-mib", "1"])
            .output()
            .unwrap(),
    );
    assert_eq!(json(&done)["networks"][0]["candidate"], raw.trim());
}
#[test]
fn handshakes_can_span_inputs_but_fragment_chains_cannot() {
    let temp = Temp::new();
    let original =
        read_pcap_records(fixture("wpa2-m1m2-compat.pcap"), CaptureLimits::default()).unwrap();
    let first = temp.file("first.pcap");
    let second = temp.file("second.pcap");
    write_pcap(&first, &original[..2]);
    write_pcap(&second, &original[2..]);
    success(
        &command(
            &[first.clone(), second.clone()],
            &[fixture("words.txt")],
            &temp.file("result"),
        )
        .output()
        .unwrap(),
    );
    let fragments =
        read_pcap_records(fixture("wpa2-fragmented-m2.pcap"), CaptureLimits::default()).unwrap();
    write_pcap(&first, &fragments[..3]);
    write_pcap(&second, &fragments[3..]);
    let out = temp.file("fragments");
    let result = command(&[first, second], &[fixture("words.txt")], &out)
        .output()
        .unwrap();
    assert!(!result.status.success());
    assert!(String::from_utf8_lossy(&result.stderr).contains("no complete"));
    assert!(!out.exists());
}

#[test]
fn outputs_and_checkpoint_locks_are_exclusive_and_failures_do_not_overwrite() {
    let temp = Temp::new();
    let out = temp.file("results");
    std::fs::write(&out, b"keep").unwrap();
    assert!(!command(&captures(), &words(), &out)
        .output()
        .unwrap()
        .status
        .success());
    assert_eq!(std::fs::read(&out).unwrap(), b"keep");
    let checkpoint = temp.file("session");
    assert!(!command(&captures(), &words(), &temp.file("paused"))
        .arg("--session")
        .arg(&checkpoint)
        .args(["--max-candidates", "1"])
        .output()
        .unwrap()
        .status
        .success());
    let original = std::fs::read(&checkpoint).unwrap();
    let lock = PathBuf::from(format!("{}.lock", checkpoint.display()));
    std::fs::write(&lock, b"external lock").unwrap();
    let rejected = temp.file("locked");
    let run = command(&captures(), &words(), &rejected)
        .arg("--resume")
        .arg(&checkpoint)
        .output()
        .unwrap();
    assert!(!run.status.success());
    assert!(String::from_utf8_lossy(&run.stderr).contains("session is locked"));
    assert!(!rejected.exists());
    assert_eq!(std::fs::read(&lock).unwrap(), b"external lock");
    std::fs::remove_file(lock).unwrap();
    assert_eq!(std::fs::read(checkpoint).unwrap(), original);
}
#[test]
fn input_count_and_packet_work_budgets_are_global() {
    let temp = Temp::new();
    let out = temp.file("limited");
    let run = command(&captures(), &words(), &out)
        .args(["--max-packets", "7"])
        .output()
        .unwrap();
    assert!(!run.status.success());
    assert!(String::from_utf8_lossy(&run.stderr).contains("packet limit"));
    assert!(!out.exists());
    let many = vec![fixture("multi-network-1.pcap"); 65];
    let run = command(&many, &words(), &out).output().unwrap();
    assert!(!run.status.success());
    assert!(String::from_utf8_lossy(&run.stderr).contains("at most 64 captures"));
    let run = command(
        &captures(),
        &[PathBuf::from("-"), fixture("multi-words-1.txt")],
        &out,
    )
    .output()
    .unwrap();
    assert!(!run.status.success());
    assert!(String::from_utf8_lossy(&run.stderr).contains("stdin must be the only dictionary"));
    assert!(!out.exists());
    use std::io::Write;
    use std::process::Stdio;
    let live = temp.file("stdin.json");
    let mut child = command(&captures(), &[PathBuf::from("-")], &live)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    child
        .stdin
        .take()
        .unwrap()
        .write_all(b"first shared password\nsecond different password\nother shared password\n")
        .unwrap();
    success(&child.wait_with_output().unwrap());
    assert!(json(&live)["networks"]
        .as_array()
        .unwrap()
        .iter()
        .all(|row| row["status"] == "found"));
}
#[test]
fn dictionary_edits_and_forged_match_positions_are_rejected_on_resume() {
    let temp = Temp::new();
    let first = temp.file("words");
    std::fs::copy(fixture("multi-words-1.txt"), &first).unwrap();
    let mut paths = words();
    paths[0] = first.clone();
    let checkpoint = temp.file("session");
    assert!(!command(&captures(), &paths, &temp.file("paused"))
        .arg("--session")
        .arg(&checkpoint)
        .args(["--max-candidates", "2"])
        .output()
        .unwrap()
        .status
        .success());
    let original = std::fs::read(&checkpoint).unwrap();
    std::fs::write(&first, b"changed dictionary\nfirst shared password").unwrap();
    let run = command(&captures(), &paths, &temp.file("edited"))
        .arg("--resume")
        .arg(&checkpoint)
        .output()
        .unwrap();
    assert!(!run.status.success());
    assert!(String::from_utf8_lossy(&run.stderr).contains("input mismatch"));
    std::fs::copy(fixture("multi-words-1.txt"), first).unwrap();
    let mut forged: Value = serde_json::from_slice(&original).unwrap();
    forged["found"][0]["global_line"] = Value::from(1);
    forged["found"][0]["position"]["line"] = Value::from(1);
    std::fs::write(&checkpoint, serde_json::to_vec(&forged).unwrap()).unwrap();
    let rejected = temp.file("forged");
    let run = command(&captures(), &paths, &rejected)
        .arg("--resume")
        .arg(&checkpoint)
        .output()
        .unwrap();
    assert!(!run.status.success());
    assert!(String::from_utf8_lossy(&run.stderr).contains("stored match cannot be verified"));
    assert!(!rejected.exists());
}
