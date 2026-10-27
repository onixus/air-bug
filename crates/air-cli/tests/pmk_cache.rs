use std::path::{Path, PathBuf};
use std::process::{Command, Output};
use std::sync::atomic::{AtomicUsize, Ordering};
struct Temp(PathBuf);
impl Temp {
    fn new() -> Self {
        static NEXT: AtomicUsize = AtomicUsize::new(0);
        let path = std::env::temp_dir().join(format!(
            "air-pmk-cli-{}-{}",
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
fn command(capture: &Path, words: &Path, cache: &Path) -> Command {
    let mut cmd = Command::new(env!("CARGO_BIN_EXE_aircrack"));
    cmd.args(["aircrack", "--capture"])
        .arg(capture)
        .arg("--wordlist")
        .arg(words)
        .args(["-e", "Test Network", "--threads", "2", "--pmk-cache"])
        .arg(cache)
        .args(["--pmk-cache-mib", "1"]);
    cmd
}
fn success(r: &Output) {
    assert!(
        r.status.success(),
        "{}\n{}",
        String::from_utf8_lossy(&r.stdout),
        String::from_utf8_lossy(&r.stderr)
    );
}
#[test]
fn cache_reopens_across_processes_and_does_not_store_plaintext_candidates() {
    let tmp = Temp::new();
    let cache = tmp.path("pmk");
    let capture = fixture("wpa2-raw.pcap");
    let words = fixture("words.txt");
    let first = command(&capture, &words, &cache).output().unwrap();
    success(&first);
    assert!(String::from_utf8_lossy(&first.stderr).contains("derived=3"));
    let second = command(&capture, &words, &cache).output().unwrap();
    success(&second);
    let err = String::from_utf8_lossy(&second.stderr);
    assert!(err.contains("hits=3 misses=0 derived=0"), "{err}");
    assert_eq!(first.stdout, second.stdout);
    let bytes = std::fs::read(cache).unwrap();
    assert!(!bytes
        .windows(b"correct horse battery".len())
        .any(|v| v == b"correct horse battery"));
}
#[test]
fn sae_and_mixed_target_provenance_is_preserved_on_cache_hits() {
    let tmp = Temp::new();
    let cache = tmp.path("pmk");
    let words = fixture("words.txt");
    success(
        &command(&fixture("wpa2-raw.pcap"), &words, &cache)
            .output()
            .unwrap(),
    );
    let result = command(&fixture("sae-m234-provenance.pcap"), &words, &cache)
        .output()
        .unwrap();
    assert!(!result.status.success());
    assert!(String::from_utf8_lossy(&result.stderr).contains("hits=0 misses=0 derived=0"));
    success(
        &command(
            &fixture("sae-m234-provenance.pcap"),
            &fixture("m34-pmk-words.txt"),
            &cache,
        )
        .output()
        .unwrap(),
    );
    let mut bytes = std::fs::read(fixture("wpa2-m2m3-bad-mic.pcap")).unwrap();
    bytes.extend_from_slice(&std::fs::read(fixture("sae-pmk-provenance.pcap")).unwrap()[24..]);
    let mixed = tmp.path("mixed.pcap");
    std::fs::write(&mixed, bytes).unwrap();
    let result = command(&mixed, &words, &cache).output().unwrap();
    assert!(!result.status.success());
    assert!(String::from_utf8_lossy(&result.stderr).contains("hits=3 misses=0 derived=0"));
    assert!(!String::from_utf8_lossy(&result.stdout).contains("[+] found:"));
}
#[test]
fn cache_and_worker_count_preserve_first_match_and_resume_position() {
    let tmp = Temp::new();
    let cache = tmp.path("pmk");
    let words = tmp.path("words");
    let checkpoint = tmp.path("session");
    let capture = fixture("wpa2-raw.pcap");
    let mut text = (0..300)
        .map(|i| format!("wrong-candidate-{i:08}\n"))
        .collect::<String>();
    text.push_str("correct horse battery\n");
    std::fs::write(&words, text).unwrap();
    let paused = command(&capture, &words, &cache)
        .arg("--session")
        .arg(&checkpoint)
        .args(["--max-candidates", "256"])
        .output()
        .unwrap();
    assert!(!paused.status.success());
    let state: serde_json::Value =
        serde_json::from_slice(&std::fs::read(&checkpoint).unwrap()).unwrap();
    assert_eq!(state["completed_lines"], 256);
    success(
        &command(&capture, &words, &cache)
            .arg("--resume")
            .arg(&checkpoint)
            .output()
            .unwrap(),
    );
    let pmk = std::fs::read_to_string(fixture("m34-pmk-words.txt")).unwrap();
    for text in [
        format!("{}correct horse battery\n", pmk),
        format!("correct horse battery\n{}", pmk),
    ] {
        std::fs::write(&words, &text).unwrap();
        let result = command(&capture, &words, &cache).output().unwrap();
        success(&result);
        assert!(String::from_utf8_lossy(&result.stdout)
            .contains(&format!("[+] found: {}", text.lines().next().unwrap())));
    }
}
#[test]
fn lock_and_invalid_cache_fail_without_false_not_found() {
    let tmp = Temp::new();
    let path = tmp.path("pmk");
    let cache = air_crack::cache::Cache::open(&path, 1).unwrap();
    let result = command(&fixture("wpa2-raw.pcap"), &fixture("words.txt"), &path)
        .output()
        .unwrap();
    assert!(!result.status.success());
    assert!(String::from_utf8_lossy(&result.stderr).contains("locked"));
    drop(cache);
    std::fs::write(&path, b"invalid cache").unwrap();
    let result = command(&fixture("wpa2-raw.pcap"), &fixture("words.txt"), &path)
        .output()
        .unwrap();
    assert!(!result.status.success());
    assert!(String::from_utf8_lossy(&result.stderr).contains("cannot open PMK cache"));
    assert_eq!(std::fs::read(path).unwrap(), b"invalid cache");
}
#[test]
fn benchmark_reports_separate_pbkdf_and_persistent_cache_measurements() {
    let tmp = Temp::new();
    let report = tmp.path("benchmark.json");
    let output = Command::new(env!("CARGO_BIN_EXE_aircrack"))
        .args([
            "benchmark",
            "--candidates",
            "2",
            "--samples",
            "1",
            "--threads",
            "1",
            "--json",
        ])
        .arg(&report)
        .output()
        .unwrap();
    success(&output);
    let data: serde_json::Value = serde_json::from_slice(&std::fs::read(&report).unwrap()).unwrap();
    assert_eq!(data["cache_samples"][0]["cold_derived"], 2);
    assert_eq!(data["cache_samples"][0]["warm_derived"], 0);
    assert_eq!(data["cache_samples"][0]["warm_hits"], 2);
    assert!(data["reference"]["median_seconds"].as_f64().unwrap() > 0.0);
}

#[test]
fn stdin_and_duplicate_candidates_use_the_same_persistent_cache() {
    use std::io::Write;
    use std::process::Stdio;
    let tmp = Temp::new();
    let cache = tmp.path("pmk");
    let mut child = command(&fixture("wpa2-raw.pcap"), Path::new("-"), &cache)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    child
        .stdin
        .take()
        .unwrap()
        .write_all(b"incorrect password\ncorrect horse battery\ncorrect horse battery\n")
        .unwrap();
    let result = child.wait_with_output().unwrap();
    success(&result);
    assert!(String::from_utf8_lossy(&result.stderr).contains("derived=2"));
}
