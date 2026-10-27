use air_capture::{read_pcap_records, CaptureLimits};
use std::io::{BufWriter, Write};
use std::path::{Path, PathBuf};
use std::process::{Command, Output};
use std::sync::atomic::{AtomicUsize, Ordering};

struct Temp(PathBuf);
impl Temp {
    fn new() -> Self {
        static NEXT: AtomicUsize = AtomicUsize::new(0);
        let p = std::env::temp_dir().join(format!(
            "airclean-{}-{}",
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
fn clean(input: &Path, output: &Path, extra: &[&str]) -> Output {
    Command::new(env!("CARGO_BIN_EXE_aircrack"))
        .args(["wpaclean", "-i"])
        .arg(input)
        .arg("-o")
        .arg(output)
        .args(extra)
        .output()
        .unwrap()
}
fn inspect(input: &Path, words: &str) -> Output {
    Command::new(env!("CARGO_BIN_EXE_aircrack"))
        .args(["aircrack", "--capture"])
        .arg(input)
        .args(["-e", "Test Network", "--wordlist"])
        .arg(fixture(words))
        .output()
        .unwrap()
}
fn successful(result: &Output) {
    assert!(
        result.status.success(),
        "stdout={} stderr={}",
        String::from_utf8_lossy(&result.stdout),
        String::from_utf8_lossy(&result.stderr)
    );
}
#[test]
fn cleaned_protocols_and_link_types_remain_verifiable() {
    let temp = Temp::new();
    for name in [
        "wpa2-raw.pcap",
        "wpa2-radiotap.pcap",
        "wpa2-ethernet.pcap",
        "wpa2-mixed.pcapng",
        "wpa2-simple.pcapng",
        "wpa1-m2m3.pcap",
        "wpa2-v3.pcap",
        "wpa2-pmkid.pcap",
        "wpa2-pmkid-assoc-radiotap.pcap",
        "wpa2-fragmented-m2.pcap",
        "ft-psk-fragmented.pcap",
        "ft-psk.pcap",
        "sae-pmk.pcap",
        "ft-sae.pcap",
    ] {
        let output = temp.file(name);
        successful(&clean(&fixture(name), &output, &[]));
        let words = if name.contains("sae") {
            "sae-pmk-words.txt"
        } else {
            "words.txt"
        };
        successful(&inspect(&output, words));
        let records = read_pcap_records(&output, CaptureLimits::default()).unwrap();
        assert!(!records.is_empty());
        assert!(records.iter().all(|r| r.packet.dlt == 105));
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
fn errors_never_publish_partial_or_overwrite_output() {
    let temp = Temp::new();
    let output = temp.file("clean.cap");
    for extra in [
        vec!["--max-packets", "1"],
        vec!["--max-records", "1"],
        vec!["--bssid", "02:00:00:00:00:99"],
    ] {
        assert!(!clean(&fixture("wpa2-raw.pcap"), &output, &extra)
            .status
            .success());
        assert!(!output.exists());
    }
    let mut bad = std::fs::read(fixture("wpa2-raw.pcap")).unwrap();
    bad.extend_from_slice(&[0; 9]);
    let input = temp.file("bad.cap");
    std::fs::write(&input, bad).unwrap();
    assert!(!clean(&input, &output, &[]).status.success());
    assert!(!output.exists());
    std::fs::write(&output, b"keep").unwrap();
    assert!(!clean(&fixture("wpa2-raw.pcap"), &output, &[])
        .status
        .success());
    assert_eq!(std::fs::read(&output).unwrap(), b"keep");
    let original = std::fs::read(fixture("wpa2-raw.pcap")).unwrap();
    std::fs::write(&input, &original).unwrap();
    assert!(!clean(&input, &input, &[]).status.success());
    assert_eq!(std::fs::read(&input).unwrap(), original);
}
#[test]
fn duplicates_and_unrelated_frames_are_removed_and_cleaning_is_idempotent() {
    let temp = Temp::new();
    let bytes = std::fs::read(fixture("wpa2-raw.pcap")).unwrap();
    let mut noisy = bytes.clone();
    noisy.extend_from_slice(&bytes[24..]);
    let input = temp.file("noisy.cap");
    let output = temp.file("clean.cap");
    let twice = temp.file("twice.cap");
    std::fs::write(&input, noisy).unwrap();
    successful(&clean(&input, &output, &[]));
    successful(&clean(&output, &twice, &[]));
    assert_eq!(
        std::fs::read(&output).unwrap(),
        std::fs::read(&twice).unwrap()
    );
    assert_eq!(
        read_pcap_records(output, CaptureLimits::default())
            .unwrap()
            .len(),
        3
    );
}
#[test]
fn captures_beyond_old_size_and_packet_limits_stream_to_small_evidence() {
    let temp = Temp::new();
    let input = temp.file("large.cap");
    let output = temp.file("clean.cap");
    let source = std::fs::read(fixture("wpa2-raw.pcap")).unwrap();
    let mut file = BufWriter::new(std::fs::File::create(&input).unwrap());
    file.write_all(&source[..24]).unwrap();
    let mut noise = vec![0u8; 700];
    noise[0..2].copy_from_slice(&0x0208u16.to_le_bytes());
    noise[4..10].copy_from_slice(&[2, 0, 0, 0, 0, 2]);
    noise[10..16].copy_from_slice(&[2, 0, 0, 0, 0, 1]);
    noise[16..22].copy_from_slice(&[2, 0, 0, 0, 0, 3]);
    for _ in 0..100_001 {
        for value in [0u32, 0, 700, 700] {
            file.write_all(&value.to_le_bytes()).unwrap();
        }
        file.write_all(&noise).unwrap();
    }
    file.write_all(&source[24..]).unwrap();
    file.flush().unwrap();
    drop(file);
    assert!(std::fs::metadata(&input).unwrap().len() > 64 * 1024 * 1024);
    successful(&inspect(&input, "words.txt"));
    successful(&clean(&input, &output, &[]));
    assert!(std::fs::metadata(&output).unwrap().len() < 1024);
    successful(&inspect(&output, "words.txt"));
    let limited = temp.file("limited.cap");
    assert!(!clean(&input, &limited, &["--max-capture-mib", "1"])
        .status
        .success());
    assert!(!limited.exists());
}

fn write_records(path: &Path, records: &[air_capture::PacketRecord]) {
    let mut file = BufWriter::new(std::fs::File::create(path).unwrap());
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
            r.packet.data.len() as u32,
        ] {
            file.write_all(&n.to_le_bytes()).unwrap();
        }
        file.write_all(&r.packet.data).unwrap();
    }
    file.flush().unwrap();
}
#[test]
fn network_filter_and_conflicting_ssids_preserve_context() {
    let temp = Temp::new();
    let mut records =
        read_pcap_records(fixture("wpa2-raw.pcap"), CaptureLimits::default()).unwrap();
    let mut second = read_pcap_records(fixture("wpa2-raw.pcap"), CaptureLimits::default()).unwrap();
    for r in &mut second {
        for offset in [4, 10, 16] {
            if r.packet.data.get(offset..offset + 6) == Some(&[2, 0, 0, 0, 0, 1]) {
                r.packet.data[offset + 5] = 99;
            }
        }
    }
    records.extend(second);
    let input = temp.file("multi.cap");
    let output = temp.file("selected.cap");
    write_records(&input, &records);
    successful(&clean(&input, &output, &["--bssid", "02:00:00:00:00:01"]));
    successful(&inspect(&output, "words.txt"));
    assert_eq!(
        read_pcap_records(&output, CaptureLimits::default())
            .unwrap()
            .len(),
        3
    );
    let mut conflicting =
        read_pcap_records(fixture("wpa2-raw.pcap"), CaptureLimits::default()).unwrap();
    let mut beacon = read_pcap_records(fixture("wpa2-raw.pcap"), CaptureLimits::default())
        .unwrap()
        .into_iter()
        .find(|r| {
            air_capture::decode_packet(&r.packet)
                .ok()
                .is_some_and(|f| air_frames::ssid_bytes_from_beacon(&f).is_some())
        })
        .unwrap();
    beacon.packet.data[38] = b'X';
    conflicting.push(beacon);
    write_records(&input, &conflicting);
    let output = temp.file("conflict.cap");
    successful(&clean(&input, &output, &[]));
    let result = Command::new(env!("CARGO_BIN_EXE_aircrack"))
        .args(["aircrack", "--capture"])
        .arg(&output)
        .arg("--wordlist")
        .arg(fixture("words.txt"))
        .output()
        .unwrap();
    assert!(!result.status.success());
    assert!(String::from_utf8_lossy(&result.stderr).contains("conflicting SSIDs"));
    successful(&inspect(&output, "words.txt"));
}
#[test]
fn cleaning_does_not_authenticate_bad_mics_and_requires_a_target() {
    let temp = Temp::new();
    let output = temp.file("clean.cap");
    successful(&clean(&fixture("wpa2-m2m3-bad-mic.pcap"), &output, &[]));
    assert!(!inspect(&output, "words.txt").status.success());
    let empty = temp.file("empty.cap");
    assert!(!clean(&fixture("decap-open.pcap"), &empty, &[])
        .status
        .success());
    assert!(!empty.exists());
}
