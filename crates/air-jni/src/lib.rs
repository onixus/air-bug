//! Bounded, offline-only Android adapter. No changes to desktop protocol logic.
#[cfg(test)]
use air_capture::read_pcap;
use air_capture::{CaptureError, CaptureLimits, CaptureReader, FrameDecoder};
use air_crack::{engine::TargetSet, wordlist::Wordlist};
use air_frames::{ssid_bytes_from_beacon, LLC_EAPOL};
use air_handshake::{
    extract_pmkid_targets, extract_targets_limited, parse_eapol_key, VerificationTarget,
};
use jni::{
    objects::{JClass, JString},
    sys::jstring,
    JNIEnv,
};
use serde::Deserialize;
use serde_json::{json, Value};
use std::{
    collections::{BTreeMap, BTreeSet},
    panic::{catch_unwind, AssertUnwindSafe},
    sync::atomic::{AtomicBool, AtomicUsize, Ordering},
};

const MAX_CAPTURE: u64 = 4 * 1024 * 1024;
const MAX_WORDLIST: u64 = 16 * 1024 * 1024;
static CANCEL: AtomicBool = AtomicBool::new(false);
static CHECKED: AtomicUsize = AtomicUsize::new(0);

#[derive(Deserialize)]
struct Request {
    capture: String,
    #[serde(default)]
    wordlist: String,
    #[serde(default)]
    ssid: String,
    #[serde(default)]
    bssid: String,
}

fn mac(bytes: &[u8; 6]) -> String {
    bytes
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect::<Vec<_>>()
        .join(":")
}
fn parse_mac(text: &str) -> Result<[u8; 6], String> {
    let mut out = [0; 6];
    let parts: Vec<_> = text.split(':').collect();
    if parts.len() != 6 || parts.iter().any(|s| s.len() != 2) {
        return Err("BSSID must be aa:bb:cc:dd:ee:ff".into());
    }
    for (byte, part) in out.iter_mut().zip(parts) {
        *byte = u8::from_str_radix(part, 16).map_err(|_| "Invalid BSSID")?;
    }
    Ok(out)
}
fn bounded_file(path: &str, max: u64) -> Result<(), String> {
    let meta = std::fs::metadata(path).map_err(|e| e.to_string())?;
    if !meta.is_file() || meta.len() > max {
        return Err(format!(
            "Input must be a regular file, at most {} MiB",
            max / 1024 / 1024
        ));
    }
    Ok(())
}
fn run(req: Request) -> Result<Value, String> {
    bounded_file(&req.capture, MAX_CAPTURE)?;
    let packets = CaptureReader::open(
        &req.capture,
        CaptureLimits {
            bytes: MAX_CAPTURE,
            packets: 32768,
        },
    )
    .map_err(|e| e.to_string())?;
    let mut evidence = air_capture::evidence::Evidence::new(128);
    let (mut packet_count, mut parsed) = (0usize, 0usize);
    let mut skipped = 0;
    let mut keys = 0;
    let mut decoder = FrameDecoder::default();
    for packet in packets {
        let packet = packet.map_err(|e| e.to_string())?;
        packet_count += 1;
        if CANCEL.load(Ordering::Relaxed) {
            return Ok(json!({"status":"cancelled"}));
        }
        match decoder.decode(&packet.packet, packet.timestamp.unwrap_or_default()) {
            Ok(Some(frame)) => {
                keys += usize::from(
                    frame
                        .payload
                        .strip_prefix(&LLC_EAPOL)
                        .and_then(parse_eapol_key)
                        .is_some(),
                );
                keys += extract_pmkid_targets(std::slice::from_ref(&frame)).len();
                // Bound M1/M2/M3 products AND PMKID target counts before extraction.
                if keys > 128 {
                    return Err("Capture exceeds 128 EAPOL/PMKID records; split the capture".into());
                }
                parsed += 1;
                evidence.push(frame).map_err(|e| e.to_string())?;
            }
            Ok(None) => {}
            Err(CaptureError::UnsupportedDlt(dlt)) => {
                return Err(format!("Unsupported link type: {dlt}"))
            }
            Err(_) => skipped += 1,
        }
    }
    let frames = evidence.frames;
    let mut networks: BTreeMap<[u8; 6], BTreeSet<Vec<u8>>> = BTreeMap::new();
    for frame in &frames {
        if let Some(ssid) = ssid_bytes_from_beacon(frame) {
            networks
                .entry(frame.addr3)
                .or_default()
                .insert(ssid.to_vec());
        }
    }
    let sessions = extract_targets_limited(&frames, 128, 1024).map_err(|e| e.to_string())?;
    for session in &sessions {
        networks.entry(session.bssid()).or_default();
    }
    let summary: Vec<_> = networks.iter().map(|(bssid, names)| json!({
        "bssid":mac(bssid),
        "ssids": names.iter().map(|s| String::from_utf8_lossy(s).into_owned()).collect::<Vec<_>>(),
        "sessions":sessions.iter().filter(|s| s.bssid() == *bssid).count()
    })).collect();
    let pmkids = sessions
        .iter()
        .filter(|s| matches!(s, VerificationTarget::Pmkid(_)))
        .count();
    let mut report = json!({"status":"inspected", "packets":packet_count, "parsed":parsed, "skipped":skipped, "sessions":sessions.len(), "handshakes":sessions.len()-pmkids, "pmkids":pmkids, "networks":summary});
    if req.wordlist.is_empty() {
        return Ok(report);
    }
    bounded_file(&req.wordlist, MAX_WORDLIST)?;
    if !req.ssid.is_empty() && req.ssid.len() > 32 {
        return Err("SSID must contain 1 to 32 UTF-8 bytes".into());
    }
    let selected = if req.bssid.is_empty() {
        None
    } else {
        Some(parse_mac(&req.bssid)?)
    };
    let candidates: Vec<_> = sessions
        .into_iter()
        .filter(|s| {
            selected.is_none_or(|b| b == s.bssid())
                && (req.ssid.is_empty()
                    || networks.get(&s.bssid()).is_none_or(|names| {
                        names.is_empty() || names.contains(req.ssid.as_bytes())
                    }))
        })
        .collect();
    if candidates.is_empty() {
        return Err("No WPA2 M1/M2, M2/M3 or PMKID target matches selection".into());
    }
    let aps: BTreeSet<_> = candidates.iter().map(|s| s.bssid()).collect();
    if aps.len() != 1 {
        return Err("Multiple networks: enter an explicit BSSID from the report".into());
    }
    let ap = candidates[0].bssid();
    let ssid = if req.ssid.is_empty() {
        let names = &networks[&ap];
        if names.len() != 1 {
            return Err("Missing or conflicting SSID: enter an explicit SSID".into());
        }
        names.first().cloned().ok_or("Missing SSID")?
    } else {
        req.ssid.into_bytes()
    };
    let targets = TargetSet::new(candidates, ssid).map_err(|e| e.to_string())?;
    let words = Wordlist::from_file(&req.wordlist).map_err(|e| e.to_string())?;
    // Sequential candidates allow cancellation between PBKDF2 calls and avoid
    // saturating all mobile cores. No passphrase cache, callbacks or raw pointers.
    for word in words {
        if CANCEL.load(Ordering::Relaxed) {
            report["status"] = json!("cancelled");
            return Ok(report);
        }
        let word = word.map_err(|e| e.to_string())?;
        let matched = targets.verify_candidate(&word);
        CHECKED.fetch_add(1, Ordering::Relaxed);
        if matched {
            report["status"] = json!("found");
            report["passphrase"] = json!(word);
            return Ok(report);
        }
    }
    if targets.requires_exported_pmk() {
        report["status"] = json!("error");
        report["message"]=json!("No supplied exported PMK matched; SAE passphrases cannot be checked from a passive capture");
        return Ok(report);
    }
    report["status"] = json!("not_found");
    Ok(report)
}
fn guarded(request: &str) -> Value {
    match catch_unwind(AssertUnwindSafe(|| {
        serde_json::from_str::<Request>(request)
            .map_err(|e| e.to_string())
            .and_then(run)
    })) {
        Ok(Ok(value)) => value,
        Ok(Err(message)) => json!({"status":"error", "message":message}),
        Err(_) => json!({"status":"error", "message":"Native analysis failed safely"}),
    }
}

#[no_mangle]
pub extern "system" fn Java_dev_onixus_aircrack_NativeBridge_run(
    mut env: JNIEnv,
    _: JClass,
    request: JString,
) -> jstring {
    catch_unwind(AssertUnwindSafe(|| {
        let result = match env.get_string(&request) {
            Ok(text) => guarded(&String::from(text)),
            Err(_) => json!({"status":"error", "message":"Invalid JNI request"}),
        };
        env.new_string(result.to_string())
            .map(|s| s.into_raw())
            .unwrap_or(std::ptr::null_mut())
    }))
    .unwrap_or(std::ptr::null_mut())
}
#[no_mangle]
pub extern "system" fn Java_dev_onixus_aircrack_NativeBridge_control(
    _: JNIEnv,
    _: JClass,
    action: i32,
) -> i64 {
    catch_unwind(|| match action {
        0 => {
            CANCEL.store(false, Ordering::Relaxed);
            CHECKED.store(0, Ordering::Relaxed);
            0
        }
        1 => {
            CANCEL.store(true, Ordering::Relaxed);
            0
        }
        _ => CHECKED.load(Ordering::Relaxed) as i64,
    })
    .unwrap_or(-1)
}

#[cfg(test)]
mod tests {
    use super::*;
    fn request(file: &str, wordlist: &str, ssid: &str, bssid: &str) -> String {
        let base = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../../tests/fixtures");
        json!({"capture":base.join(file),"wordlist":if wordlist.is_empty(){String::new()}else{base.join(wordlist).to_string_lossy().into_owned()},"ssid":ssid,"bssid":bssid}).to_string()
    }
    #[test]
    fn offline_pipeline_and_errors() {
        CANCEL.store(false, Ordering::Relaxed);
        let report = guarded(&request("wpa2-radiotap.pcap", "", "", ""));
        assert_eq!(report["status"], "inspected");
        assert_eq!(report["sessions"], 1);
        let result = guarded(&request("wpa2-radiotap.pcap", "words.txt", "", ""));
        assert_eq!(result["status"], "found", "{result}");
        assert_eq!(result["passphrase"], "correct horse battery");
        for file in [
            "wpa2-m2m3.pcap",
            "wpa1-m1m2.pcap",
            "wpa1-m2m3.pcap",
            "wpa2-v3.pcap",
            "wpa2-v3-m2m3.pcap",
            "ft-psk.pcap",
            "ft-psk-fragmented.pcap",
            "wpa2-fragmented-m2.pcap",
            "wpa2-pmkid.pcap",
            "wpa2-pmkid-assoc.pcap",
            "wpa2-pmkid-reassoc.pcap",
        ] {
            let found = guarded(&request(file, "words.txt", "", ""));
            assert_eq!(found["status"], "found", "{file}: {found}");
            assert_eq!(found["sessions"], 1);
            assert_eq!(found["pmkids"], if file.contains("pmkid") { 1 } else { 0 });
            let missed = guarded(&request(file, "wrong-words.txt", "", ""));
            assert_eq!(missed["status"], "not_found", "{file}: {missed}");
        }
        let sae = guarded(&request("sae-pmk.pcap", "words.txt", "", ""));
        assert_eq!(sae["status"], "error");
        let sae = guarded(&request("sae-pmk.pcap", "sae-pmk-words.txt", "", ""));
        assert_eq!(sae["status"], "found");
        // Association PMKIDs must not bypass the pre-extraction record budget.
        let source = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../../tests/fixtures/wpa2-pmkid-assoc.pcap");
        let packets = read_pcap(source).unwrap();
        let packet = &packets[1].data;
        let temp =
            std::env::temp_dir().join(format!("air-jni-pmkid-budget-{}.pcap", std::process::id()));
        for count in [128, 129] {
            let mut bytes = vec![0xd4, 0xc3, 0xb2, 0xa1, 2, 0, 4, 0];
            for v in [0u32, 0, 65535, 105] {
                bytes.extend_from_slice(&v.to_le_bytes());
            }
            for _ in 0..count {
                for v in [1u32, 0, packet.len() as u32, packet.len() as u32] {
                    bytes.extend_from_slice(&v.to_le_bytes());
                }
                bytes.extend_from_slice(packet);
            }
            std::fs::write(&temp, bytes).unwrap();
            let report = guarded(&json!({"capture":temp}).to_string());
            assert_eq!(
                report["status"],
                if count == 128 { "inspected" } else { "error" }
            );
        }
        std::fs::remove_file(temp).unwrap();
        assert_eq!(guarded("not json")["status"], "error");
        assert_eq!(
            guarded(&request("missing.pcap", "", "", ""))["status"],
            "error"
        );
        assert_eq!(
            guarded(&request("wpa2-radiotap.pcap", "words.txt", "wrong", ""))["status"],
            "error"
        );
        assert_eq!(
            guarded(&request("wpa2-radiotap.pcap", "words.txt", "", "bad"))["status"],
            "error"
        );
        CANCEL.store(true, Ordering::Relaxed);
        assert_eq!(
            guarded(&request("wpa2-radiotap.pcap", "", "", ""))["status"],
            "cancelled"
        );
        CANCEL.store(false, Ordering::Relaxed);
    }
}
