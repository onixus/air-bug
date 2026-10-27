use air_capture::survey::{display_bytes, mac_string, Survey};
use anyhow::{Context, Result};
use serde_json::{json, Value};
use std::fs::{File, OpenOptions};
use std::io::Write;
use std::path::{Path, PathBuf};
use std::time::Duration;

/// Reserve new paths before starting capture. Failed surveys/exports remove only
/// files created by this invocation; existing files/symlinks are never opened.
pub struct Exports {
    files: Vec<(bool, PathBuf, File)>,
    committed: bool,
}
impl Drop for Exports {
    fn drop(&mut self) {
        if !self.committed {
            for (_, path, _) in &self.files {
                let _ = std::fs::remove_file(path);
            }
        }
    }
}
impl Exports {
    pub fn reserve(json: Option<&Path>, csv: Option<&Path>) -> Result<Self> {
        let mut result = Self {
            files: Vec::new(),
            committed: false,
        };
        for (is_json, path) in [(true, json), (false, csv)] {
            if let Some(path) = path {
                let mut options = OpenOptions::new();
                options.write(true).create_new(true);
                #[cfg(unix)]
                {
                    use std::os::unix::fs::OpenOptionsExt;
                    options.mode(0o600);
                }
                let file = options.open(path).with_context(|| {
                    format!(
                        "cannot create export {}; existing files are never overwritten",
                        path.display()
                    )
                })?;
                result.files.push((is_json, path.to_owned(), file));
            }
        }
        Ok(result)
    }
    pub fn write(&mut self, data: &Survey, elapsed: Duration) -> Result<()> {
        for (is_json, path, file) in &mut self.files {
            if *is_json {
                serde_json::to_writer_pretty(&mut *file, &snapshot(data, elapsed))?;
                file.write_all(b"\n")?;
            } else {
                write_csv(file, data, elapsed)?;
            }
            file.sync_all()
                .with_context(|| format!("cannot sync export {}", path.display()))?;
        }
        self.committed = true;
        Ok(())
    }
}
fn snapshot(data: &Survey, elapsed: Duration) -> Value {
    let aps: Vec<_> = data.aps.iter().map(|(mac, ap)| json!({
        "bssid": mac_string(mac), "ssid": display_bytes(&ap.ssid), "ssid_hex": hex::encode(&ap.ssid),
        "channel": ap.channel, "last_direct_observation": ap.last_direct_observation, "signal_dbm": ap.signal, "security": if ap.security.is_empty() { None } else { Some(&ap.security) },
        "beacons": ap.beacons, "packets": ap.packets, "age_seconds": elapsed.saturating_sub(ap.last_seen).as_secs_f64(),
        "security_audit": { "last_status": ap.audit_last_status, "malformed_advertisements": ap.audit_malformed, "changed": ap.audit_changed, "last_valid": ap.security_audit, "current_assessment": ap.security_audit.as_ref().filter(|_| ap.audit_last_status == Some("valid")).map(|a| &a.advertised.assessment) },
        "capture_diagnostics": { "counters": ap.capture, "observations": ap.capture_observations(), "scope": "EAPOL counts are per BSSID and may belong to different peers or exchanges" },
        "ft":ap.ft, "handshake_m1m2": ap.handshake_m1m2, "handshake_m2m3": ap.handshake_m2m3, "handshake_m3m4":ap.handshake_m3m4, "pmkid": ap.pmkid,
    })).collect();
    let stations: Vec<_> = data.stations.iter().map(|(mac, sta)| json!({
        "mac": mac_string(mac), "last_bssid": sta.bssid.as_ref().map(mac_string), "signal_dbm": sta.signal,
        "packets": sta.packets, "age_seconds": elapsed.saturating_sub(sta.last_seen).as_secs_f64(),
        "probe_ssid": display_bytes(&sta.probe), "probe_ssid_hex": hex::encode(&sta.probe),
    })).collect();
    json!({
        "schema_version": 1, "kind": "survey_snapshot", "elapsed_seconds": elapsed.as_secs_f64(),
        "packets": data.packets, "ignored": data.ignored, "evicted": data.evicted,
        "verification_pending_evicted": data.verification_evicted(),
        "capture_quality": data.quality,
        "capture_quality_scope": "All input records before BSSID filtering; counters do not estimate packet loss. FCS flags are driver reports, not computed checksums.",
        "security_audit_scope": "Last valid unfragmented beacon or probe response; advertised, not negotiated or authenticated. A malformed later advertisement makes the current state unknown.",
        "verification_scope": "Personal Wi-Fi EAPOL/FT and PSK PMKID; structural evidence only, password/MIC not verified; SAE requires an exported PMK",
        "access_points": aps, "clients": stations,
        "rnr_neighbors": data.rnr_neighbors.values().map(|r| json!({
            "reporter_bssid": mac_string(&r.reporter_bssid),
            "neighbor_bssid": r.neighbor.bssid.as_ref().map(mac_string),
            "operating_class": r.neighbor.operating_class, "channel": r.neighbor.channel,
            "radio": r.neighbor.radio, "short_ssid": r.neighbor.short_ssid,
            "bss_parameters": r.neighbor.bss_parameters, "tbtt_offset": r.neighbor.tbtt_offset,
            "tbtt_type": r.neighbor.tbtt_type, "tbtt_length": r.neighbor.tbtt_length,
            "origin": r.origin, "directly_observed": r.neighbor.bssid.and_then(|b| data.aps.get(&b)).is_some_and(|ap| ap.last_direct_observation.is_some()),
        })).collect::<Vec<_>>(),
        "rnr_scope": "Neighbors are unauthenticated reports, not direct observations; channel may be a wider-channel center. No SSID, reachability, or association is inferred.",
    })
}
fn text(value: &str) -> String {
    // Spreadsheet formula protection applies only to text, not numeric RSSI.
    let prefix = if value.starts_with(['=', '+', '-', '@', '\t', '\r', '\n']) {
        "'"
    } else {
        ""
    };
    format!("\"{prefix}{}\"", value.replace('"', "\"\""))
}
fn optional(value: Option<impl ToString>) -> String {
    value.map(|v| v.to_string()).unwrap_or_default()
}
fn write_csv(out: &mut File, data: &Survey, elapsed: Duration) -> Result<()> {
    writeln!(out, "kind,mac,last_bssid,ssid,ssid_hex,channel,signal_dbm,security,beacons,packets,age_seconds,handshake_m1m2,handshake_m2m3,pmkid,probe_ssid,probe_ssid_hex,ft,handshake_m3m4,audit_status,pmf,akms,ciphers,security_observations,audit_changed,audit_malformed,retry_frames,fragmented_frames,eapol_m1,eapol_m2,eapol_m3,eapol_m4,eapol_unparsed,capture_observations,advertised_mode,audit_findings,audit_recommendations,origin_kind,reporter_bssid,band,frequency_mhz,operating_class,short_ssid,record_index")?;
    for (mac, ap) in &data.aps {
        let advertised = ap
            .security_audit
            .as_ref()
            .filter(|_| ap.audit_last_status == Some("valid"))
            .map(|o| &o.advertised);
        let profile = advertised.and_then(|a| a.rsn.as_ref().or(a.wpa.as_ref()));
        let names = |items: &[air_capture::security_audit::Suite]| {
            items
                .iter()
                .map(|x| format!("{}:{}", x.name, x.selector))
                .collect::<Vec<_>>()
                .join(";")
        };
        let fields = [
            "ap".into(),
            text(&mac_string(mac)),
            String::new(),
            text(&display_bytes(&ap.ssid)),
            text(&hex::encode(&ap.ssid)),
            optional(ap.channel),
            optional(ap.signal),
            text(&ap.security),
            ap.beacons.to_string(),
            ap.packets.to_string(),
            elapsed
                .saturating_sub(ap.last_seen)
                .as_secs_f64()
                .to_string(),
            ap.handshake_m1m2.to_string(),
            ap.handshake_m2m3.to_string(),
            ap.pmkid.to_string(),
            String::new(),
            String::new(),
            ap.ft.to_string(),
            ap.handshake_m3m4.to_string(),
            text(ap.audit_last_status.unwrap_or("unknown")),
            text(ap.pmf()),
            text(&profile.map(|p| names(&p.akm_suites)).unwrap_or_default()),
            text(
                &profile
                    .map(|p| names(&p.pairwise_ciphers))
                    .unwrap_or_default(),
            ),
            text(
                &advertised
                    .map(|a| a.observations.join(";"))
                    .unwrap_or_default(),
            ),
            ap.audit_changed.to_string(),
            ap.audit_malformed.to_string(),
            ap.capture.retry_bit_frames.to_string(),
            ap.capture.fragmented_frames.to_string(),
            ap.capture.eapol_m1.to_string(),
            ap.capture.eapol_m2.to_string(),
            ap.capture.eapol_m3.to_string(),
            ap.capture.eapol_m4.to_string(),
            ap.capture.unsupported_or_malformed_eapol_key.to_string(),
            text(&ap.capture_observations().join(";")),
            text(
                advertised
                    .map(|a| a.assessment.advertised_mode)
                    .unwrap_or("unknown"),
            ),
            text(
                &advertised
                    .map(|a| {
                        a.assessment
                            .findings
                            .iter()
                            .map(|f| format!("{}:{}", f.severity, f.id))
                            .collect::<Vec<_>>()
                            .join("; ")
                    })
                    .unwrap_or_default(),
            ),
            text(
                &advertised
                    .map(|a| {
                        a.assessment
                            .findings
                            .iter()
                            .map(|f| f.recommendation)
                            .collect::<Vec<_>>()
                            .join("; ")
                    })
                    .unwrap_or_default(),
            ),
        ];
        let mut fields = fields.to_vec();
        let origin = ap.last_direct_observation.as_ref();
        let radio = origin.and_then(|o| o.radio);
        fields.extend([
            text(origin.map(|o| o.kind).unwrap_or("unknown")),
            String::new(),
            text(radio.map(|r| r.band).unwrap_or("unknown")),
            optional(radio.map(|r| r.frequency_mhz)),
            String::new(),
            String::new(),
            optional(origin.map(|o| o.record_index)),
        ]);
        writeln!(out, "{}", fields.join(","))?;
    }
    for (mac, sta) in &data.stations {
        let fields = [
            "client".into(),
            text(&mac_string(mac)),
            sta.bssid
                .as_ref()
                .map(mac_string)
                .map(|s| text(&s))
                .unwrap_or_default(),
            String::new(),
            String::new(),
            String::new(),
            optional(sta.signal),
            String::new(),
            String::new(),
            sta.packets.to_string(),
            elapsed
                .saturating_sub(sta.last_seen)
                .as_secs_f64()
                .to_string(),
            String::new(),
            String::new(),
            String::new(),
            text(&display_bytes(&sta.probe)),
            text(&hex::encode(&sta.probe)),
            String::new(),
            String::new(),
            String::new(),
            String::new(),
            String::new(),
            String::new(),
            String::new(),
            String::new(),
            String::new(),
            String::new(),
            String::new(),
            String::new(),
            String::new(),
            String::new(),
            String::new(),
            String::new(),
            String::new(),
        ];
        let mut fields = fields.to_vec();
        fields.extend(std::iter::repeat_n(String::new(), 10));
        writeln!(out, "{}", fields.join(","))?;
    }
    for r in data.rnr_neighbors.values() {
        let mut fields = vec![String::new(); 43];
        fields[0] = "rnr".into();
        fields[1] = r
            .neighbor
            .bssid
            .as_ref()
            .map(mac_string)
            .map(|s| text(&s))
            .unwrap_or_default();
        fields[5] = r.neighbor.channel.to_string();
        fields[36] = text(r.origin.kind);
        fields[37] = text(&mac_string(&r.reporter_bssid));
        fields[38] = text(r.neighbor.radio.map(|x| x.band).unwrap_or("unknown"));
        fields[39] = optional(r.neighbor.radio.map(|x| x.frequency_mhz));
        fields[40] = r.neighbor.operating_class.to_string();
        fields[41] = optional(r.neighbor.short_ssid);
        fields[42] = r.origin.record_index.to_string();
        writeln!(out, "{}", fields.join(","))?;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn malformed_latest_advertisement_never_exposes_stale_assessment_as_current() {
        let mut data = Survey::default();
        let ap = [2, 1, 2, 3, 4, 5];
        let mut beacon = vec![0x80, 0, 0, 0];
        beacon.extend([255; 6]);
        beacon.extend(ap);
        beacon.extend(ap);
        beacon.extend([0; 14]);
        data.observe(105, &beacon, Duration::ZERO, None);
        let mut bad = beacon.clone();
        bad.extend([48, 4, 1, 0, 0, 0]);
        data.observe(105, &bad, Duration::from_secs(1), None);
        let value = snapshot(&data, Duration::from_secs(1));
        let audit = &value["access_points"][0]["security_audit"];
        assert_eq!(audit["last_status"], "malformed");
        assert!(audit["current_assessment"].is_null());
        assert_eq!(
            audit["last_valid"]["advertised"]["assessment"]["advertised_mode"],
            "open_advertised"
        );
    }
    #[test]
    fn csv_escapes_quotes_and_formulas_but_preserves_raw_bytes_in_hex() {
        assert_eq!(text("=SUM(1,2)"), "\"'=SUM(1,2)\"");
        assert_eq!(text("a,\"b\""), "\"a,\"\"b\"\"\"");
        let mut data = Survey::default();
        data.aps.insert(
            [2, 0, 0, 0, 0, 1],
            air_capture::survey::AccessPoint {
                ssid: vec![0xff, 27],
                ..Default::default()
            },
        );
        let json = snapshot(&data, Duration::ZERO);
        assert_eq!(json["access_points"][0]["ssid_hex"], "ff1b");
        assert!(json["access_points"][0]["signal_dbm"].is_null());
    }
}
