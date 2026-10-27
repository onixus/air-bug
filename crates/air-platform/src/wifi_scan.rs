//! Ordinary OS-managed discovery, entirely separate from monitor capture/tuning.
use serde::Deserialize;
use std::{io, time::Duration};

#[derive(Debug, Deserialize)]
pub struct Network {
    pub ssid_hex: Option<String>,
    pub bssid: Option<String>,
    pub channel: Option<u16>,
    pub band: Option<u8>,
    pub signal_dbm: Option<i16>,
    pub noise_dbm: Option<i16>,
    #[serde(default)]
    pub security: Vec<String>,
}
#[derive(Debug, Deserialize)]
pub struct Snapshot {
    pub version: u32,
    pub source: String,
    pub mode_before: u32,
    pub mode_after: u32,
    pub current_bssid: Option<String>,
    pub total: usize,
    pub networks: Vec<Network>,
}

impl Network {
    pub fn security_label(&self) -> String {
        if self.security.is_empty() {
            "Unknown".into()
        } else {
            self.security.join("/")
        }
    }
}
impl Snapshot {
    pub fn is_current(&self, n: &Network) -> bool {
        self.mode_after == 1
            && self
                .current_bssid
                .as_deref()
                .zip(n.bssid.as_deref())
                .is_some_and(|(a, b)| a.eq_ignore_ascii_case(b))
    }
}

pub fn scan(iface: &str, cached: bool, request_location: bool) -> io::Result<Snapshot> {
    scan_until(iface, cached, request_location, || false)
}

pub fn scan_until(
    iface: &str,
    cached: bool,
    request_location: bool,
    cancelled: impl Fn() -> bool,
) -> io::Result<Snapshot> {
    if !cfg!(target_os = "macos") {
        return Err(io::Error::other(
            "ordinary Wi-Fi overview currently requires macOS/CoreWLAN",
        ));
    }
    if iface.is_empty()
        || iface.starts_with('-')
        || !iface
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b"_.:-".contains(&b))
    {
        return Err(io::Error::other("unsafe interface name"));
    }
    let executable = std::env::current_exe()?;
    let directory = executable
        .parent()
        .ok_or_else(|| io::Error::other("executable directory unavailable"))?;
    let bundle = directory.join("Air Wi-Fi Scan.app/Contents/MacOS/air-wifi-scan-macos");
    let standalone = directory.join("air-wifi-scan-macos");
    let helper = if bundle.is_file() { bundle } else { standalone };
    if !helper.is_file() {
        return Err(io::Error::other(
            "build the scan companion with tools/build-wifi-scan-macos.sh",
        ));
    }
    let source = if cached { "cache" } else { "scan" };
    let mut arguments = vec![iface, source];
    if request_location {
        arguments.push("--request-location");
    }
    let timeout = Duration::from_secs(if request_location { 60 } else { 20 });
    let output = super::channels::run_timed_until(&helper, &arguments, timeout, cancelled)?;
    let snapshot = decode(&output)?;
    if snapshot.source != source {
        return Err(io::Error::other("unexpected scan source"));
    }
    Ok(snapshot)
}
fn decode(text: &str) -> io::Result<Snapshot> {
    let mut s: Snapshot = serde_json::from_str(text).map_err(io::Error::other)?;
    if s.version != 1
        || !matches!(s.source.as_str(), "scan" | "cache")
        || s.networks.len() > 4096
        || s.total < s.networks.len()
    {
        return Err(io::Error::other("invalid Wi-Fi scan response"));
    }
    fn valid_bssid(s: &str) -> bool {
        s.len() == 17
            && s.split(':').count() == 6
            && s.split(':')
                .all(|p| p.len() == 2 && p.bytes().all(|b| b.is_ascii_hexdigit()))
    }
    if s.current_bssid.as_deref().is_some_and(|b| !valid_bssid(b)) {
        return Err(io::Error::other("invalid current BSSID"));
    }
    for n in &s.networks {
        if n.security.len() > 6
            || n.security
                .iter()
                .any(|v| !matches!(v.as_str(), "Open" | "WEP" | "WPA" | "WPA2" | "WPA3" | "OWE"))
        {
            return Err(io::Error::other("invalid Wi-Fi security metadata"));
        }
        if n.ssid_hex.as_ref().is_some_and(|s| {
            s.len() > 64 || s.len() % 2 != 0 || !s.bytes().all(|b| b.is_ascii_hexdigit())
        }) || n.channel == Some(0)
            || n.signal_dbm.is_some_and(|v| !(-127..0).contains(&v))
            || n.noise_dbm.is_some_and(|v| !(-127..0).contains(&v))
        {
            return Err(io::Error::other("invalid Wi-Fi network metadata"));
        }
    }
    s.networks
        .sort_by_key(|n| std::cmp::Reverse(n.signal_dbm.unwrap_or(-128)));
    Ok(s)
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn preserves_redaction_duplicate_rows_and_sorts_signal() {
        let s = decode(r#"{"version":1,"source":"scan","mode_before":1,"mode_after":1,"total":2,"networks":[{"ssid_hex":null,"bssid":null,"channel":6,"band":1,"signal_dbm":-70},{"ssid_hex":"611b62","bssid":null,"channel":44,"band":2,"signal_dbm":-40}]}"#).unwrap();
        assert_eq!(s.networks.len(), 2);
        assert_eq!(s.networks[0].signal_dbm, Some(-40));
        assert!(s.networks[1].ssid_hex.is_none());
    }
    #[test]
    fn security_and_current_bssid_are_explicit_and_privacy_safe() {
        let json = r#"{"version":1,"source":"scan","mode_before":1,"mode_after":1,"current_bssid":"AA:BB:CC:DD:EE:01","total":2,"networks":[{"ssid_hex":"61","bssid":"aa:bb:cc:dd:ee:01","security":["WPA2","WPA3"]},{"ssid_hex":"61","bssid":"aa:bb:cc:dd:ee:02"}]}"#;
        let mut s = decode(json).unwrap();
        assert_eq!(s.networks[0].security_label(), "WPA2/WPA3");
        assert_eq!(s.networks[1].security_label(), "Unknown");
        assert!(s.is_current(&s.networks[0]));
        assert!(!s.is_current(&s.networks[1])); // Same SSID, different AP.
        s.mode_after = 0;
        assert!(!s.is_current(&s.networks[0]));
        s.mode_after = 1;
        s.current_bssid = None;
        assert!(!s.is_current(&s.networks[0]));
        assert!(decode(&json.replace("WPA3", "garbage")).is_err());
        assert!(decode(&json.replace("AA:BB:CC:DD:EE:01", "")).is_err());
    }
    #[test]
    fn rejects_invalid_protocol_and_metadata() {
        let valid = r#"{"version":1,"source":"cache","mode_before":1,"mode_after":1,"total":1,"networks":[{"ssid_hex":"61","channel":6,"signal_dbm":-70}]}"#;
        for bad in [
            valid.replace("\"version\":1", "\"version\":2"),
            valid.replace("\"61\"", "\"xyz\""),
            valid.replace("-70", "40"),
            valid.replace("\"total\":1", "\"total\":0"),
        ] {
            assert!(decode(&bad).is_err());
        }
    }
}
