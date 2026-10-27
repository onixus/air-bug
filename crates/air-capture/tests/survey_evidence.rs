use air_capture::{read_pcap, survey::Survey};
use std::time::Duration;
fn survey(name: &str, filter: Option<[u8; 6]>) -> Survey {
    let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../tests/fixtures")
        .join(name);
    let mut survey = Survey::default();
    for packet in read_pcap(path).unwrap() {
        survey.observe(packet.dlt, &packet.data, Duration::ZERO, filter);
    }
    survey
}
#[test]
fn supported_wire_captures_mark_evidence_and_filters_do_not_leak() {
    for (name, hs, pmkid) in [
        ("wpa2-raw.pcap", true, false),
        ("wpa2-radiotap.pcap", true, false),
        ("wpa2-m2m3-radiotap.pcap", true, false),
        ("wpa2-pmkid-radiotap.pcap", false, true),
        ("wpa2-pmkid-assoc-radiotap.pcap", false, true),
        ("wpa2-pmkid-reassoc-radiotap.pcap", false, true),
        // Structural evidence does not assert that the captured MIC/PMKID is correct.
        ("wpa2-m2m3-bad-mic.pcap", true, false),
        ("wpa2-pmkid-bad-id.pcap", false, true),
    ] {
        let data = survey(name, None);
        let ap = &data.aps[&[2, 0, 0, 0, 0, 1]];
        assert_eq!(ap.handshake_m1m2 || ap.handshake_m2m3, hs, "{name}");
        assert_eq!(ap.pmkid, pmkid, "{name}");
        assert!(survey(name, Some([2; 6])).aps.is_empty(), "{name}");
    }
}
