use air_capture::survey::Survey;
use std::time::Duration;
const AP: [u8; 6] = [2, 0, 0, 0, 0, 1];
const OLD: [u8; 6] = [2, 0, 0, 0, 0, 2];
const STA: [u8; 6] = [2, 0, 0, 0, 0, 3];
fn frame(fc: u16, a1: [u8; 6], a2: [u8; 6], body: &[u8]) -> Vec<u8> {
    let mut f = fc.to_le_bytes().to_vec();
    f.extend([0; 2]);
    f.extend(a1);
    f.extend(a2);
    f.extend(AP);
    f.extend([0; 2]);
    f.extend(body);
    f
}
fn observe(s: &mut Survey, f: &[u8]) {
    s.observe_record(
        105,
        f,
        f.len() as u32,
        Some(Duration::from_secs(12)),
        Duration::ZERO,
        None,
    );
}
#[test]
fn enterprise_eap_is_separate_from_password_evidence_and_never_exports_identity() {
    let mut s = Survey::default();
    let mut p = air_frames::LLC_EAPOL.to_vec();
    p.extend([2, 0, 0, 10, 2, 1, 0, 10, 1, b'a', b'l', b'i', b'c', b'e']);
    let f = frame(0x0108, AP, STA, &p);
    observe(&mut s, &f);
    let ap = &s.aps[&AP];
    assert_eq!(ap.enterprise.identity_responses, 1);
    assert_eq!(ap.verification_label(), "-");
    let json = format!("{:?}", ap.enterprise);
    assert!(!json.contains("alice"));
    assert!(!json.contains("616c696365"));
    let mut filtered = Survey::default();
    filtered.observe(105, &f, Duration::ZERO, Some(OLD));
    assert!(filtered.aps.is_empty());
    let mut protected = f;
    protected[1] |= 0x40;
    observe(&mut s, &protected);
    assert_eq!(s.aps[&AP].enterprise.identity_responses, 1);
}
#[test]
fn reassociation_status_reason_and_ft_auth_are_observations_not_association() {
    let mut s = Survey::default();
    let mut p = vec![0, 0, 10, 0];
    p.extend(OLD);
    observe(&mut s, &frame(0x20, AP, STA, &p));
    observe(&mut s, &frame(0x30, STA, AP, &[0, 0, 17, 0, 0, 0]));
    observe(&mut s, &frame(0xb0, STA, AP, &[2, 0, 2, 0, 0, 0]));
    observe(&mut s, &frame(0xc0, STA, AP, &[3, 0]));
    assert_eq!(s.roaming.events.len(), 4);
    assert_eq!(
        s.roaming.events[0].previous_bssid.as_deref(),
        Some("02:00:00:00:00:02")
    );
    assert_eq!(s.roaming.events[1].status_code, Some(17));
    assert_eq!(s.roaming.events[2].authentication_algorithm, Some(2));
    assert_eq!(s.roaming.events[3].reason_code, Some(3));
    assert_eq!(s.roaming.events[0].capture_timestamp_seconds, Some(12.0));
    assert_eq!(s.roaming.events[0].record_index, 1);
    assert!(s.stations.is_empty());
    assert_eq!(s.ignored, 0);
    // No fabricated roam when only data headers change BSSID.
    observe(&mut s, &frame(0x0108, AP, STA, &[]));
    assert_eq!(s.roaming.events.len(), 4);
}
#[test]
fn protected_fragmented_filtered_malformed_and_bounded_management() {
    let f = frame(0xc0, STA, AP, &[3, 0]);
    let mut s = Survey::default();
    s.observe(105, &f, Duration::ZERO, Some(OLD));
    for fc in [0x40c0, 0x04c0, 0x01c0] {
        observe(&mut s, &frame(fc, STA, AP, &[3, 0]));
    }
    for len in 0..f.len() {
        observe(&mut s, &f[..len]);
    }
    assert!(s.roaming.events.is_empty());
    observe(&mut s, &frame(0x20, AP, STA, &[0; 4]));
    assert!(s.roaming.malformed_management > 0);
    for _ in 0..520 {
        observe(&mut s, &f);
    }
    assert_eq!(s.roaming.events.len(), 512);
    assert_eq!(s.roaming.evicted, 8);
    s.expire(Duration::from_secs(1000), Duration::from_secs(1));
    assert_eq!(s.roaming.events.len(), 512);
}
#[test]
fn advertisements_expose_mobility_domain_k_v_and_invalidate_bad_updates() {
    let mut p = vec![0; 12];
    p.extend([54, 3, 0x12, 0x34, 3, 70, 5, 2, 0, 0, 0, 0, 127, 3, 0, 0, 8]);
    let mut s = Survey::default();
    observe(&mut s, &frame(0x80, [255; 6], AP, &p));
    let caps = s.aps[&AP].roaming_capabilities.as_ref().unwrap();
    assert_eq!(caps.mobility_domain_hex.as_deref(), Some("1234"));
    assert_eq!(caps.ft_over_ds, Some(true));
    assert_eq!(caps.neighbor_report, Some(true));
    assert_eq!(caps.bss_transition, Some(true));
    p.extend([54, 1, 0]);
    observe(&mut s, &frame(0x80, [255; 6], AP, &p));
    assert!(s.aps[&AP].roaming_capabilities.is_none());
}

#[test]
fn short_fixed_fields_or_invalid_security_clear_current_roaming_capabilities() {
    let mut beacon = vec![0; 12];
    beacon.extend([54, 3, 0x12, 0x34, 1]);
    for invalid in [
        frame(0x80, [255; 6], AP, &[0; 11]),
        frame(0x50, STA, AP, &[0; 11]),
        {
            let mut p = beacon.clone();
            p.extend([48, 4, 1, 0, 0, 0]);
            frame(0x80, [255; 6], AP, &p)
        },
    ] {
        let mut s = Survey::default();
        observe(&mut s, &frame(0x80, [255; 6], AP, &beacon));
        assert!(s.aps[&AP].roaming_capabilities.is_some());
        observe(&mut s, &invalid);
        let ap = &s.aps[&AP];
        assert!(ap.roaming_capabilities.is_none());
        assert_eq!(ap.audit_last_status, Some("malformed"));
        assert_eq!(ap.audit_malformed, 1);
        assert_eq!(ap.pmf(), "unknown");
    }
}
