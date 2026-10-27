use air_frames::{parse_dot11, Dot11Frame, LLC_EAPOL};
use air_handshake::{extract, extract_pmkid, parse_eapol_key};

fn message(from_ap: bool, replay: u64) -> Dot11Frame {
    let ap = [2, 0, 0, 0, 0, 1];
    let sta = [2, 0, 0, 0, 0, 2];
    let mut raw = vec![0; 24];
    raw[..2].copy_from_slice(&(if from_ap { 0x0208u16 } else { 0x0108u16 }).to_le_bytes());
    raw[4..10].copy_from_slice(if from_ap { &sta } else { &ap });
    raw[10..16].copy_from_slice(if from_ap { &ap } else { &sta });
    raw[16..22].copy_from_slice(&ap);
    raw.extend_from_slice(&LLC_EAPOL);
    let mut key = vec![0; 99];
    key[..5].copy_from_slice(&[2, 3, 0, 95, 2]);
    key[5..7].copy_from_slice(&(if from_ap { 0x008au16 } else { 0x010au16 }).to_be_bytes());
    key[9..17].copy_from_slice(&replay.to_be_bytes());
    key[17..49].fill(if from_ap { 1 } else { 2 });
    if !from_ap {
        key[81..97].fill(3);
    }
    raw.extend_from_slice(&key);
    parse_dot11(&raw).unwrap()
}

#[test]
fn truncated_and_malformed_eapol_never_panics() {
    let f = message(false, 1);
    let eapol = &f.payload[8..];
    for len in 0..99 {
        assert!(parse_eapol_key(&eapol[..len]).is_none(), "length {len}");
    }
    for offset in [0, 1, 4, 5, 6, 97, 98] {
        let mut data = eapol.to_vec();
        data[offset] = 0xff;
        assert!(parse_eapol_key(&data).is_none(), "offset {offset}");
    }
    let mut data = eapol.to_vec();
    data[3] = 96;
    assert!(parse_eapol_key(&data).is_none());
}

#[test]
fn only_complete_matching_pairs_become_sessions() {
    assert!(extract(&[]).is_empty());
    assert!(extract(&[message(true, 1)]).is_empty());
    assert!(extract(&[message(false, 1)]).is_empty());
    assert!(extract(&[message(true, 1), message(false, 2)]).is_empty());
    let mut wrong_sta = message(false, 1);
    wrong_sta.addr2[5] = 3;
    assert!(extract(&[message(true, 1), wrong_sta]).is_empty());
    let mut wrong_ap = message(false, 1);
    wrong_ap.addr1[5] = 3;
    assert!(extract(&[message(true, 1), wrong_ap]).is_empty());
    let mut not_eapol = message(false, 1);
    not_eapol.payload[6] = 0x08;
    assert!(extract(&[message(true, 1), not_eapol]).is_empty());
    let mut wrong_direction = message(false, 1);
    wrong_direction.frame_control = 0x0208;
    assert!(extract(&[message(true, 1), wrong_direction]).is_empty());
    // Reordered input and duplicate M1 must still yield one session.
    let sessions = extract(&[message(false, 1), message(true, 1), message(true, 1)]);
    assert_eq!(sessions.len(), 1);
    assert_eq!(sessions[0].count, 2);
    assert_eq!(&sessions[0].eapol[81..97], &[0; 16]);
    assert_eq!(sessions[0].mic, Some([3; 16]));
}

#[test]
fn unrelated_data_and_unsupported_descriptor_are_not_handshakes() {
    let mut frame = message(false, 1);
    frame.payload.fill(0);
    assert!(extract(&[message(true, 1), frame]).is_empty());
    let mut frame = message(false, 1);
    frame.payload[8 + 6] = 9; // HMAC-MD5 descriptor version 1
    assert!(extract(&[message(true, 1), frame]).is_empty());
}

#[test]
fn rsn_pmkid_requires_counts_and_version() {
    assert!(extract_pmkid(&[0; 32]).is_none());
    let mut rsn = vec![
        1, 0, 0, 15, 172, 4, 1, 0, 0, 15, 172, 4, 1, 0, 0, 15, 172, 2, 0, 0, 1, 0,
    ];
    rsn.extend_from_slice(&[7; 16]);
    assert_eq!(extract_pmkid(&rsn), Some([7; 16]));
    // The only optional field after the PMKID list is a four-octet
    // group management cipher suite. Reject truncated or excess suffixes.
    for suffix_len in [1, 2, 3, 5, 6, 7, 8] {
        let mut malformed = rsn.clone();
        malformed.extend(std::iter::repeat_n(0, suffix_len));
        assert!(extract_pmkid(&malformed).is_none(), "suffix {suffix_len}");
    }
    let mut with_group_management_cipher = rsn.clone();
    with_group_management_cipher.extend_from_slice(&[0, 15, 172, 6]);
    assert_eq!(extract_pmkid(&with_group_management_cipher), Some([7; 16]));
    for len in 0..rsn.len() {
        assert!(extract_pmkid(&rsn[..len]).is_none());
    }
}

fn m3(replay: u64) -> Dot11Frame {
    let mut f = message(true, replay);
    f.payload[8 + 5..8 + 7].copy_from_slice(&0x13cau16.to_be_bytes());
    f.payload[8 + 81..8 + 97].fill(9);
    f
}

#[test]
fn m2m3_pairs_counter_direction_endpoints_and_deduplicates_full_handshake() {
    let m2 = message(false, 7);
    let m3 = m3(8);
    for frames in [
        vec![m2.clone(), m3.clone()],
        vec![m3.clone(), m2.clone(), m3.clone()],
        vec![message(true, 7), m2.clone(), m3.clone()],
    ] {
        let sessions = extract(&frames);
        assert_eq!(sessions.len(), 1);
        assert_eq!(sessions[0].anonce, Some([1; 32]));
        assert_eq!(sessions[0].snonce, Some([2; 32]));
        assert_eq!(sessions[0].mic, Some([3; 16])); // M2 MIC, never M3 MIC
    }
    for counter in [0, 7, 9, u64::MAX] {
        assert!(extract(&[m2.clone(), self::m3(counter)]).is_empty());
    }
    assert!(extract(&[message(false, u64::MAX), self::m3(0)]).is_empty());
    let mut other_station = m3.clone();
    other_station.addr1[5] = 3;
    assert!(extract(&[m2.clone(), other_station]).is_empty());
    let mut other_ap = m3.clone();
    other_ap.addr2[5] = 3;
    assert!(extract(&[m2.clone(), other_ap]).is_empty());
    let mut direction = m3.clone();
    direction.frame_control = 0x0108;
    assert!(extract(&[m2.clone(), direction]).is_empty());
    for info in [0x13c9u16, 0x13cb, 0x138a, 0x1fca, 0x030a] {
        let mut bad = m3.clone();
        bad.payload[13..15].copy_from_slice(&info.to_be_bytes());
        assert!(extract(&[m2.clone(), bad]).is_empty(), "flags {info:x}");
    }
}

fn pmkid_m1(data: &[u8]) -> Dot11Frame {
    let mut f = message(true, 7);
    f.payload[8 + 2..8 + 4].copy_from_slice(&((95 + data.len()) as u16).to_be_bytes());
    f.payload[8 + 97..8 + 99].copy_from_slice(&(data.len() as u16).to_be_bytes());
    f.payload.extend_from_slice(data);
    f
}

#[test]
fn pmkid_kdes_validate_whole_tlv_list_and_reject_spurious_sources() {
    use air_handshake::extract_pmkid_targets;
    let mut kde = vec![221, 20, 0, 15, 172, 4];
    let id = [0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15]; // valid zero-leading ID
    kde.extend_from_slice(&id);
    let f = pmkid_m1(&kde);
    let targets = extract_pmkid_targets(&[f.clone(), f.clone()]);
    assert_eq!(targets.len(), 1);
    assert_eq!(targets[0].pmkid, id);
    for data in [
        kde[..kde.len() - 1].to_vec(),
        [kde.clone(), vec![0]].concat(),
        vec![221, 20, 0, 15, 172, 4],
        vec![
            221, 20, 0, 15, 172, 4, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
        ],
    ] {
        assert!(extract_pmkid_targets(&[pmkid_m1(&data)]).is_empty());
    }
    for offset in [2, 3, 4, 5] {
        let mut malformed = kde.clone();
        malformed[offset] ^= 1;
        assert!(extract_pmkid_targets(&[pmkid_m1(&malformed)]).is_empty());
    }
    let mut m2 = f.clone();
    m2.frame_control = 0x0108;
    m2.payload[13..15].copy_from_slice(&0x010au16.to_be_bytes());
    m2.payload[89..105].fill(3);
    assert!(extract_pmkid_targets(&[m2]).is_empty());
    let mut bad_sta = f.clone();
    bad_sta.addr1 = [255; 6];
    assert!(extract_pmkid_targets(&[bad_sta]).is_empty());
    let mut backwards = f;
    backwards.frame_control = 0x0108;
    assert!(extract_pmkid_targets(&[backwards]).is_empty());
}

#[test]
fn association_pmkid_list_requires_psk_akm_and_station_identity() {
    use air_handshake::extract_pmkid_targets;
    let ap = [2, 0, 0, 0, 0, 1];
    let sta = [2, 0, 0, 0, 0, 2];
    let mut rsn = vec![
        1, 0, 0, 15, 172, 4, 1, 0, 0, 15, 172, 4, 1, 0, 0, 15, 172, 2, 0, 0, 2, 0,
    ];
    rsn.extend_from_slice(&[1; 16]);
    rsn.extend_from_slice(&[2; 16]);
    let mut raw = vec![0; 24 + 4];
    raw[4..10].copy_from_slice(&ap);
    raw[10..16].copy_from_slice(&sta);
    raw[16..22].copy_from_slice(&ap);
    raw.extend_from_slice(&[48, rsn.len() as u8]);
    raw.extend_from_slice(&rsn);
    let f = parse_dot11(&raw).unwrap();
    assert_eq!(extract_pmkid_targets(std::slice::from_ref(&f)).len(), 2);
    for akm in [1, 3, 6, 8] {
        let mut bad = f.clone();
        bad.payload[4 + 2 + 17] = akm;
        assert!(extract_pmkid_targets(&[bad]).is_empty());
    }
    let mut bad = f.clone();
    bad.addr3[5] = 3;
    assert!(extract_pmkid_targets(&[bad]).is_empty());
    let mut beacon = f.clone();
    beacon.frame_control = 0x80;
    assert!(extract_pmkid_targets(&[beacon]).is_empty());
    let mut truncated = f;
    truncated.payload.pop();
    assert!(extract_pmkid_targets(&[truncated]).is_empty());
}

#[test]
fn bounded_extraction_rejects_combinations_before_building_unbounded_output() {
    use air_handshake::extract_targets_limited;
    let a = message(true, 1);
    let mut b = a.clone();
    b.payload[8 + 17] ^= 1;
    let c = message(false, 1);
    let mut d = c.clone();
    d.payload[8 + 81] ^= 1;
    let frames = [a, b, c, d];
    assert_eq!(extract_targets_limited(&frames, 4, 4).unwrap().len(), 4);
    assert!(extract_targets_limited(&frames, 4, 3).is_err());
    assert!(extract_targets_limited(&frames, 3, 4).is_err());
    assert!(extract_targets_limited(&frames, 0, 0).is_err());
}

#[test]
fn descriptor_types_and_versions_do_not_mix_between_messages() {
    let a = message(true, 1);
    let mut b = message(false, 1);
    b.payload[8 + 6] = 9; // supported HMAC-MD5 version, different from M1
    assert!(extract(&[a.clone(), b.clone()]).is_empty());
    let mut a = a;
    a.payload[8 + 6] = 0x89;
    assert_eq!(extract(&[a.clone(), b.clone()]).len(), 1);
    a.payload[8 + 4] = 254;
    assert!(extract(&[a.clone(), b.clone()]).is_empty());
    b.payload[8 + 4] = 254;
    assert_eq!(extract(&[a, b]).len(), 1);
    let mut unsupported = message(false, 1);
    unsupported.payload[8 + 6] = 0x0b; // v3 requires an explicit supported negotiated PSK RSN IE
    assert!(parse_eapol_key(&unsupported.payload[8..]).is_none());
}

#[test]
fn group_key_message_is_not_an_authenticator_nonce_for_pairwise_extraction() {
    let mut group = message(true, 1);
    group.payload[8 + 5..8 + 7].copy_from_slice(&0x1382u16.to_be_bytes());
    group.payload[8 + 81..8 + 97].fill(3);
    assert_eq!(parse_eapol_key(&group.payload[8..]).unwrap().message, 5);
    assert!(extract(&[message(false, 1), group]).is_empty());
}
