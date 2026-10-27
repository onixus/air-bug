use air_core::{mic, pmk, ptk};

fn vector(name: &str) -> Vec<u8> {
    let vectors = include_str!("../../../tests/fixtures/vectors.txt");
    let value = vectors
        .lines()
        .find_map(|l| l.strip_prefix(&format!("{name}=")))
        .unwrap();
    hex::decode(value).unwrap()
}

#[test]
fn published_wpa_pmk_vector() {
    assert_eq!(
        hex::encode(pmk("password", b"IEEE")),
        "f42c6fc52df0ebef9ebb4b90b38a5f902e83fe1b135a70e23aed762e9710a12e"
    );
}

#[test]
fn independent_python_pmk_ptk_mic_vectors() {
    let pmk = pmk("correct horse battery", b"Test Network");
    assert_eq!(pmk.as_slice(), vector("pmk"));
    let a = [2, 0, 0, 0, 0, 1];
    let b = [2, 0, 0, 0, 0, 2];
    let anonce = std::array::from_fn(|i| i as u8 + 1);
    let snonce = std::array::from_fn(|i| i as u8 + 33);
    let key = ptk(&pmk, &a, &b, &anonce, &snonce);
    assert_eq!(key.as_slice(), vector("ptk"));
    assert_eq!(key, ptk(&pmk, &b, &a, &snonce, &anonce));
    // MAC and nonce ordering are independent, not paired endpoint ordering.
    assert_eq!(key, ptk(&pmk, &b, &a, &anonce, &snonce));
    assert_eq!(key, ptk(&pmk, &a, &b, &snonce, &anonce));
    assert_eq!(mic(&key, &vector("eapol_zero")).as_slice(), vector("mic"));
}

#[test]
fn pmkid_independent_vector_preserves_ap_sta_order() {
    let pmk = pmk("correct horse battery", b"Test Network");
    let ap = [2, 0, 0, 0, 0, 1];
    let sta = [2, 0, 0, 0, 0, 2];
    let expected =
        hex::decode(include_str!("../../../tests/fixtures/pmkid-vector.txt").trim()).unwrap();
    assert_eq!(air_core::pmkid(&pmk, &ap, &sta).as_slice(), expected);
    assert_ne!(
        air_core::pmkid(&pmk, &ap, &sta),
        air_core::pmkid(&pmk, &sta, &ap)
    );
}

#[test]
fn hmac_md5_matches_rfc2202_and_hex_psk_bypasses_passphrase_derivation() {
    let ptk = [0x0b; 48];
    assert_eq!(
        hex::encode(air_core::mic_version(&ptk, b"Hi There", 1).unwrap()),
        "9294727a3638bb1c13f48ef8158bfc9d"
    );
    assert!(air_core::mic_version(&ptk, b"Hi There", 4).is_none());
    assert_eq!(
        air_core::candidate_pmk(&"ab".repeat(32), b"any SSID"),
        Some([0xab; 32])
    );
    assert!(air_core::candidate_pmk(&"xz".repeat(32), b"any SSID").is_none());
}

#[test]
fn aes_cmac_and_unwrap_match_published_rfc_vectors() {
    let mut ptk = [0; 48];
    ptk[..16].copy_from_slice(&hex::decode("2b7e151628aed2a6abf7158809cf4f3c").unwrap());
    assert_eq!(
        hex::encode(air_core::mic_version(&ptk, b"", 3).unwrap()),
        "bb1d6929e95937287fa37d129b756746"
    );
    let kek: [u8; 16] = hex::decode("000102030405060708090a0b0c0d0e0f")
        .unwrap()
        .try_into()
        .unwrap();
    let mut wrapped = hex::decode("1fa68b0a8112b447aef34bd8fb5a7b829d3e862371d2cfe5").unwrap();
    assert_eq!(
        hex::encode(air_core::unwrap_key_data(&kek, &wrapped).unwrap()),
        "00112233445566778899aabbccddeeff"
    );
    wrapped[0] ^= 1;
    assert!(air_core::unwrap_key_data(&kek, &wrapped).is_none());
    assert!(air_core::unwrap_key_data(&kek, &wrapped[..17]).is_none());
}
#[test]
fn extended_ptk_and_tkip_seed_match_independent_vectors() {
    let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../../tests/fixtures");
    // Expected byte strings come from the independent Python/OpenSSL generator.
    let text = std::fs::read_to_string(root.join("advanced-vectors.json")).unwrap();
    let get = |name: &str| {
        text.lines()
            .find(|l| l.contains(&format!("\"{name}\"")))
            .unwrap()
            .split('"')
            .nth(3)
            .unwrap()
            .to_string()
    };
    let pmk = air_core::pmk("correct horse battery", b"Test Network");
    let an = std::array::from_fn(|i| i as u8 + 1);
    let sn = std::array::from_fn(|i| i as u8 + 33);
    let ap = [2, 0, 0, 0, 0, 1];
    let sta = [2, 0, 0, 0, 0, 2];
    let sha = air_core::ptk_extended(&pmk, &ap, &sta, &an, &sn, true);
    assert_eq!(hex::encode(&sha[..48]), get("ptk_sha256"));
    let legacy = air_core::ptk_extended(&pmk, &ap, &sta, &an, &sn, false);
    assert_eq!(
        hex::encode(air_core::tkip::seed(
            legacy[32..48].try_into().unwrap(),
            &ap,
            &[1, 0, 0, 0, 0, 0]
        )),
        get("tkip_seed")
    );
}
