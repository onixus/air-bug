use air_core::{mic, pmk, ptk};
use air_crack::{engine::CrackError, verify::constant_time_eq, Engine};
use air_handshake::HandshakeSession;
use std::io;

fn session(passphrase: &str) -> HandshakeSession {
    let bssid = [2, 0, 0, 0, 0, 1];
    let sta = [2, 0, 0, 0, 0, 2];
    let anonce = [1; 32];
    let snonce = [2; 32];
    let mut eapol = vec![0; 99];
    eapol[0] = 2;
    eapol[1] = 3;
    eapol[2..4].copy_from_slice(&95u16.to_be_bytes());
    eapol[4] = 2;
    eapol[5..7].copy_from_slice(&0x010au16.to_be_bytes());
    eapol[17..49].copy_from_slice(&snonce);
    let key = ptk(&pmk(passphrase, b"test"), &bssid, &sta, &anonce, &snonce);
    let target = mic(&key, &eapol);
    HandshakeSession {
        bssid,
        sta,
        anonce: Some(anonce),
        snonce: Some(snonce),
        eapol,
        mic: Some(target),
        count: 2,
        nonce_source: None,
    }
}

#[test]
fn ct_eq() {
    assert!(constant_time_eq(b"abc", b"abc"));
    assert!(!constant_time_eq(b"abc", b"abd"));
    assert!(!constant_time_eq(b"abc", b"abcd"));
    assert!(constant_time_eq(b"", b""));
}

#[test]
fn verifies_only_matching_candidates() {
    let engine = Engine::new(session("password"), b"test".to_vec()).unwrap();
    assert!(engine.verify_candidate("password"));
    assert!(!engine.verify_candidate("wrongpass"));
    assert!(!engine.verify_candidate("short"));
    assert!(!engine.verify_candidate(&"a".repeat(64)));
    assert_eq!(
        engine.crack(vec!["short".into(), "password".into()]),
        Some("password".into())
    );
}

#[test]
fn rejects_control_characters_even_when_mic_matches() {
    for pass in ["pass\0word", "pass\nword", "pass\x7fword", "passéword"] {
        let engine = Engine::new(session(pass), b"test".to_vec()).unwrap();
        assert!(!engine.verify_candidate(pass));
    }
    let engine = Engine::new(session(" pass word "), b"test".to_vec()).unwrap();
    assert!(engine.verify_candidate(" pass word "));
}

#[test]
fn rejects_invalid_ssid_and_inconsistent_sessions_without_panicking() {
    let valid = session("password");
    for ssid in [vec![], vec![b'x'; 33]] {
        assert!(matches!(
            Engine::new(valid.clone(), ssid),
            Err(CrackError::InvalidSsid)
        ));
    }
    for length in 0..99 {
        let mut invalid = valid.clone();
        invalid.eapol.truncate(length);
        assert!(Engine::new(invalid, b"test".to_vec()).is_err());
    }
    let mut variants = Vec::new();
    let mut invalid = valid.clone();
    invalid.snonce = Some([3; 32]);
    variants.push(invalid);
    let mut invalid = valid.clone();
    invalid.eapol[81] = 1;
    variants.push(invalid);
    let mut invalid = valid.clone();
    invalid.eapol.push(0);
    variants.push(invalid);
    let mut invalid = valid.clone();
    invalid.bssid[0] = 1;
    variants.push(invalid);
    let mut invalid = valid;
    invalid.anonce = None;
    variants.push(invalid);
    for invalid in variants {
        assert!(Engine::new(invalid, b"test".to_vec()).is_err());
    }
}

#[test]
fn wordlist_batches_propagate_late_errors_and_find_late_candidates() {
    let engine = Engine::new(session("password"), b"test".to_vec()).unwrap();
    let candidates = (0..257)
        .map(|_| Ok("short".to_owned()))
        .chain(std::iter::once(Ok("password".to_owned())));
    assert_eq!(
        engine.crack_wordlist(candidates).unwrap(),
        Some("password".to_owned())
    );
    let candidates = (0..257)
        .map(|_| Ok("short".to_owned()))
        .chain(std::iter::once(Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "bad wordlist",
        ))));
    assert!(
        matches!(engine.crack_wordlist(candidates), Err(CrackError::Wordlist(error)) if error.kind() == io::ErrorKind::InvalidData)
    );
    assert!(engine.crack_wordlist(std::iter::empty()).unwrap().is_none());
}

#[test]
fn target_set_checks_all_targets_and_preserves_first_dictionary_match() {
    use air_crack::engine::TargetSet;
    use air_handshake::{PmkidSession, VerificationTarget};
    let ssid = b"Test Network";
    let bssid = [2, 0, 0, 0, 0, 1];
    let sta = [2, 0, 0, 0, 0, 2];
    let target = |pass: &str| {
        VerificationTarget::Pmkid(PmkidSession {
            bssid,
            sta,
            pmkid: air_core::pmkid(&air_core::pmk(pass, ssid), &bssid, &sta),
        })
    };
    // Two targets deliberately validate different passwords: first dictionary
    // position must win, irrespective of target order or Rayon scheduling.
    let set = TargetSet::new(
        vec![target("second password"), target("first password")],
        ssid.to_vec(),
    )
    .unwrap();
    let result = set.crack_batch(&[
        "wrong password".into(),
        "first password".into(),
        "second password".into(),
    ]);
    assert_eq!(result, Some((1, "first password".into())));
    assert!(!set.verify_candidate("wrong password"));
    assert!(!set.verify_candidate("tiny"));
    assert!(TargetSet::new(vec![], ssid.to_vec()).is_err());
}
