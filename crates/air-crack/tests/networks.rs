use air_crack::{
    engine::TargetSet,
    networks::{Network, Networks},
};
use air_handshake::{PmkidSession, VerificationTarget};
fn network(ap: [u8; 6], ssid: &[u8]) -> Network {
    let root = air_core::pmk("test password", ssid);
    let targets = TargetSet::new(
        vec![VerificationTarget::Pmkid(PmkidSession {
            bssid: ap,
            sta: [2, 0, 0, 0, 1, 1],
            pmkid: air_core::pmkid(&root, &ap, &[2, 0, 0, 0, 1, 1]),
        })],
        ssid.to_vec(),
    )
    .unwrap();
    Network {
        bssid: ap,
        ssid: ssid.to_vec(),
        targets,
    }
}
#[test]
fn network_identifiers_must_match_the_validated_targets() {
    let ap = [2, 0, 0, 0, 0, 1];
    let mut wrong = network(ap, b"SSID");
    wrong.bssid[5] = 2;
    assert!(Networks::new(vec![wrong]).is_err());
    let mut wrong = network(ap, b"SSID");
    wrong.ssid = b"Other".to_vec();
    assert!(Networks::new(vec![wrong]).is_err());
    assert!(Networks::new(vec![network(ap, b"SSID"), network(ap, b"SSID")]).is_err());
}
#[test]
fn bounded_grouped_verification_skips_completed_networks() {
    let networks = Networks::new(vec![
        network([2, 0, 0, 0, 0, 1], b"SSID"),
        network([2, 0, 0, 0, 0, 2], b"SSID"),
    ])
    .unwrap();
    assert_eq!(networks.groups(), 1);
    let words = vec![
        "incorrect password".into(),
        "test password".into(),
        "test password".into(),
    ];
    assert_eq!(
        networks.crack_batch(&words, &[false, false], None).unwrap(),
        vec![Some(1), Some(1)]
    );
    assert_eq!(
        networks.crack_batch(&words, &[true, false], None).unwrap(),
        vec![None, Some(1)]
    );
    assert!(networks.crack_batch(&words, &[], None).is_err());
    assert!(networks
        .crack_batch(&vec!["test password".into(); 257], &[false, false], None)
        .is_err());
}
