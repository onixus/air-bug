use air_frames::{parse_dot11, ssid_bytes_from_beacon, ssid_from_beacon, FrameKind};

#[test]
fn header_boundaries_and_unsupported_frames() {
    for len in 0..24 {
        assert!(parse_dot11(&vec![0; len]).is_err());
    }
    let mut frame = vec![0; 24];
    frame[0] = 8;
    let parsed = parse_dot11(&frame).unwrap();
    assert_eq!(parsed.kind, FrameKind::Data);
    assert!(parsed.payload.is_empty());
    frame[0] = 0x88; // QoS requires 2 more header bytes
    assert!(parse_dot11(&frame).is_err());
    frame.extend_from_slice(&[0, 0]);
    frame.extend_from_slice(b"payload");
    assert_eq!(parse_dot11(&frame).unwrap().payload, b"payload");
    frame[1] = 0x40; // protected
    assert!(parse_dot11(&frame).is_err());
    frame[1] = 0x04; // More Fragments
    assert!(parse_dot11(&frame).is_err());
    frame[1] = 0;
    frame[22] = 1; // non-first fragment
    assert!(parse_dot11(&frame).is_err());
    frame[22] = 0;
    frame[24] = 0x80; // A-MSDU
    assert!(parse_dot11(&frame).is_err());
}

#[test]
fn fragmented_management_frames_are_not_parsed_as_complete_beacons() {
    let mut bytes = vec![0; 24 + 12];
    bytes[0] = 0x80;
    bytes.extend_from_slice(&[0, 4, b't', b'e', b's', b't']);
    assert!(parse_dot11(&bytes).is_ok());

    bytes[1] = 0x04; // First fragment, with More Fragments set.
    assert!(parse_dot11(&bytes).is_err());
    bytes[1] = 0;
    bytes[22] = 1; // Final fragment is also not a complete management body.
    assert!(parse_dot11(&bytes).is_err());
}

#[test]
fn beacon_skips_fixed_fields_and_preserves_ssid_bytes() {
    let mut bytes = vec![0; 24 + 12];
    bytes[0] = 0x80;
    bytes.extend_from_slice(&[0, 4, b't', b'e', b's', b't']);
    let frame = parse_dot11(&bytes).unwrap();
    assert_eq!(ssid_from_beacon(&frame).as_deref(), Some("test"));
    bytes[38] = 0xff;
    let frame = parse_dot11(&bytes).unwrap();
    assert_eq!(
        ssid_bytes_from_beacon(&frame),
        Some(&[0xff, b'e', b's', b't'][..])
    );
    assert!(ssid_from_beacon(&frame).is_none());
    bytes[37] = 0xff; // truncated IE
    assert!(ssid_from_beacon(&parse_dot11(&bytes).unwrap()).is_none());
}
