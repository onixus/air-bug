use air_capture::read_pcap;

#[test]
fn read_missing_file_errors() {
    assert!(read_pcap("/nonexistent.pcap").is_err());
}

#[test]
fn radiotap_alignment_extended_bitmap_flags_and_bounds() {
    use air_capture::dlt_decode;
    let raw = vec![0x08; 24];
    // Extended presence word, then alignment to an 8-byte TSFT, then flags.
    let mut radio = vec![0, 0, 25, 0];
    radio.extend_from_slice(&0x80000003u32.to_le_bytes());
    radio.extend_from_slice(&0u32.to_le_bytes());
    radio.extend_from_slice(&[0; 4]); // TSFT alignment
    radio.extend_from_slice(&[0; 8]); // TSFT
    radio.push(0x10); // FCS follows frame
    radio.extend_from_slice(&raw);
    radio.extend_from_slice(&[0; 4]);
    assert_eq!(dlt_decode(127, &radio).unwrap(), raw);
    radio[24] = 0x50; // bad FCS flag
    assert!(dlt_decode(127, &radio).is_err());
    for len in 0..25 {
        assert!(dlt_decode(127, &radio[..len]).is_err());
    }
    assert!(dlt_decode(119, &radio).is_err());
    assert!(dlt_decode(1, &radio).is_err()); // Ethernet is not a raw 802.11 payload
    assert!(dlt_decode(127, &[0, 0, 8, 0, 0, 0, 0, 128]).is_err()); // missing extension
}

#[test]
fn radiotap_removes_qos_padding_and_fcs_without_consuming_payload() {
    use air_capture::{decode_packet, dlt_decode, Packet};
    use air_frames::LLC_EAPOL;

    let mut header = vec![0; 26];
    header[..2].copy_from_slice(&0x0188u16.to_le_bytes());
    let mut radio = vec![0, 0, 9, 0, 2, 0, 0, 0, 0x30]; // flags: padding + FCS
    radio.extend_from_slice(&header);
    radio.extend_from_slice(&[0, 0]); // 26-byte QoS header padded to 28 bytes
    radio.extend_from_slice(&LLC_EAPOL);
    radio.extend_from_slice(b"payload");
    radio.extend_from_slice(&[0xde, 0xad, 0xbe, 0xef]);
    let mut expected = header;
    expected.extend_from_slice(&LLC_EAPOL);
    expected.extend_from_slice(b"payload");
    assert_eq!(dlt_decode(127, &radio).unwrap(), expected);
    let parsed = decode_packet(&Packet {
        data: radio.clone(),
        dlt: 127,
    })
    .unwrap();
    assert_eq!(&parsed.payload[..8], &LLC_EAPOL);
    assert_eq!(&parsed.payload[8..], b"payload");

    // A truncated padding region cannot be repaired by consuming FCS bytes.
    radio.truncate(9 + 26 + 1);
    radio.extend_from_slice(&[0; 4]);
    assert!(dlt_decode(127, &radio).is_err());
}

#[test]
fn malformed_ethernet_and_radiotap_inputs_never_panic() {
    use air_capture::{decode_packet, dlt_decode, Packet};
    for len in 0..128 {
        for value in [0, 0xff, 0x80] {
            let data = vec![value; len];
            let _ = dlt_decode(127, &data);
            let _ = decode_packet(&Packet { data, dlt: 1 });
        }
    }
}

#[test]
fn pcapng_rejects_invalid_interface_and_truncated_container() {
    let fixture = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../tests/fixtures/wpa2-mixed.pcapng");
    let mut bytes = std::fs::read(fixture).unwrap();
    // First SHB (28 bytes) + IDB (20 bytes), then EPB: interface ID at offset 56.
    bytes[56..60].copy_from_slice(&9u32.to_le_bytes());
    let path =
        std::env::temp_dir().join(format!("air-capture-invalid-{}.pcapng", std::process::id()));
    std::fs::write(&path, &bytes).unwrap();
    assert!(read_pcap(&path).is_err());
    bytes.truncate(30);
    std::fs::write(&path, &bytes).unwrap();
    assert!(read_pcap(&path).is_err());
    std::fs::remove_file(path).unwrap();
}

#[test]
fn capture_limits_accept_exact_bounds_and_reject_one_less() {
    use air_capture::{read_pcap_with_limits, CaptureLimits};
    for name in ["wpa2-raw.pcap", "wpa2-mixed.pcapng", "wpa2-simple.pcapng"] {
        let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../../tests/fixtures")
            .join(name);
        let bytes = std::fs::metadata(&path).unwrap().len();
        let packets = read_pcap(&path).unwrap().len();
        assert_eq!(
            read_pcap_with_limits(&path, CaptureLimits { bytes, packets })
                .unwrap()
                .len(),
            packets
        );
        assert!(read_pcap_with_limits(
            &path,
            CaptureLimits {
                bytes: bytes - 1,
                packets
            }
        )
        .is_err());
        assert!(read_pcap_with_limits(
            &path,
            CaptureLimits {
                bytes,
                packets: packets - 1
            }
        )
        .is_err());
    }
}
