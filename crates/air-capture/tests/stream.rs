use air_capture::{evidence::Evidence, CaptureLimits, CaptureReader};
use air_frames::{Dot11Frame, FrameKind, LLC_EAPOL};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicUsize, Ordering};
struct Temp(PathBuf);
impl Temp {
    fn new(bytes: &[u8]) -> Self {
        static NEXT: AtomicUsize = AtomicUsize::new(0);
        let p = std::env::temp_dir().join(format!(
            "air-stream-{}-{}",
            std::process::id(),
            NEXT.fetch_add(1, Ordering::Relaxed)
        ));
        std::fs::write(&p, bytes).unwrap();
        Self(p)
    }
}
impl Drop for Temp {
    fn drop(&mut self) {
        let _ = std::fs::remove_file(&self.0);
    }
}
fn fixture(name: &str) -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../tests/fixtures")
        .join(name)
}
#[test]
fn iteration_is_lazy_and_errors_are_terminal() {
    let mut bytes = std::fs::read(fixture("wpa2-raw.pcap")).unwrap();
    bytes.extend_from_slice(&[0; 9]);
    let file = Temp::new(&bytes);
    let mut reader = CaptureReader::open(&file.0, CaptureLimits::default()).unwrap();
    let count = CaptureReader::open(fixture("wpa2-raw.pcap"), CaptureLimits::default())
        .unwrap()
        .count();
    for _ in 0..count {
        assert!(reader.next().unwrap().is_ok());
    }
    assert!(reader.next().unwrap().is_err());
    assert!(reader.next().is_none());
    let mut reader = CaptureReader::open(
        &file.0,
        CaptureLimits {
            bytes: bytes.len() as u64,
            packets: 0,
        },
    )
    .unwrap();
    assert!(reader
        .next()
        .unwrap()
        .unwrap_err()
        .to_string()
        .contains("packet limit"));
    assert!(reader.next().is_none());
}
#[test]
fn classic_pcap_endian_and_timestamp_precision_are_preserved() {
    for (little, nano) in [(true, false), (false, false), (true, true), (false, true)] {
        let mut bytes: Vec<u8> = match (little, nano) {
            (true, false) => vec![0xd4, 0xc3, 0xb2, 0xa1],
            (false, false) => vec![0xa1, 0xb2, 0xc3, 0xd4],
            (true, true) => vec![0x4d, 0x3c, 0xb2, 0xa1],
            (false, true) => vec![0xa1, 0xb2, 0x3c, 0x4d],
        };
        bytes.extend_from_slice(if little { &[2, 0, 4, 0] } else { &[0, 2, 0, 4] });
        for n in [0u32, 0, 65535, 105, 7, 123, 3, 5] {
            bytes.extend_from_slice(&if little {
                n.to_le_bytes()
            } else {
                n.to_be_bytes()
            });
        }
        bytes.extend_from_slice(&[1, 2, 3]);
        let file = Temp::new(&bytes);
        let record = CaptureReader::open(&file.0, CaptureLimits::default())
            .unwrap()
            .next()
            .unwrap()
            .unwrap();
        assert_eq!(record.packet.data, [1, 2, 3]);
        assert_eq!(record.original_len, 5);
        assert_eq!(
            record.timestamp.unwrap().subsec_nanos(),
            if nano { 123 } else { 123000 }
        );
    }
}
#[test]
fn pcapng_section_interfaces_reset_without_losing_records() {
    let bytes = std::fs::read(fixture("wpa2-mixed.pcapng")).unwrap();
    let original: Vec<_> =
        CaptureReader::open(fixture("wpa2-mixed.pcapng"), CaptureLimits::default())
            .unwrap()
            .collect::<Result<_, _>>()
            .unwrap();
    let mut joined = bytes.clone();
    joined.extend_from_slice(&bytes);
    let file = Temp::new(&joined);
    let records: Vec<_> = CaptureReader::open(&file.0, CaptureLimits::default())
        .unwrap()
        .collect::<Result<_, _>>()
        .unwrap();
    assert_eq!(records.len(), original.len() * 2);
    for (a, b) in records.iter().zip(original.iter().cycle()) {
        assert_eq!(a.packet.dlt, b.packet.dlt);
        assert_eq!(a.packet.data, b.packet.data);
        assert_eq!(a.timestamp, b.timestamp);
    }
}
#[test]
fn evidence_discards_data_deduplicates_and_enforces_memory_budgets() {
    let mut evidence = Evidence::new(1);
    let mut frame = Dot11Frame {
        kind: FrameKind::Data,
        frame_control: 0x208,
        addr1: [2; 6],
        addr2: [4; 6],
        addr3: [6; 6],
        addr4: None,
        payload: vec![0; 2048],
    };
    for _ in 0..5000 {
        assert!(!evidence.push(frame.clone()).unwrap());
    }
    assert!(evidence.frames.is_empty());
    frame.payload = LLC_EAPOL.to_vec();
    assert!(evidence.push(frame.clone()).unwrap());
    assert!(!evidence.push(frame.clone()).unwrap());
    frame.payload.push(1);
    assert!(evidence.push(frame.clone()).is_err());
    assert_eq!(evidence.frames.len(), 1);
    let mut evidence = Evidence::new(1024);
    frame.payload.resize(65535, 0);
    for n in 0..64 {
        frame.addr1[5] = n;
        assert!(evidence.push(frame.clone()).unwrap());
    }
    frame.addr1[5] = 65;
    assert!(evidence.push(frame).is_err());
}

#[test]
fn pcap_accepts_wire_lengths_larger_than_snaplen_and_rejects_invalid_records() {
    fn pcap(snap: u32, frac: u32, incl: u32, original: u32) -> Vec<u8> {
        let mut data = vec![0xd4, 0xc3, 0xb2, 0xa1, 2, 0, 4, 0];
        for value in [0u32, 0, snap, 105, 7, frac, incl, original] {
            data.extend(value.to_le_bytes());
        }
        data.extend(vec![0; incl as usize]);
        data
    }
    let file = Temp::new(&pcap(3, 123, 3, 200));
    let record = CaptureReader::open(&file.0, CaptureLimits::default())
        .unwrap()
        .next()
        .unwrap()
        .unwrap();
    assert_eq!(record.packet.data.len(), 3);
    assert_eq!(record.original_len, 200);
    assert_eq!(record.timestamp.unwrap().subsec_nanos(), 123000);
    for bytes in [
        pcap(2, 0, 3, 200),
        pcap(4, 0, 3, 2),
        pcap(4, 1_000_000, 3, 3),
    ] {
        let file = Temp::new(&bytes);
        let mut reader = CaptureReader::open(&file.0, CaptureLimits::default()).unwrap();
        assert!(reader.next().unwrap().is_err());
        assert!(reader.next().is_none());
    }
}
