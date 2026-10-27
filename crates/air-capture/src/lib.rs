use air_frames::{parse_dot11, wire_header_len, Dot11Frame, LLC_EAPOL};
use pcap_file::pcap::PcapReader;
use pcap_file::pcapng::{Block, PcapNgReader};
use std::fs::File;
use std::io::{BufReader, Read, Seek};
use std::path::Path;
use thiserror::Error;

#[derive(Debug, Error)]
pub enum CaptureError {
    #[error("io: {0}")]
    Io(#[from] std::io::Error),
    #[error("pcap: {0}")]
    Pcap(String),
    #[error("unsupported dlt: {0}")]
    UnsupportedDlt(u32),
}

#[derive(Debug, Clone)]
pub struct Packet {
    pub data: Vec<u8>,
    pub dlt: u32,
}

/// Return an unpadded 802.11 frame. Ethernet is handled separately by decode_packet.
pub fn dlt_decode(dlt: u32, data: &[u8]) -> Result<Vec<u8>, CaptureError> {
    match dlt {
        105 => Ok(data.to_vec()),
        127 => {
            let bad = || CaptureError::Pcap("malformed radiotap packet".into());
            if data.len() < 8 || data[0] != 0 {
                return Err(bad());
            }
            let len = u16::from_le_bytes([data[2], data[3]]) as usize;
            if len < 8 || len > data.len() {
                return Err(bad());
            }
            let present = u32::from_le_bytes(data[4..8].try_into().map_err(|_| bad())?);
            let mut end = 8;
            let mut word = present;
            while word & (1 << 31) != 0 {
                let bytes = data
                    .get(end..end + 4)
                    .filter(|_| end + 4 <= len)
                    .ok_or_else(bad)?;
                word = u32::from_le_bytes(bytes.try_into().map_err(|_| bad())?);
                end += 4;
            }
            let mut flags = 0;
            if present & 1 != 0 {
                end = (end + 7) & !7;
                end += 8;
            }
            if end > len {
                return Err(bad());
            }
            if present & 2 != 0 {
                if end >= len {
                    return Err(bad());
                }
                flags = data[end];
            }
            if flags & 0x40 != 0 {
                return Err(CaptureError::Pcap("bad FCS".into()));
            }
            let mut frame = data[len..].to_vec();
            if flags & 0x10 != 0 {
                if frame.len() < 4 {
                    return Err(bad());
                }
                frame.truncate(frame.len() - 4);
            }
            if flags & 0x20 != 0 {
                let header = wire_header_len(&frame).map_err(|_| bad())?;
                let padded = (header + 3) & !3;
                if frame.len() < padded {
                    return Err(bad());
                }
                frame.drain(header..padded);
            }
            Ok(frame)
        }
        _ => Err(CaptureError::UnsupportedDlt(dlt)),
    }
}

/// Normalize Ethernet EAPOL or decode raw/radiotap 802.11.
fn normalize_packet(packet: &Packet) -> Result<Vec<u8>, CaptureError> {
    let frame = if packet.dlt == 1 {
        let data = &packet.data;
        if data.len() < 21 || data[12..14] != [0x88, 0x8e] || data[15] != 3 {
            return Err(CaptureError::Pcap(
                "not an Ethernet EAPOL-Key packet".into(),
            ));
        }
        // In an infrastructure EAPOL exchange the ACK flag identifies the AP sender.
        let from_ap = data[20] & 0x80 != 0;
        let mut raw = vec![0; 24];
        raw[..2].copy_from_slice(&(if from_ap { 0x0208u16 } else { 0x0108u16 }).to_le_bytes());
        raw[4..10].copy_from_slice(&data[..6]);
        raw[10..16].copy_from_slice(&data[6..12]);
        let ap = if from_ap { &data[6..12] } else { &data[..6] };
        raw[16..22].copy_from_slice(ap);
        raw.extend_from_slice(&LLC_EAPOL);
        raw.extend_from_slice(&data[14..]);
        raw
    } else {
        dlt_decode(packet.dlt, &packet.data)?
    };
    Ok(frame)
}

pub fn decode_packet(packet: &Packet) -> Result<Dot11Frame, CaptureError> {
    parse_dot11(&normalize_packet(packet)?).map_err(|e| CaptureError::Pcap(e.to_string()))
}

/// Hard ceilings for desktop/offline parsing; exceeding a limit is an error,
/// never a partial successful capture.
#[derive(Clone, Copy, Debug)]
pub struct CaptureLimits {
    pub bytes: u64,
    pub packets: usize,
}
impl Default for CaptureLimits {
    fn default() -> Self {
        Self {
            bytes: 64 * 1024 * 1024,
            packets: 100_000,
        }
    }
}

struct BudgetReader<R> {
    inner: R,
    remaining: u64,
}
impl<R: Read> Read for BudgetReader<R> {
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        if buf.is_empty() {
            return Ok(0);
        }
        if self.remaining == 0 {
            let mut probe = [0];
            return if self.inner.read(&mut probe)? == 0 {
                Ok(0)
            } else {
                Err(std::io::Error::other("capture byte limit exceeded"))
            };
        }
        let len = buf
            .len()
            .min(self.remaining.min(usize::MAX as u64) as usize);
        let n = self.inner.read(&mut buf[..len])?;
        self.remaining -= n as u64;
        Ok(n)
    }
}

pub fn read_pcap(path: impl AsRef<Path>) -> Result<Vec<Packet>, CaptureError> {
    read_pcap_with_limits(path, CaptureLimits::default())
}

pub fn read_pcap_with_limits(
    path: impl AsRef<Path>,
    limits: CaptureLimits,
) -> Result<Vec<Packet>, CaptureError> {
    Ok(read_pcap_records(path, limits)?
        .into_iter()
        .map(|record| record.packet)
        .collect())
}

#[derive(Debug)]
pub struct PacketRecord {
    pub packet: Packet,
    pub timestamp: Option<std::time::Duration>,
    pub original_len: u32,
}

/// Compatibility collector. Streaming consumers should use `CaptureReader`.
pub fn read_pcap_records(
    path: impl AsRef<Path>,
    limits: CaptureLimits,
) -> Result<Vec<PacketRecord>, CaptureError> {
    CaptureReader::open(path, limits)?.collect()
}

type Input = BufReader<BudgetReader<File>>;
type Interface = (u32, u32, u8, i64);
enum Container {
    Pcap(PcapReader<Input>),
    Ng(PcapNgReader<Input>, Vec<Interface>),
}
/// Pull-based PCAP/PCAPng reader. Retains one record, bounded parser buffers,
/// and at most 256 interfaces; file size and packet counts are work budgets.
pub struct CaptureReader {
    container: Container,
    remaining: usize,
    done: bool,
}
impl CaptureReader {
    pub fn open(path: impl AsRef<Path>, limits: CaptureLimits) -> Result<Self, CaptureError> {
        let mut f = File::open(path)?;
        let metadata = f.metadata()?;
        if !metadata.is_file() || metadata.len() > limits.bytes {
            return Err(CaptureError::Pcap(
                "capture byte limit exceeded or not a regular file".into(),
            ));
        }
        // peek magic
        let mut magic = [0u8; 4];
        f.read_exact(&mut magic)?;
        f.seek(std::io::SeekFrom::Start(0))?;
        let f = BudgetReader {
            inner: f,
            remaining: limits.bytes,
        };
        let input = BufReader::new(f);
        let container = if magic == [0x0a, 0x0d, 0x0d, 0x0a] {
            Container::Ng(
                PcapNgReader::new(input).map_err(|e| CaptureError::Pcap(e.to_string()))?,
                Vec::new(),
            )
        } else {
            Container::Pcap(PcapReader::new(input).map_err(|e| CaptureError::Pcap(e.to_string()))?)
        };
        Ok(Self {
            container,
            remaining: limits.packets,
            done: false,
        })
    }
    fn next_record(&mut self) -> Result<Option<PacketRecord>, CaptureError> {
        match &mut self.container {
            Container::Ng(reader, interfaces) => {
                while let Some(blk) = reader.next_block() {
                    let blk = blk.map_err(|e| CaptureError::Pcap(e.to_string()))?;
                    match blk {
                        Block::SectionHeader(_) => interfaces.clear(),
                        Block::InterfaceDescription(idb) => {
                            if interfaces.len() >= 256 {
                                return Err(CaptureError::Pcap(
                                    "capture interface limit exceeded".into(),
                                ));
                            }
                            use pcap_file::pcapng::blocks::interface_description::InterfaceDescriptionOption;
                            let mut resolution = 6;
                            let mut offset = 0i64;
                            for option in idb.options {
                                match option {
                                    InterfaceDescriptionOption::IfTsResol(value) => {
                                        resolution = value
                                    }
                                    InterfaceDescriptionOption::IfTsOffset(value) => {
                                        offset = value as i64
                                    }
                                    _ => {}
                                }
                            }
                            interfaces.push((
                                u32::from(idb.linktype),
                                idb.snaplen,
                                resolution,
                                offset,
                            ))
                        }
                        Block::EnhancedPacket(epb) => {
                            let (dlt, _, resolution, offset) = interfaces
                                .get(epb.interface_id as usize)
                                .copied()
                                .ok_or_else(|| {
                                    CaptureError::Pcap("unknown pcapng interface".into())
                                })?;
                            let denominator = if resolution & 128 == 0 {
                                10u128.checked_pow(resolution as u32)
                            } else {
                                1u128.checked_shl((resolution & 127) as u32)
                            }
                            .ok_or_else(|| {
                                CaptureError::Pcap("unsupported pcapng timestamp resolution".into())
                            })?;
                            let ns = ((epb.timestamp.as_nanos() * 1_000_000_000) / denominator)
                                as i128
                                + offset as i128 * 1_000_000_000;
                            if ns < 0 || ns / 1_000_000_000 > u64::MAX as i128 {
                                return Err(CaptureError::Pcap(
                                    "pcapng timestamp out of range".into(),
                                ));
                            }
                            return Ok(Some(PacketRecord {
                                timestamp: Some(std::time::Duration::new(
                                    (ns / 1_000_000_000) as u64,
                                    (ns % 1_000_000_000) as u32,
                                )),
                                original_len: epb.original_len,
                                packet: Packet {
                                    data: epb.data.to_vec(),
                                    dlt,
                                },
                            }));
                        }
                        Block::SimplePacket(spb) => {
                            let (dlt, snaplen, _, _) =
                                interfaces.first().copied().ok_or_else(|| {
                                    CaptureError::Pcap("missing pcapng interface".into())
                                })?;
                            let captured = if snaplen == 0 {
                                spb.original_len
                            } else {
                                spb.original_len.min(snaplen)
                            } as usize;
                            let data = spb.data.get(..captured).ok_or_else(|| {
                                CaptureError::Pcap("truncated simple packet".into())
                            })?;
                            return Ok(Some(PacketRecord {
                                timestamp: None,
                                original_len: spb.original_len,
                                packet: Packet {
                                    data: data.to_vec(),
                                    dlt,
                                },
                            }));
                        }
                        _ => {}
                    }
                }
                Ok(None)
            }
            Container::Pcap(reader) => {
                let header = reader.header();
                if let Some(pkt) = reader.next_raw_packet() {
                    let pkt = pkt.map_err(|e| CaptureError::Pcap(e.to_string()))?;
                    // Only captured bytes are constrained by snaplen. The original
                    // wire length can legitimately be larger on truncated records.
                    if pkt.incl_len > header.snaplen || pkt.incl_len > pkt.orig_len {
                        return Err(CaptureError::Pcap("invalid pcap record length".into()));
                    }
                    let nanos = match header.ts_resolution {
                        pcap_file::TsResolution::MicroSecond => pkt.ts_frac.checked_mul(1000),
                        pcap_file::TsResolution::NanoSecond => Some(pkt.ts_frac),
                    }
                    .filter(|n| *n < 1_000_000_000)
                    .ok_or_else(|| CaptureError::Pcap("invalid pcap timestamp".into()))?;
                    return Ok(Some(PacketRecord {
                        timestamp: Some(std::time::Duration::new(pkt.ts_sec.into(), nanos)),
                        original_len: pkt.orig_len,
                        packet: Packet {
                            data: pkt.data.into_owned(),
                            dlt: u32::from(header.datalink),
                        },
                    }));
                }
                Ok(None)
            }
        }
    }
}
impl Iterator for CaptureReader {
    type Item = Result<PacketRecord, CaptureError>;
    fn next(&mut self) -> Option<Self::Item> {
        if self.done {
            return None;
        }
        match self.next_record() {
            Ok(Some(record)) if self.remaining > 0 => {
                self.remaining -= 1;
                Some(Ok(record))
            }
            Ok(None) => {
                self.done = true;
                None
            }
            result => {
                self.done = true;
                Some(Err(match result {
                    Err(error) => error,
                    _ => CaptureError::Pcap("capture packet limit exceeded".into()),
                }))
            }
        }
    }
}

pub mod enterprise;
pub mod radio;
pub mod rnr;
pub mod roaming;
pub mod security_audit;
pub mod survey;

mod survey_handshake;

/// Stateful cleartext fragment decoding. Protected frames require airdecap first.
#[derive(Default)]
pub struct FrameDecoder {
    pub reassembly: air_frames::reassembly::Reassembler,
}
impl FrameDecoder {
    pub fn decode(
        &mut self,
        packet: &Packet,
        now: std::time::Duration,
    ) -> Result<Option<Dot11Frame>, CaptureError> {
        self.decode_normalized(packet, Some(now))
            .map(|value| value.map(|(frame, _)| frame))
    }
    /// Return the complete normalized 802.11 record, with fragment-zero time.
    /// Ethernet EAPOL is represented by the same synthetic infrastructure header
    /// used by decode_packet; no radio metadata is invented.
    pub fn decode_normalized(
        &mut self,
        packet: &Packet,
        timestamp: Option<std::time::Duration>,
    ) -> Result<Option<(Dot11Frame, PacketRecord)>, CaptureError> {
        let frame = normalize_packet(packet)?;
        let length = wire_header_len(&frame).map_err(|e| CaptureError::Pcap(e.to_string()))?;
        if frame[1] & 0x40 != 0 {
            return Ok(None);
        }
        let Some(complete) = self.reassembly.push_timed(
            &frame,
            frame[length..].to_vec(),
            air_frames::reassembly::Security::clear(),
            None,
            timestamp.unwrap_or_default(),
            timestamp,
        ) else {
            return Ok(None);
        };
        let parsed = parse_dot11(&complete.frame).map_err(|e| CaptureError::Pcap(e.to_string()))?;
        let record = PacketRecord {
            timestamp: complete.timestamp_known.then_some(complete.time),
            original_len: complete.frame.len() as u32,
            packet: Packet {
                dlt: 105,
                data: complete.frame,
            },
        };
        Ok(Some((parsed, record)))
    }
}

pub mod evidence;
