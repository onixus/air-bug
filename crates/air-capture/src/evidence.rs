//! Bounded verification evidence shared by offline streaming consumers.
use crate::CaptureError;
use air_frames::{ssid_bytes_from_beacon, Dot11Frame, FrameKind, LLC_EAPOL};

pub fn relevant(frame: &Dot11Frame) -> bool {
    frame.payload.starts_with(&LLC_EAPOL)
        || (frame.kind == FrameKind::Mgmt && matches!(frame.frame_control & 0xf0, 0 | 0x20 | 0x30))
}

/// Ordinary data is never retained. Duplicate evidence and SSID advertisements
/// are discarded; new evidence exceeding any budget fails the operation.
pub struct Evidence {
    pub frames: Vec<Dot11Frame>,
    max_records: usize,
    records: usize,
    names: usize,
    bytes: usize,
}
impl Evidence {
    pub fn new(max_records: usize) -> Self {
        Self {
            frames: Vec::new(),
            max_records,
            records: 0,
            names: 0,
            bytes: 0,
        }
    }
    /// True when the caller should retain associated provenance for this frame.
    pub fn push(&mut self, frame: Dot11Frame) -> Result<bool, CaptureError> {
        let key = relevant(&frame);
        let ssid = ssid_bytes_from_beacon(&frame);
        if !key && ssid.is_none() {
            return Ok(false);
        }
        if self.frames.iter().any(|old| {
            if let Some(name) = ssid {
                old.addr3 == frame.addr3 && ssid_bytes_from_beacon(old) == Some(name)
            } else {
                old.frame_control == frame.frame_control
                    && old.addr1 == frame.addr1
                    && old.addr2 == frame.addr2
                    && old.addr3 == frame.addr3
                    && old.addr4 == frame.addr4
                    && old.payload == frame.payload
            }
        }) {
            return Ok(false);
        }
        if (key && self.records >= self.max_records)
            || (!key && self.names >= 1024)
            || self.bytes.saturating_add(frame.payload.len()) > 4 * 1024 * 1024
        {
            return Err(CaptureError::Pcap(
                "verification record/target limit exceeded (evidence memory or SSID budget)".into(),
            ));
        }
        self.records += usize::from(key);
        self.names += usize::from(!key);
        self.bytes += frame.payload.len();
        self.frames.push(frame);
        Ok(true)
    }
}
