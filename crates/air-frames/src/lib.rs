use thiserror::Error;

pub const LLC_EAPOL: [u8; 8] = [0xaa, 0xaa, 3, 0, 0, 0, 0x88, 0x8e];

#[derive(Debug, Error)]
pub enum FrameError {
    #[error("truncated frame")]
    Truncated,
    #[error("unsupported frame")]
    Unknown,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FrameKind {
    Mgmt,
    Ctrl,
    Data,
    Unknown,
}

#[derive(Debug, Clone)]
pub struct Dot11Frame {
    pub kind: FrameKind,
    pub frame_control: u16,
    pub addr1: [u8; 6],
    pub addr2: [u8; 6],
    pub addr3: [u8; 6],
    pub addr4: Option<[u8; 6]>,
    pub payload: Vec<u8>,
}

/// Length of an unencrypted management/data MAC header, including QoS/HT control.
pub fn header_len(bytes: &[u8]) -> Result<usize, FrameError> {
    if bytes.get(1).is_some_and(|b| b & 4 != 0) || bytes.get(22).is_some_and(|b| b & 15 != 0) {
        return Err(FrameError::Unknown);
    }
    if bytes.get(1).is_some_and(|b| b & 0x40 != 0) {
        return Err(FrameError::Unknown);
    }
    wire_header_len(bytes)
}

/// Structural MAC header length, including Protected frames. Does not decrypt payloads.
pub fn wire_header_len(bytes: &[u8]) -> Result<usize, FrameError> {
    let fc = u16::from_le_bytes(
        bytes
            .get(..2)
            .ok_or(FrameError::Truncated)?
            .try_into()
            .map_err(|_| FrameError::Truncated)?,
    );
    if fc & 3 != 0 {
        return Err(FrameError::Unknown);
    }
    let kind = (fc >> 2) & 3;
    if kind != 0 && kind != 2 {
        return Err(FrameError::Unknown);
    }
    let mut len = 24;
    if kind == 2 {
        // Null data subtypes have no MSDU. Aggregated payloads need reassembly.
        if fc & 0x0040 != 0 {
            return Err(FrameError::Unknown);
        }
        if fc & 0x0300 == 0x0300 {
            len += 6;
        }
        if fc & 0x0080 != 0 {
            if bytes.get(len).is_some_and(|qos| qos & 0x80 != 0) {
                return Err(FrameError::Unknown);
            }
            len += 2;
            if fc & 0x8000 != 0 {
                len += 4;
            }
        }
    }
    if bytes.len() < len {
        return Err(FrameError::Truncated);
    }
    Ok(len)
}

pub fn parse_dot11(bytes: &[u8]) -> Result<Dot11Frame, FrameError> {
    let len = header_len(bytes)?;
    let fc = u16::from_le_bytes([bytes[0], bytes[1]]);
    let kind = if (fc >> 2) & 3 == 0 {
        FrameKind::Mgmt
    } else {
        FrameKind::Data
    };
    Ok(Dot11Frame {
        kind,
        frame_control: fc,
        addr1: bytes[4..10].try_into().map_err(|_| FrameError::Truncated)?,
        addr2: bytes[10..16]
            .try_into()
            .map_err(|_| FrameError::Truncated)?,
        addr3: bytes[16..22]
            .try_into()
            .map_err(|_| FrameError::Truncated)?,
        addr4: if fc & 0x030c == 0x0308 {
            Some(
                bytes[24..30]
                    .try_into()
                    .map_err(|_| FrameError::Truncated)?,
            )
        } else {
            None
        },
        payload: bytes[len..].to_vec(),
    })
}

impl Dot11Frame {
    /// Infrastructure BSSID, station, and direction (true = AP to station).
    pub fn endpoints(&self) -> Option<([u8; 6], [u8; 6], bool)> {
        if self.kind != FrameKind::Data {
            return None;
        }
        match self.frame_control & 0x0300 {
            0x0100 => Some((self.addr1, self.addr2, false)),
            0x0200 => Some((self.addr2, self.addr1, true)),
            0x0300 if self.addr4.is_some() && self.payload.starts_with(&LLC_EAPOL) => {
                // Four-address EAPOL uses radio peers for PTK derivation. ACK
                // identifies the authenticator; DA/SA may be bridged hosts.
                let from_ap = self.payload.get(LLC_EAPOL.len() + 6)? & 0x80 != 0;
                Some(if from_ap {
                    (self.addr2, self.addr1, true)
                } else {
                    (self.addr1, self.addr2, false)
                })
            }
            _ => None,
        }
    }
}

/// MSDU destination/source, distinct from receiver/transmitter on WDS links.
pub fn data_addresses(frame: &[u8]) -> Option<([u8; 6], [u8; 6])> {
    wire_header_len(frame).ok()?;
    if frame[0] & 12 != 8 {
        return None;
    }
    let (destination, source) = match frame[1] & 3 {
        0 => (frame.get(4..10)?, frame.get(10..16)?),
        1 => (frame.get(16..22)?, frame.get(10..16)?),
        2 => (frame.get(4..10)?, frame.get(16..22)?),
        _ => (frame.get(16..22)?, frame.get(24..30)?),
    };
    Some((destination.try_into().ok()?, source.try_into().ok()?))
}

pub fn qos_tid(frame: &[u8]) -> Option<u8> {
    wire_header_len(frame).ok()?;
    if frame[0] & 0x8c != 0x88 {
        return Some(0);
    }
    Some(frame[if frame[1] & 3 == 3 { 30 } else { 24 }] & 15)
}

/// Preserve SSID octets: SSIDs need not be UTF-8. Hidden SSIDs provide no salt.
pub fn ssid_bytes_from_beacon(frame: &Dot11Frame) -> Option<&[u8]> {
    if frame.kind != FrameKind::Mgmt || !matches!(frame.frame_control & 0x00f0, 0x0080 | 0x0050) {
        return None;
    }
    let mut ies = frame.payload.get(12..)?;
    while ies.len() >= 2 {
        let len = ies[1] as usize;
        let value = ies.get(2..2 + len)?;
        if ies[0] == 0 {
            return (len > 0 && len <= 32 && value.iter().any(|b| *b != 0)).then_some(value);
        }
        ies = &ies[2 + len..];
    }
    None
}

pub fn ssid_from_beacon(frame: &Dot11Frame) -> Option<String> {
    String::from_utf8(ssid_bytes_from_beacon(frame)?.to_vec()).ok()
}

pub mod reassembly;
