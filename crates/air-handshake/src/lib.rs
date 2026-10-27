pub mod ft;
use air_core::MacAddr;
use air_frames::{Dot11Frame, LLC_EAPOL};
use std::collections::BTreeMap;
use thiserror::Error;

#[derive(Debug, Error)]
pub enum HandshakeError {
    #[error("incomplete or invalid WPA/WPA2 M1/M2, M2/M3, M3/M4 or PMKID target")]
    Incomplete,
    #[error("verification record/target limit exceeded")]
    ResourceLimit,
}

#[derive(Debug, Default, Clone)]
pub struct HandshakeSession {
    pub bssid: MacAddr,
    pub sta: MacAddr,
    pub anonce: Option<[u8; 32]>,
    pub snonce: Option<[u8; 32]>,
    /// Exactly the EAPOL header + body, with MIC bytes zeroed for verification.
    pub eapol: Vec<u8>,
    pub mic: Option<[u8; 16]>,
    pub count: usize,
    /// Captured M2 supplying SNonce/negotiation context for an M4 MIC target.
    pub nonce_source: Option<Vec<u8>>,
}

impl HandshakeSession {
    /// Negotiation profile carried by the captured supplicant exchange.
    pub fn profile(&self) -> Option<PskProfile> {
        if let Some(m2) = &self.nonce_source {
            return parse_eapol_key(m2)?.profile;
        }
        negotiated_psk(self.eapol.get(99..)?)
    }
}

#[derive(Debug, Clone)]
pub struct EapolKey<'a> {
    pub message: u8,
    pub descriptor_type: u8,
    pub descriptor_version: u8,
    pub profile: Option<PskProfile>,
    pub replay_counter: u64,
    pub nonce: [u8; 32],
    pub mic: [u8; 16],
    pub bytes: &'a [u8],
    pub key_data: &'a [u8],
}

/// WPA/WPA2 descriptor v1/v2/v3, pairwise M1/M2/M3/M4 or AP group-key message.
pub fn parse_eapol_key(bytes: &[u8]) -> Option<EapolKey<'_>> {
    if bytes.len() < 99
        || !matches!(bytes[0], 1..=3)
        || bytes[1] != 3
        || !matches!(bytes[4], 2 | 254)
    {
        return None;
    }
    let body_len = u16::from_be_bytes([bytes[2], bytes[3]]) as usize;
    let bytes = bytes.get(..4 + body_len)?;
    if bytes.len() < 99 {
        return None;
    }
    let data_len = u16::from_be_bytes([bytes[97], bytes[98]]) as usize;
    if 99 + data_len != bytes.len() {
        return None;
    }
    let info = u16::from_be_bytes([bytes[5], bytes[6]]);
    // Exact flags exclude group keys, install, secure, error, request and encrypted key data.
    let version = (info & 7) as u8;
    if !matches!(version, 0..=3) || (matches!(version, 0 | 3) && bytes[4] != 2) {
        return None;
    }
    let message = match info & !7 {
        0x0088 => 1,
        0x0108 => 2,
        flags if flags & !0x1200 == 0x01c8 => 3,
        0x0308 if data_len == 0 => 4,
        flags if flags & !0x1030 == 0x0380 => 5, // AP group-key message 1

        _ => return None,
    };
    let profile = if message == 2 {
        negotiated_psk(&bytes[99..])
    } else {
        None
    };
    if message == 2 && profile.is_some_and(|p| p.akm == 6) && version != 3 {
        return None;
    }
    if message == 2 && profile.is_some_and(|p| matches!(p.akm, 4 | 9)) {
        return None;
    }
    if version == 3 && message == 2 && !profile.is_some_and(|p| p.cipher == 4 && p.akm == 6) {
        return None;
    }
    if version == 0 && message == 2 && !profile.is_some_and(|p| p.akm == 8 && p.cipher == 4) {
        return None;
    }
    if message == 2 && profile.is_some_and(|p| p.akm == 8) && version != 0 {
        return None;
    }
    let nonce: [u8; 32] = bytes[17..49].try_into().ok()?;
    let mic: [u8; 16] = bytes[81..97].try_into().ok()?;
    if (!matches!(message, 4 | 5) && nonce == [0; 32])
        || (message == 1 && mic != [0; 16])
        || (message != 1 && mic == [0; 16])
    {
        return None;
    }
    Some(EapolKey {
        message,
        descriptor_type: bytes[4],
        descriptor_version: version,
        profile,
        replay_counter: u64::from_be_bytes(bytes[9..17].try_into().ok()?),
        nonce,
        mic,
        bytes,
        key_data: &bytes[99..],
    })
}

/// Extract the first PMKID only from a structurally valid RSN IE body.
pub fn extract_pmkid(rsn: &[u8]) -> Option<[u8; 16]> {
    if rsn.get(..2)? != [1, 0] {
        return None;
    }
    let mut pos = 6; // version + group cipher
    for _ in 0..2 {
        // pairwise ciphers, then AKM selectors
        let count = u16::from_le_bytes(rsn.get(pos..pos + 2)?.try_into().ok()?) as usize;
        if count == 0 {
            return None;
        }
        pos += 2;
        rsn.get(pos..pos + count * 4)?;
        pos += count * 4;
    }
    rsn.get(pos..pos + 2)?; // capabilities
    pos += 2;
    let count = u16::from_le_bytes(rsn.get(pos..pos + 2)?.try_into().ok()?) as usize;
    pos += 2;
    if count == 0 {
        return None;
    }
    let pmkids = rsn.get(pos..pos + count * 16)?;
    // A group management cipher selector may follow the complete PMKID list.
    // No other trailing data is defined, and partial selectors are malformed.
    let suffix = rsn.get(pos + count * 16..)?;
    if !matches!(suffix.len(), 0 | 4) {
        return None;
    }
    pmkids.get(..16)?.try_into().ok()
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub struct PmkidSession {
    pub bssid: MacAddr,
    pub sta: MacAddr,
    pub pmkid: [u8; 16],
}

#[derive(Debug, Clone)]
pub enum VerificationTarget {
    Handshake(HandshakeSession),
    Pmkid(PmkidSession),
    Ft(ft::FtSession),
}

impl VerificationTarget {
    pub fn bssid(&self) -> MacAddr {
        match self {
            Self::Handshake(s) => s.bssid,
            Self::Pmkid(s) => s.bssid,
            Self::Ft(s) => s.bssid,
        }
    }
    pub fn sta(&self) -> MacAddr {
        match self {
            Self::Handshake(s) => s.sta,
            Self::Pmkid(s) => s.sta,
            Self::Ft(s) => s.sta,
        }
    }
}

fn valid_endpoints(ap: MacAddr, sta: MacAddr) -> bool {
    ap != sta && ap != [0; 6] && sta != [0; 6] && ap[0] & 1 == 0 && sta[0] & 1 == 0
}

#[derive(Default)]
struct Messages<'a> {
    authenticators: Vec<EapolKey<'a>>,
    supplicants: Vec<EapolKey<'a>>,
}

pub fn extract(frames: &[Dot11Frame]) -> Vec<HandshakeSession> {
    extract_limited(frames, usize::MAX).expect("unlimited extraction")
}
fn extract_limited(
    frames: &[Dot11Frame],
    max_targets: usize,
) -> Result<Vec<HandshakeSession>, HandshakeError> {
    // M1/M2 have the same counter. M3 increments M2 by one; checked_sub
    // prevents counter wraparound. Both endpoint addresses participate in the key.
    type Key = (MacAddr, MacAddr, u64, u8, u8);
    let mut pairs: BTreeMap<Key, Messages<'_>> = BTreeMap::new();
    for f in frames {
        let Some((ap, sta, from_ap)) = f.endpoints() else {
            continue;
        };
        if !valid_endpoints(ap, sta) {
            continue;
        }
        let Some(eapol) = f.payload.strip_prefix(&LLC_EAPOL) else {
            continue;
        };
        let Some(key) = parse_eapol_key(eapol) else {
            continue;
        };
        if key.message > 3 || (key.message != 2) != from_ap {
            continue;
        }
        let counter = if key.message == 3 {
            let Some(counter) = key.replay_counter.checked_sub(1) else {
                continue;
            };
            counter
        } else {
            key.replay_counter
        };
        let pair = pairs
            .entry((
                ap,
                sta,
                counter,
                key.descriptor_type,
                key.descriptor_version,
            ))
            .or_default();
        let messages = if key.message == 2 {
            &mut pair.supplicants
        } else {
            &mut pair.authenticators
        };
        // For verification only the authenticator nonce is needed from M1/M3.
        if !messages.iter().any(|k| {
            if key.message == 2 {
                k.bytes == key.bytes
            } else {
                k.nonce == key.nonce
            }
        }) {
            messages.push(key);
        }
    }
    let mut sessions = Vec::new();
    for ((bssid, sta, _, _, _), pair) in pairs {
        for auth in &pair.authenticators {
            for m2 in &pair.supplicants {
                if sessions.len() >= max_targets {
                    return Err(HandshakeError::ResourceLimit);
                }
                let mut eapol = m2.bytes.to_vec();
                eapol[81..97].fill(0);
                sessions.push(HandshakeSession {
                    bssid,
                    sta,
                    anonce: Some(auth.nonce),
                    snonce: Some(m2.nonce),
                    eapol,
                    mic: Some(m2.mic),
                    count: 2,
                    nonce_source: None,
                });
            }
        }
    }
    // M3/M4 share the exact replay counter. A zero M4 nonce needs a captured
    // M2 from the preceding counter; never substitute ANonce for SNonce.
    let mut thirds: BTreeMap<Key, Vec<EapolKey<'_>>> = BTreeMap::new();
    let mut fourths: BTreeMap<Key, Vec<EapolKey<'_>>> = BTreeMap::new();
    let mut seconds: BTreeMap<Key, Vec<EapolKey<'_>>> = BTreeMap::new();
    for frame in frames {
        let Some((ap, sta, from_ap)) = frame.endpoints() else {
            continue;
        };
        if !valid_endpoints(ap, sta) {
            continue;
        }
        let Some(key) = frame
            .payload
            .strip_prefix(&LLC_EAPOL)
            .and_then(parse_eapol_key)
        else {
            continue;
        };
        let map = match (key.message, from_ap) {
            (2, false) => &mut seconds,
            (3, true) => &mut thirds,
            (4, false) => &mut fourths,
            _ => continue,
        };
        let list = map
            .entry((
                ap,
                sta,
                key.replay_counter,
                key.descriptor_type,
                key.descriptor_version,
            ))
            .or_default();
        if !list.iter().any(|old| old.bytes == key.bytes) {
            list.push(key);
        }
    }
    for ((ap, sta, counter, descriptor, version), messages) in fourths {
        let Some(auths) = thirds.get(&(ap, sta, counter, descriptor, version)) else {
            continue;
        };
        for m4 in messages {
            let context = counter
                .checked_sub(1)
                .and_then(|c| seconds.get(&(ap, sta, c, descriptor, version)));
            let sources: Vec<_> = context
                .into_iter()
                .flatten()
                .filter(|m2| m4.nonce == [0; 32] || m4.nonce == m2.nonce)
                .collect();
            // Descriptor 0/3 needs explicit negotiated AKM from M2.
            if sources.is_empty() && (m4.nonce == [0; 32] || matches!(version, 0 | 3)) {
                continue;
            }
            let sources: Vec<_> = if sources.is_empty() {
                vec![None]
            } else {
                sources.into_iter().map(Some).collect()
            };
            for source in sources {
                for m3 in auths {
                    let mut eapol = m4.bytes.to_vec();
                    eapol[81..97].fill(0);
                    let snonce = source.map_or(m4.nonce, |m2| m2.nonce);
                    if sessions.iter().any(|old| {
                        old.bssid == ap
                            && old.sta == sta
                            && old.anonce == Some(m3.nonce)
                            && old.snonce == Some(snonce)
                            && old.eapol == eapol
                            && old.mic == Some(m4.mic)
                            && old.profile() == source.and_then(|m2| m2.profile)
                    }) {
                        continue;
                    }
                    if sessions.len() >= max_targets {
                        return Err(HandshakeError::ResourceLimit);
                    }
                    sessions.push(HandshakeSession {
                        bssid: ap,
                        sta,
                        anonce: Some(m3.nonce),
                        snonce: Some(snonce),
                        eapol,
                        mic: Some(m4.mic),
                        count: if source.is_some() { 3 } else { 2 },
                        nonce_source: source.map(|m2| m2.bytes.to_vec()),
                    });
                }
            }
        }
    }
    Ok(sessions)
}

/// Parse complete, bounded TLVs. Partial headers/values invalidate the entire
/// list, even if a valid PMKID occurred before the malformed suffix.
fn elements(mut data: &[u8]) -> Option<Vec<(u8, &[u8])>> {
    let mut out = Vec::new();
    while !data.is_empty() {
        let len = *data.get(1)? as usize;
        out.push((data[0], data.get(2..2 + len)?));
        data = &data[2 + len..];
    }
    Some(out)
}

/// Collect all nonzero PMKIDs from M1 PMKID KDEs or PSK association/reassociation
/// RSN IEs. Beacon RSN data does not identify a station and is never a target.
pub fn extract_pmkid_targets(frames: &[Dot11Frame]) -> Vec<PmkidSession> {
    let mut out = std::collections::BTreeSet::new();
    for f in frames {
        if let Some((ap, sta, from_ap)) = f.endpoints() {
            if !valid_endpoints(ap, sta) || !from_ap {
                continue;
            }
            let Some(key) = f.payload.strip_prefix(&LLC_EAPOL).and_then(parse_eapol_key) else {
                continue;
            };
            if key.message != 1 || key.descriptor_type != 2 || key.descriptor_version != 2 {
                continue;
            }
            let Some(kdes) = elements(key.key_data) else {
                continue;
            };
            for (id, value) in kdes {
                if id == 221 && value.len() == 20 && value[..4] == [0, 15, 172, 4] {
                    let pmkid = value[4..].try_into().expect("checked KDE length");
                    if pmkid != [0; 16] {
                        out.insert(PmkidSession {
                            bssid: ap,
                            sta,
                            pmkid,
                        });
                    }
                }
            }
        } else if f.kind == air_frames::FrameKind::Mgmt && f.frame_control & 0x0300 == 0 {
            let fixed = match f.frame_control & 0x00f0 {
                0x0000 => 4,  // association request: capabilities + listen interval
                0x0020 => 10, // reassociation request adds current AP address
                _ => continue,
            };
            let (ap, sta) = (f.addr1, f.addr2);
            if !valid_endpoints(ap, sta) || f.addr3 != ap {
                continue;
            }
            let Some(ies) = f.payload.get(fixed..).and_then(elements) else {
                continue;
            };
            for (id, value) in ies {
                if id != 48 {
                    continue;
                }
                for pmkid in rsn_psk_pmkids(value) {
                    if pmkid != [0; 16] {
                        out.insert(PmkidSession {
                            bssid: ap,
                            sta,
                            pmkid,
                        });
                    }
                }
            }
        }
    }
    out.into_iter().collect()
}

fn rsn_psk_pmkids(rsn: &[u8]) -> Vec<[u8; 16]> {
    // Reuse strict structural validation before walking the variable lists.
    if extract_pmkid(rsn).is_none() {
        return Vec::new();
    }
    let cipher_count = u16::from_le_bytes([rsn[6], rsn[7]]) as usize;
    let mut pos = 8 + cipher_count * 4;
    let akm_count = u16::from_le_bytes([rsn[pos], rsn[pos + 1]]) as usize;
    pos += 2;
    let akms = &rsn[pos..pos + akm_count * 4];
    // SHA256/FT/SAE PMKIDs need different derivations. Do not treat those as PSK.
    if akms
        .as_chunks::<4>()
        .0
        .iter()
        .any(|a| a != &[0, 15, 172, 2])
    {
        return Vec::new();
    }
    pos += akm_count * 4 + 2; // AKMs and capabilities
    let count = u16::from_le_bytes([rsn[pos], rsn[pos + 1]]) as usize;
    pos += 2;
    rsn[pos..pos + count * 16].as_chunks::<16>().0.to_vec()
}

pub fn extract_targets(frames: &[Dot11Frame]) -> Vec<VerificationTarget> {
    extract(frames)
        .into_iter()
        .map(VerificationTarget::Handshake)
        .chain(
            extract_pmkid_targets(frames)
                .into_iter()
                .map(VerificationTarget::Pmkid),
        )
        .chain(
            frames
                .iter()
                .filter_map(ft::parse)
                .map(VerificationTarget::Ft),
        )
        .collect()
}

/// Bound input work before pair construction and output before allocating combinations.
/// Relevant records include association requests even when their RSN is malformed.
pub fn extract_targets_limited(
    frames: &[Dot11Frame],
    max_records: usize,
    max_targets: usize,
) -> Result<Vec<VerificationTarget>, HandshakeError> {
    let records = frames
        .iter()
        .filter(|f| {
            f.payload.starts_with(&LLC_EAPOL)
                || (f.kind == air_frames::FrameKind::Mgmt
                    && matches!(f.frame_control & 0x00f0, 0 | 0x20 | 0x30))
        })
        .take(max_records.saturating_add(1))
        .count();
    if records > max_records {
        return Err(HandshakeError::ResourceLimit);
    }
    let mut out: Vec<_> = extract_limited(frames, max_targets)?
        .into_iter()
        .map(VerificationTarget::Handshake)
        .collect();
    let mut ids = std::collections::BTreeSet::new();
    for frame in frames {
        for id in extract_pmkid_targets(std::slice::from_ref(frame)) {
            if !ids.contains(&id) {
                if out.len() + ids.len() >= max_targets {
                    return Err(HandshakeError::ResourceLimit);
                }
                ids.insert(id);
            }
        }
    }
    out.extend(ids.into_iter().map(VerificationTarget::Pmkid));
    for target in frames.iter().filter_map(ft::parse) {
        if out.len() >= max_targets {
            return Err(HandshakeError::ResourceLimit);
        }
        out.push(VerificationTarget::Ft(target));
    }
    Ok(out)
}

/// A single negotiated personal AKM/cipher from the supplicant's RSN IE.
/// Ambiguous, malformed, enterprise, and unsupported selectors fail closed.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct PskProfile {
    pub akm: u8,
    pub cipher: u8,
    pub group_cipher: u8,
}
pub fn negotiated_psk(data: &[u8]) -> Option<PskProfile> {
    let ies = elements(data)?;
    let mut rsns = ies.into_iter().filter(|(id, _)| *id == 48);
    let (_, rsn) = rsns.next()?;
    if rsns.next().is_some() {
        return None;
    }
    if rsn.get(..2)? != [1, 0] || rsn.get(2..5)? != [0, 15, 172] {
        return None;
    }
    let group = *rsn.get(5)?;
    if !matches!(group, 2 | 4) {
        return None;
    }
    if rsn.get(6..11)? != [1, 0, 0, 15, 172] {
        return None;
    }
    let cipher = *rsn.get(11)?;
    if !matches!(cipher, 2 | 4) {
        return None;
    }
    if rsn.get(12..17)? != [1, 0, 0, 15, 172] {
        return None;
    }
    let akm = *rsn.get(17)?;
    if !matches!(akm, 2 | 4 | 6 | 8 | 9) || (matches!(akm, 4 | 6 | 8 | 9) && cipher != 4) {
        return None;
    }
    let mut tail = rsn.get(18..)?;
    if !tail.is_empty() {
        tail = tail.get(2..)?;
    }
    if !tail.is_empty() {
        let count = u16::from_le_bytes(tail.get(..2)?.try_into().ok()?) as usize;
        tail = tail.get(2 + count * 16..)?;
        if !matches!(tail.len(), 0 | 4) {
            return None;
        }
    }
    Some(PskProfile {
        akm,
        cipher,
        group_cipher: group,
    })
}
