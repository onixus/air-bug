//! Bounded passive inventory and WPA2 verification-evidence indicators; no decryption.
use std::collections::BTreeMap;
use std::io::{self, Read};
use std::time::Duration;

use crate::security_audit::{self, SecurityObservation};
use serde::Serialize;

pub type Mac = [u8; 6];
const MAX_ROWS: usize = 4096;
const MAX_RECORD: usize = 65535;

#[derive(Clone, Debug, Default)]
pub struct AccessPoint {
    pub enterprise: crate::enterprise::EapAudit,
    pub roaming_capabilities: Option<crate::roaming::Capabilities>,
    pub ssid: Vec<u8>,
    pub channel: Option<u16>,
    pub signal: Option<i8>,
    pub security: String,
    pub beacons: u64,
    pub packets: u64,
    pub last_seen: Duration,
    pub handshake_m1m2: bool,
    pub handshake_m2m3: bool,
    pub handshake_m3m4: bool,
    pub pmkid: bool,
    pub ft: bool,
    pub security_audit: Option<SecurityObservation>,
    pub audit_last_status: Option<&'static str>,
    pub audit_malformed: u64,
    pub audit_changed: bool,
    pub capture: ApQuality,
    pub last_direct_observation: Option<ObservationOrigin>,
}
/// One received frame; capture timestamps and radio metadata can be absent.
#[derive(Clone, Debug, Serialize)]
pub struct ObservationOrigin {
    pub kind: &'static str,
    pub record_index: u64,
    pub capture_timestamp_seconds: Option<f64>,
    pub processing_seconds: f64,
    pub radio: Option<crate::radio::RadioChannel>,
}
#[derive(Clone, Debug, Serialize)]
pub struct NeighborObservation {
    pub reporter_bssid: Mac,
    pub neighbor: crate::rnr::Neighbor,
    pub origin: ObservationOrigin,
    #[serde(skip)]
    pub last_seen: Duration,
}
type NeighborKey = (Mac, u8, u8, Option<Mac>, Option<u32>, Option<u8>, u8);
#[derive(Clone, Debug, Default, Serialize)]
pub struct ApQuality {
    pub retry_bit_frames: u64,
    pub fragmented_frames: u64,
    pub eapol_m1: u64,
    pub eapol_m2: u64,
    pub eapol_m3: u64,
    pub eapol_m4: u64,
    pub unsupported_or_malformed_eapol_key: u64,
    pub m4_zero_nonce: u64,
    pub advertised_channel: Option<u16>,
    pub capture_channel: Option<u16>,
    pub capture_frequency_mhz: Option<u16>,
    pub channel_disagreements: u64,
}
#[derive(Clone, Debug, Default, Serialize)]
pub struct CaptureQuality {
    pub truncated_records: u64,
    pub invalid_record_lengths: u64,
    pub radiotap_bad_fcs: u64,
    pub radiotap_invalid: u64,
    pub fcs_present_reported: u64,
    pub fcs_absent_reported: u64,
    pub fcs_unknown: u64,
    pub timestamp_missing: u64,
    pub timestamp_regressions: u64,
    pub malformed_rnr_elements: u64,
    pub rnr_evicted: u64,
}
impl AccessPoint {
    pub fn pmf(&self) -> &'static str {
        if self.audit_last_status != Some("valid") {
            return "unknown";
        }
        self.security_audit
            .as_ref()
            .and_then(|a| a.advertised.rsn.as_ref())
            .map_or("unknown", |r| r.pmf)
    }
    pub fn capture_observations(&self) -> Vec<&'static str> {
        let c = &self.capture;
        let mut result = Vec::new();
        if !(self.handshake_m1m2
            || self.handshake_m2m3
            || self.handshake_m3m4
            || self.pmkid
            || self.ft)
        {
            if c.eapol_m1 + c.eapol_m2 + c.eapol_m3 + c.eapol_m4 == 0 {
                result.push("no_supported_handshake_or_pmkid_observed");
            } else {
                result.push("no_compatible_supported_pair_observed");
            }
            if c.eapol_m1 > 0 && c.eapol_m2 == 0 {
                result.push("m1_seen_without_m2");
            }
            if c.eapol_m2 > 0 && c.eapol_m1 == 0 && c.eapol_m3 == 0 {
                result.push("m2_seen_without_m1_or_m3");
            }
            if c.m4_zero_nonce > 0 {
                result.push("m4_zero_nonce_needs_matching_m2");
            }
        }
        if c.unsupported_or_malformed_eapol_key > 0 {
            result.push("unsupported_or_malformed_eapol_key_seen");
        }
        result
    }
    pub fn verification_label(&self) -> &'static str {
        if self.ft {
            return "FT";
        }
        match (
            self.handshake_m1m2 || self.handshake_m2m3 || self.handshake_m3m4,
            self.pmkid,
        ) {
            (true, true) => "HS+PMKID",
            (true, false) => "HS",
            (false, true) => "PMKID",
            _ => "-",
        }
    }
}
#[derive(Clone, Debug, Default)]
pub struct Station {
    /// Last infrastructure BSSID observed, not proof of current association.
    pub bssid: Option<Mac>,
    pub signal: Option<i8>,
    pub packets: u64,
    pub probe: Vec<u8>,
    pub last_seen: Duration,
}
#[derive(Default)]
pub struct Survey {
    pub aps: BTreeMap<Mac, AccessPoint>,
    pub stations: BTreeMap<Mac, Station>,
    pub packets: u64,
    pub ignored: u64,
    pub evicted: u64,
    pub quality: CaptureQuality,
    pub roaming: crate::roaming::Diagnostics,
    pub rnr_neighbors: BTreeMap<NeighborKey, NeighborObservation>,
    last_timestamp: Option<Duration>,
    tracker: crate::survey_handshake::Tracker,
    decoder: crate::FrameDecoder,
}

fn unicast(mac: Mac) -> bool {
    mac != [0; 6] && mac[0] & 1 == 0
}
fn addr(bytes: &[u8], start: usize) -> Mac {
    bytes[start..start + 6].try_into().unwrap()
}

pub fn display_bytes(bytes: &[u8]) -> String {
    if bytes.is_empty() {
        return "<hidden/unknown>".into();
    }
    bytes
        .iter()
        .map(|b| {
            if (0x20..=0x7e).contains(b) && *b != b'\\' {
                (*b as char).to_string()
            } else {
                format!("\\x{b:02x}")
            }
        })
        .collect()
}
pub fn mac_string(mac: &Mac) -> String {
    mac.iter()
        .map(|b| format!("{b:02x}"))
        .collect::<Vec<_>>()
        .join(":")
}
fn channel_from_frequency(freq: u16) -> Option<u16> {
    match freq {
        2484 => Some(14),
        2412..=2472 if (freq - 2407).is_multiple_of(5) => Some((freq - 2407) / 5),
        5160..=5885 if freq.is_multiple_of(5) => Some((freq - 5000) / 5),
        _ => crate::radio::from_frequency(freq).map(|r| r.channel),
    }
}

struct Radio<'a> {
    frame: &'a [u8],
    channel: Option<u16>,
    frequency: Option<u16>,
    signal: Option<i8>,
}
fn radio(dlt: u32, bytes: &[u8]) -> Option<Radio<'_>> {
    if dlt == 105 {
        return Some(Radio {
            frame: bytes,
            channel: None,
            frequency: None,
            signal: None,
        });
    }
    if dlt != 127 || bytes.len() < 8 || bytes[0] != 0 {
        return None;
    }
    let len = u16::from_le_bytes([bytes[2], bytes[3]]) as usize;
    if len < 8 || len > bytes.len() {
        return None;
    }
    let present = u32::from_le_bytes(bytes[4..8].try_into().ok()?);
    let mut offset = 8;
    let mut word = present;
    while word & (1 << 31) != 0 {
        let next = bytes
            .get(offset..offset + 4)
            .filter(|_| offset + 4 <= len)?;
        word = u32::from_le_bytes(next.try_into().ok()?);
        offset += 4;
    }
    let mut signal = None;
    let mut channel = None;
    let mut frequency = None;
    let mut flags = 0;
    // Radiotap fixed fields through dBm antenna signal; offsets relative to header.
    for (bit, align, size) in [
        (0, 8, 8),
        (1, 1, 1),
        (2, 1, 1),
        (3, 2, 4),
        (4, 2, 2),
        (5, 1, 1),
    ] {
        if present & (1 << bit) == 0 {
            continue;
        }
        offset = (offset + align - 1) & !(align - 1);
        let field = bytes
            .get(offset..offset + size)
            .filter(|_| offset + size <= len)?;
        match bit {
            1 => flags = field[0],
            3 => {
                frequency = Some(u16::from_le_bytes([field[0], field[1]]));
                channel = frequency.and_then(channel_from_frequency);
            }
            5 => signal = Some(field[0] as i8),
            _ => {}
        }
        offset += size;
    }
    if flags & 0x40 != 0 {
        return None;
    } // driver marks bad FCS
    let end = if flags & 0x10 != 0 {
        bytes.len().checked_sub(4)?
    } else {
        bytes.len()
    };
    Some(Radio {
        frame: bytes.get(len..end)?,
        channel,
        frequency,
        signal,
    })
}

// Return None for malformed metadata, Some(None) when Flags is not present.
fn radiotap_flags(bytes: &[u8]) -> Option<Option<u8>> {
    if bytes.len() < 8 || bytes[0] != 0 {
        return None;
    }
    let len = u16::from_le_bytes([bytes[2], bytes[3]]) as usize;
    if len < 8 || len > bytes.len() {
        return None;
    }
    let present = u32::from_le_bytes(bytes[4..8].try_into().ok()?);
    let mut offset = 8;
    let mut word = present;
    while word & (1 << 31) != 0 {
        word = u32::from_le_bytes(bytes.get(offset..offset + 4)?.try_into().ok()?);
        offset += 4;
        if offset > len {
            return None;
        }
    }
    if present & 1 != 0 {
        offset = (offset + 7) & !7;
        offset += 8;
    }
    if offset > len {
        return None;
    }
    if present & 2 != 0 {
        if offset >= len {
            return None;
        }
        return Some(Some(bytes[offset]));
    }
    Some(None)
}

#[derive(Default)]
struct Advertisement {
    ssid: Vec<u8>,
    channel: Option<u16>,
    rsn: bool,
    wpa: bool,
    sae: bool,
}
fn advertisement(mut bytes: &[u8]) -> Option<Advertisement> {
    let mut result = Advertisement::default();
    while !bytes.is_empty() {
        let id = *bytes.first()?;
        let len = *bytes.get(1)? as usize;
        let value = bytes.get(2..2 + len)?;
        match id {
            0 if len <= 32 && value.iter().any(|b| *b != 0) => result.ssid = value.to_vec(),
            3 | 61 if !value.is_empty() => result.channel = Some(value[0] as u16),
            48 => {
                result.rsn = true;
                // Parse bounded RSN pairwise and AKM lists; do not search arbitrary bytes.
                if value.get(..2) == Some(&[1, 0]) && value.len() >= 8 {
                    let pairs = u16::from_le_bytes([value[6], value[7]]) as usize;
                    let pos = 8 + pairs * 4;
                    if let Some(count) = value.get(pos..pos + 2) {
                        let count = u16::from_le_bytes([count[0], count[1]]) as usize;
                        if let Some(akms) = value.get(pos + 2..pos + 2 + count * 4) {
                            result.sae = akms
                                .as_chunks::<4>()
                                .0
                                .iter()
                                .any(|a| a[..3] == [0, 15, 172] && matches!(a[3], 8 | 9));
                        }
                    }
                }
            }
            221 if value.starts_with(&[0, 80, 242, 1]) => result.wpa = true,
            _ => {}
        }
        bytes = &bytes[len + 2..];
    }
    Some(result)
}

impl Survey {
    pub fn verification_evicted(&self) -> u64 {
        self.tracker.evicted
    }
    pub fn expire(&mut self, now: Duration, age: Duration) {
        self.tracker.expire(now);
        self.aps
            .retain(|_, ap| now.saturating_sub(ap.last_seen) <= age);
        self.stations
            .retain(|_, sta| now.saturating_sub(sta.last_seen) <= age);
        self.rnr_neighbors
            .retain(|_, n| now.saturating_sub(n.last_seen) <= age);
    }
    fn invalidate_advertisement(&mut self, mac: Mac, now: Duration) -> Option<()> {
        let ap = self.aps.get_mut(&mac)?;
        ap.roaming_capabilities = None;
        ap.audit_last_status = Some("malformed");
        ap.audit_malformed += 1;
        ap.security = "Unknown".into();
        ap.packets += 1;
        ap.last_seen = now;
        Some(())
    }
    fn ap(&mut self, mac: Mac) -> &mut AccessPoint {
        if self.aps.len() >= MAX_ROWS && !self.aps.contains_key(&mac) {
            if let Some(old) = self
                .aps
                .iter()
                .min_by_key(|(_, a)| a.last_seen)
                .map(|(m, _)| *m)
            {
                self.aps.remove(&old);
                self.evicted += 1;
            }
        }
        self.aps.entry(mac).or_default()
    }
    fn station(&mut self, mac: Mac) -> &mut Station {
        if self.stations.len() >= MAX_ROWS && !self.stations.contains_key(&mac) {
            if let Some(old) = self
                .stations
                .iter()
                .min_by_key(|(_, s)| s.last_seen)
                .map(|(m, _)| *m)
            {
                self.stations.remove(&old);
                self.evicted += 1;
            }
        }
        self.stations.entry(mac).or_default()
    }
    pub fn observe(&mut self, dlt: u32, bytes: &[u8], now: Duration, filter: Option<Mac>) {
        self.observe_record(dlt, bytes, bytes.len() as u32, None, now, filter);
    }
    pub fn observe_record(
        &mut self,
        dlt: u32,
        bytes: &[u8],
        original_len: u32,
        timestamp: Option<Duration>,
        now: Duration,
        filter: Option<Mac>,
    ) {
        self.packets += 1;
        if let Some(ts) = timestamp {
            if self.last_timestamp.is_some_and(|last| ts < last) {
                self.quality.timestamp_regressions += 1;
            }
            self.last_timestamp = Some(ts);
        } else {
            self.quality.timestamp_missing += 1;
        }
        if original_len as usize > bytes.len() {
            self.quality.truncated_records += 1;
            self.ignored += 1;
            return;
        }
        if (original_len as usize) < bytes.len() {
            self.quality.invalid_record_lengths += 1;
            self.ignored += 1;
            return;
        }
        if dlt == 127 {
            match radiotap_flags(bytes) {
                None => {
                    self.quality.radiotap_invalid += 1;
                    self.ignored += 1;
                    return;
                }
                Some(flags) => {
                    match flags {
                        Some(f) if f & 0x10 != 0 => self.quality.fcs_present_reported += 1,
                        Some(_) => self.quality.fcs_absent_reported += 1,
                        None => self.quality.fcs_unknown += 1,
                    }
                    if flags.is_some_and(|f| f & 0x40 != 0) {
                        self.quality.radiotap_bad_fcs += 1;
                        self.ignored += 1;
                        return;
                    }
                    if radio(dlt, bytes).is_none() {
                        self.quality.radiotap_invalid += 1;
                        self.ignored += 1;
                        return;
                    }
                }
            }
        } else {
            self.quality.fcs_unknown += 1;
        }
        let management_observed = radio(dlt, bytes).is_some_and(|r| {
            self.roaming
                .observe(r.frame, self.packets, timestamp, now, filter)
        });
        let inventoried = self
            .observe_inner(dlt, bytes, now, timestamp, filter)
            .is_some();
        let frame = self
            .decoder
            .decode(
                &crate::Packet {
                    dlt,
                    data: bytes.to_vec(),
                },
                now,
            )
            .ok()
            .flatten();
        let mut attributed = false;
        if let Some(frame) = &frame {
            if let Some((ap, sta, from_ap)) = frame.endpoints() {
                if unicast(ap) && unicast(sta) && ap != sta && !filter.is_some_and(|m| m != ap) {
                    if let Some(payload) = frame.payload.strip_prefix(&air_frames::LLC_EAPOL) {
                        if frame.frame_control & 0x0300 != 0x0300 && payload.get(1) == Some(&0) {
                            let row = self.ap(ap);
                            row.enterprise.observe(payload, from_ap);
                            if !inventoried {
                                row.packets += 1;
                                row.last_seen = now;
                                attributed = true;
                            }
                        }
                        if payload.get(1) == Some(&3) {
                            let key = air_handshake::parse_eapol_key(payload);
                            let row = self.ap(ap);
                            match key {
                                Some(k)
                                    if k.message <= 4 && matches!(k.message, 1 | 3) == from_ap =>
                                {
                                    match k.message {
                                        1 => row.capture.eapol_m1 += 1,
                                        2 => row.capture.eapol_m2 += 1,
                                        3 => row.capture.eapol_m3 += 1,
                                        4 => {
                                            row.capture.eapol_m4 += 1;
                                            if k.nonce == [0; 32] {
                                                row.capture.m4_zero_nonce += 1;
                                            }
                                        }
                                        _ => {}
                                    }
                                }
                                _ => row.capture.unsupported_or_malformed_eapol_key += 1,
                            }
                            if !inventoried {
                                row.packets += 1;
                                row.last_seen = now;
                                attributed = true;
                            }
                        }
                    }
                }
            }
        }
        let evidence = frame
            .as_ref()
            .and_then(|frame| self.tracker.observe(frame, now, filter));
        if let Some(evidence) = evidence {
            let ap = self.ap(evidence.ap);
            ap.handshake_m1m2 |= evidence.m1m2;
            ap.handshake_m2m3 |= evidence.m2m3;
            ap.handshake_m3m4 |= evidence.m3m4;
            ap.pmkid |= evidence.pmkid;
            ap.ft |= evidence.ft;
            if !inventoried && !attributed {
                ap.packets += 1;
                ap.last_seen = now;
            }
        } else if !inventoried && !attributed && !management_observed {
            self.ignored += 1;
        }
    }
    fn observe_inner(
        &mut self,
        dlt: u32,
        bytes: &[u8],
        now: Duration,
        timestamp: Option<Duration>,
        filter: Option<Mac>,
    ) -> Option<()> {
        let radio = radio(dlt, bytes)?;
        let frame = radio.frame;
        if frame.len() < 24 {
            return None;
        }
        let fc = u16::from_le_bytes([frame[0], frame[1]]);
        if fc & 3 != 0 {
            return None;
        }
        let kind = (fc >> 2) & 3;
        let subtype = (fc >> 4) & 15;
        let a1 = addr(frame, 4);
        let a2 = addr(frame, 10);
        let a3 = addr(frame, 16);
        if kind == 0 && matches!(subtype, 8 | 5) && fc & 0xc700 == 0 && frame[22] & 15 == 0 {
            if !unicast(a3) || a2 != a3 || filter.is_some_and(|m| m != a3) {
                return None;
            }
            let Some(fixed) = frame.get(24..36) else {
                return self.invalidate_advertisement(a3, now);
            };
            let ies = &frame[36..];
            let adv = match advertisement(ies) {
                Some(adv) => adv,
                None => return self.invalidate_advertisement(a3, now),
            };
            let mut neighbors = Vec::new();
            let mut malformed_rnr = 0u64;
            let mut remaining = ies;
            while !remaining.is_empty() {
                let len = remaining[1] as usize;
                let value = &remaining[2..2 + len];
                if remaining[0] == 201 {
                    match crate::rnr::parse(value) {
                        Ok(records) => neighbors.extend(records),
                        Err(_) => malformed_rnr += 1,
                    }
                }
                remaining = &remaining[2 + len..];
            }
            self.quality.malformed_rnr_elements += malformed_rnr;
            let origin = ObservationOrigin {
                kind: if subtype == 8 {
                    "beacon"
                } else {
                    "probe_response"
                },
                record_index: self.packets,
                capture_timestamp_seconds: timestamp.map(|t| t.as_secs_f64()),
                processing_seconds: now.as_secs_f64(),
                radio: radio.frequency.and_then(crate::radio::from_frequency),
            };
            let privacy = fixed[10] & 0x10 != 0;
            let record_index = self.packets;
            let parsed = security_audit::parse(&frame[36..], privacy);
            let roaming_capabilities = crate::roaming::capabilities(ies).ok();
            let ap = self.ap(a3);
            ap.roaming_capabilities = roaming_capabilities;
            if !adv.ssid.is_empty() {
                ap.ssid = adv.ssid;
            }
            ap.last_direct_observation = Some(origin.clone());
            ap.channel = radio.channel.or(adv.channel).or(ap.channel);
            ap.signal = radio.signal.or(ap.signal);
            ap.security = match (adv.rsn, adv.wpa, adv.sae, privacy) {
                (true, _, true, _) => "RSN/SAE",
                (true, true, _, _) => "WPA/RSN",
                (true, _, _, _) => "RSN",
                (_, true, _, _) => "WPA",
                (_, _, _, true) => "Privacy",
                _ => "Open",
            }
            .into();
            match parsed {
                Ok(advertised) => {
                    ap.audit_changed |= ap
                        .security_audit
                        .as_ref()
                        .is_some_and(|old| old.advertised != advertised);
                    ap.security_audit = Some(SecurityObservation {
                        record_index,
                        source: if subtype == 8 {
                            "beacon"
                        } else {
                            "probe_response"
                        },
                        observed_processing_seconds: now.as_secs_f64(),
                        advertised,
                    });
                    ap.audit_last_status = Some("valid");
                }
                Err(()) => {
                    ap.roaming_capabilities = None;
                    ap.audit_last_status = Some("malformed");
                    ap.audit_malformed += 1;
                    ap.security = "Unknown".into();
                }
            }
            ap.capture.retry_bit_frames += u64::from(fc & 0x0800 != 0);
            ap.capture.advertised_channel = adv.channel.or(ap.capture.advertised_channel);
            ap.capture.capture_channel = radio.channel.or(ap.capture.capture_channel);
            ap.capture.capture_frequency_mhz = radio.frequency.or(ap.capture.capture_frequency_mhz);
            ap.capture.channel_disagreements +=
                u64::from(matches!((adv.channel,radio.channel),(Some(a),Some(b)) if a != b));
            ap.beacons += u64::from(subtype == 8);
            ap.packets += 1;
            ap.last_seen = now;
            for neighbor in neighbors {
                let key = (
                    a3,
                    neighbor.operating_class,
                    neighbor.channel,
                    neighbor.bssid,
                    neighbor.short_ssid,
                    neighbor.tbtt_offset,
                    neighbor.tbtt_type,
                );
                if self.rnr_neighbors.len() >= MAX_ROWS && !self.rnr_neighbors.contains_key(&key) {
                    if let Some(old) = self
                        .rnr_neighbors
                        .iter()
                        .min_by_key(|(_, n)| n.last_seen)
                        .map(|(k, _)| *k)
                    {
                        self.rnr_neighbors.remove(&old);
                        self.quality.rnr_evicted += 1;
                    }
                }
                self.rnr_neighbors.insert(
                    key,
                    NeighborObservation {
                        reporter_bssid: a3,
                        neighbor,
                        origin: origin.clone(),
                        last_seen: now,
                    },
                );
            }
            return Some(());
        }
        if kind == 0
            && subtype == 4
            && fc & 0xc700 == 0
            && frame[22] & 15 == 0
            && filter.is_none()
            && unicast(a2)
        {
            let adv = advertisement(&frame[24..])?;
            let sta = self.station(a2);
            sta.probe = adv.ssid;
            sta.signal = radio.signal.or(sta.signal);
            sta.packets += 1;
            sta.last_seen = now;
            return Some(());
        }
        // Header-only accounting accepts encrypted, QoS, null and fragmented data.
        // Never interpret encrypted payloads. WDS/IBSS have no infrastructure mapping.
        if kind == 2 {
            let needed = 24
                + if subtype & 8 != 0 {
                    2 + if fc & 0x8000 != 0 { 4 } else { 0 }
                } else {
                    0
                };
            if frame.len() < needed {
                return None;
            }
            let (bssid, station, from_ap) = match fc & 0x0300 {
                0x0100 => (a1, a2, false),
                0x0200 => (a2, a1, true),
                _ => return None,
            };
            if !unicast(bssid) || filter.is_some_and(|m| m != bssid) {
                return None;
            }
            let origin = ObservationOrigin {
                kind: "data_header",
                record_index: self.packets,
                capture_timestamp_seconds: timestamp.map(|t| t.as_secs_f64()),
                processing_seconds: now.as_secs_f64(),
                radio: radio.frequency.and_then(crate::radio::from_frequency),
            };
            let ap = self.ap(bssid);
            ap.last_direct_observation = Some(origin);
            ap.packets += 1;
            ap.last_seen = now;
            ap.capture.retry_bit_frames += u64::from(fc & 0x0800 != 0);
            ap.capture.fragmented_frames += u64::from(fc & 0x0400 != 0 || frame[22] & 15 != 0);
            ap.capture.capture_channel = radio.channel.or(ap.capture.capture_channel);
            ap.capture.capture_frequency_mhz = radio.frequency.or(ap.capture.capture_frequency_mhz);
            ap.channel = radio.channel.or(ap.channel);
            if from_ap {
                ap.signal = radio.signal.or(ap.signal);
            }
            if unicast(station) && station != bssid {
                let sta = self.station(station);
                sta.bssid = Some(bssid);
                sta.packets += 1;
                sta.last_seen = now;
                if !from_ap {
                    sta.signal = radio.signal.or(sta.signal);
                }
            }
            return Some(());
        }
        None
    }
}

/// Incremental classic-PCAP decoder for tcpdump's growing file. Partial writes
/// are retained until complete; packet data is never retained after the callback.
#[derive(Default)]
pub struct PcapStream {
    buffer: Vec<u8>,
    header: Option<(bool, u32, usize, bool)>,
}
impl PcapStream {
    pub fn is_ready(&self) -> bool {
        self.header.is_some()
    }
    pub fn poll(
        &mut self,
        input: &mut impl Read,
        mut packet: impl FnMut(u32, &[u8]),
    ) -> io::Result<usize> {
        self.poll_records(input, |dlt, data, _, _| packet(dlt, data))
    }
    pub fn poll_records(
        &mut self,
        input: &mut impl Read,
        mut packet: impl FnMut(u32, &[u8], u32, Option<Duration>),
    ) -> io::Result<usize> {
        let mut buf = [0u8; 65536];
        let n = input.read(&mut buf)?;
        self.buffer.extend_from_slice(&buf[..n]);
        if self.header.is_none() && self.buffer.len() >= 24 {
            let h = &self.buffer[..24];
            let little = match h[..4] {
                [0xd4, 0xc3, 0xb2, 0xa1] | [0x4d, 0x3c, 0xb2, 0xa1] => true,
                [0xa1, 0xb2, 0xc3, 0xd4] | [0xa1, 0xb2, 0x3c, 0x4d] => false,
                _ => return Err(io::Error::other("survey requires classic pcap")),
            };
            if h[4..8] != if little { [2, 0, 4, 0] } else { [0, 2, 0, 4] } {
                return Err(io::Error::other("invalid pcap version"));
            }
            let dlt = number(&h[20..24], little) & 0xffff;
            if !matches!(dlt, 105 | 127) {
                return Err(io::Error::other(format!(
                    "survey needs raw 802.11 or Radiotap, got DLT {dlt}"
                )));
            }
            let snap = number(&h[16..20], little) as usize;
            if snap == 0 || snap > MAX_RECORD {
                return Err(io::Error::other("unsupported pcap snaplen (maximum 65535)"));
            }
            let nanos = matches!(h[..4], [0x4d, 0x3c, 0xb2, 0xa1] | [0xa1, 0xb2, 0x3c, 0x4d]);
            self.header = Some((little, dlt, snap, nanos));
            self.buffer.drain(..24);
        }
        if let Some((little, dlt, snap, nanos)) = self.header {
            let mut consumed = 0;
            while self.buffer.len() - consumed >= 16 {
                let h = &self.buffer[consumed..consumed + 16];
                let length = number(&h[8..12], little) as usize;
                let original = number(&h[12..16], little) as usize;
                if length > snap || length > original {
                    return Err(io::Error::other("invalid pcap record length"));
                }
                if self.buffer.len() - consumed < 16 + length {
                    break;
                }
                let seconds = number(&h[..4], little);
                let fraction = number(&h[4..8], little);
                if fraction >= if nanos { 1_000_000_000 } else { 1_000_000 } {
                    return Err(io::Error::other("invalid pcap timestamp"));
                }
                let ts = Duration::new(
                    seconds.into(),
                    if nanos { fraction } else { fraction * 1000 },
                );
                packet(
                    dlt,
                    &self.buffer[consumed + 16..consumed + 16 + length],
                    original as u32,
                    Some(ts),
                );
                consumed += 16 + length;
            }
            self.buffer.drain(..consumed);
        }
        Ok(n)
    }
    pub fn finish(&self) -> io::Result<()> {
        if self.header.is_none() || !self.buffer.is_empty() {
            return Err(io::Error::other("truncated survey pcap"));
        }
        Ok(())
    }
}
fn number(bytes: &[u8], little: bool) -> u32 {
    let a = bytes.try_into().unwrap();
    if little {
        u32::from_le_bytes(a)
    } else {
        u32::from_be_bytes(a)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    const AP: Mac = [2, 1, 2, 3, 4, 5];
    const STA: Mac = [2, 6, 7, 8, 9, 10];
    fn frame(fc: u16, a1: Mac, a2: Mac, a3: Mac) -> Vec<u8> {
        let mut f = fc.to_le_bytes().to_vec();
        f.extend([0; 2]);
        f.extend(a1);
        f.extend(a2);
        f.extend(a3);
        f.extend([0; 2]);
        f
    }
    fn beacon() -> Vec<u8> {
        let mut f = frame(0x80, [255; 6], AP, AP);
        f.extend([0; 12]);
        f.extend([0, 4]);
        f.extend(b"test");
        f.extend([3, 1, 6]);
        f
    }
    fn radiotap(f: &[u8], signal: i8, flags: u8) -> Vec<u8> {
        let mut r = vec![
            0,
            0,
            17,
            0,
            0x3e,
            0,
            0,
            0,
            flags,
            12,
            0x85,
            9,
            0x80,
            0,
            0,
            0,
            signal as u8,
        ];
        r.extend(f);
        if flags & 0x10 != 0 {
            r.extend([0; 4]);
        }
        r
    }
    #[test]
    fn encrypted_and_null_data_inventory_uses_transmitter_signal() {
        let mut s = Survey::default();
        s.observe(127, &radiotap(&beacon(), -40, 0x10), Duration::ZERO, None);
        let mut data = frame(0x4188, AP, STA, [2, 9, 9, 9, 9, 9]);
        data.extend([0; 2]);
        data.extend([0xff; 20]);
        s.observe(127, &radiotap(&data, -70, 0), Duration::from_secs(1), None);
        s.observe(
            127,
            &radiotap(&frame(0x0248, STA, AP, AP), -42, 0),
            Duration::from_secs(2),
            None,
        );
        assert_eq!(s.aps.len(), 1);
        assert_eq!(s.stations.len(), 1);
        let ap = &s.aps[&AP];
        assert_eq!(ap.ssid, b"test");
        assert_eq!(ap.channel, Some(6));
        assert_eq!(ap.signal, Some(-42));
        assert_eq!(ap.beacons, 1);
        assert_eq!(ap.packets, 3);
        let sta = &s.stations[&STA];
        assert_eq!(sta.bssid, Some(AP));
        assert_eq!(sta.signal, Some(-70));
        assert_eq!(sta.packets, 2);
        s.expire(Duration::from_secs(123), Duration::from_secs(120));
        assert!(s.aps.is_empty() && s.stations.is_empty());
    }
    #[test]
    fn probes_filter_multicast_wds_hidden_and_security_labels() {
        let mut s = Survey::default();
        let mut probe = frame(0x40, [255; 6], STA, [255; 6]);
        probe.extend([0, 3, b'a', 27, b'b']);
        s.observe(105, &probe, Duration::ZERO, None);
        assert_eq!(display_bytes(&s.stations[&STA].probe), "a\\x1bb");
        let mut filtered = Survey::default();
        filtered.observe(105, &probe, Duration::ZERO, Some(AP));
        assert!(filtered.stations.is_empty());
        let mut b = beacon();
        b[34] = 0x10;
        b.extend([
            48, 18, 1, 0, 0, 15, 172, 4, 1, 0, 0, 15, 172, 4, 1, 0, 0, 15, 172, 8,
        ]);
        s.observe(105, &b, Duration::ZERO, None);
        assert_eq!(s.aps[&AP].security, "RSN/SAE");
        let mut hidden = frame(0x80, [255; 6], AP, AP);
        hidden.extend([0; 12]);
        hidden.extend([0, 0]);
        s.observe(105, &hidden, Duration::ZERO, None);
        assert_eq!(s.aps[&AP].ssid, b"test");
        s.observe(105, &frame(0x0308, AP, STA, AP), Duration::ZERO, None);
        s.observe(105, &frame(0x0208, [255; 6], AP, AP), Duration::ZERO, None);
        assert_eq!(s.stations.len(), 1);
        assert_eq!(s.stations[&STA].packets, 1);
    }
    #[test]
    fn malformed_headers_bad_fcs_and_fragments_are_ignored() {
        let packet = radiotap(&beacon(), -50, 0);
        for end in 0..packet.len() {
            Survey::default().observe(127, &packet[..end], Duration::ZERO, None);
        }
        let mut s = Survey::default();
        s.observe(127, &radiotap(&beacon(), -50, 0x40), Duration::ZERO, None);
        let mut fragmented = beacon();
        fragmented[1] |= 4;
        s.observe(105, &fragmented, Duration::ZERO, None);
        let mut malformed = beacon();
        malformed.extend([0, 32, 1]);
        s.observe(105, &malformed, Duration::ZERO, None);
        s.observe(105, &frame(0x0188, AP, STA, AP), Duration::ZERO, None);
        assert!(s.aps.is_empty() && s.stations.is_empty());
        assert_eq!(s.ignored, 4);
    }
    fn pcap(little: bool) -> Vec<u8> {
        let mut v = if little {
            vec![0xd4, 0xc3, 0xb2, 0xa1, 2, 0, 4, 0]
        } else {
            vec![0xa1, 0xb2, 0xc3, 0xd4, 0, 2, 0, 4]
        };
        v.extend([0; 8]);
        let enc = |n: u32| {
            if little {
                n.to_le_bytes()
            } else {
                n.to_be_bytes()
            }
        };
        v.extend(enc(4096));
        v.extend(enc(105));
        let b = beacon();
        v.extend([0; 8]);
        v.extend(enc(b.len() as u32));
        v.extend(enc(b.len() as u32));
        v.extend(b);
        v
    }
    #[test]
    fn incremental_pcap_handles_partial_writes_and_both_endiannesses() {
        for little in [true, false] {
            let bytes = pcap(little);
            let mut decoder = PcapStream::default();
            let mut count = 0;
            for byte in bytes {
                decoder
                    .poll(&mut &[byte][..], |dlt, packet| {
                        assert_eq!(dlt, 105);
                        assert_eq!(packet, beacon());
                        count += 1;
                    })
                    .unwrap();
            }
            decoder.finish().unwrap();
            assert_eq!(count, 1);
        }
    }
    #[test]
    fn rnr_neighbors_are_reported_separately_from_direct_6ghz_frames() {
        let mut s = Survey::default();
        let mut b = beacon();
        b.extend([201, 12, 0, 8, 131, 5, 1, 2, 9, 8, 7, 6, 5, 2]);
        let mut r = vec![0, 0, 12, 0, 8, 0, 0, 0, 0x43, 0x17, 0, 0];
        r.extend(&b);
        s.observe_record(
            127,
            &r,
            r.len() as u32,
            Some(Duration::from_secs(7)),
            Duration::ZERO,
            None,
        );
        assert_eq!(s.aps.len(), 1);
        assert_eq!(s.rnr_neighbors.len(), 1);
        let ap = &s.aps[&AP];
        let origin = ap.last_direct_observation.as_ref().unwrap();
        assert_eq!(origin.radio.unwrap().band, "6GHz");
        assert_eq!(origin.radio.unwrap().channel, 1);
        assert_eq!(origin.capture_timestamp_seconds, Some(7.0));
        let n = s.rnr_neighbors.values().next().unwrap();
        assert_eq!(n.reporter_bssid, AP);
        assert_eq!(n.neighbor.bssid, Some([2, 9, 8, 7, 6, 5]));
        assert_eq!(n.neighbor.radio.unwrap().frequency_mhz, 5975);
        assert_eq!(n.origin.record_index, 1);
        let mut bad = beacon();
        bad.extend([201, 5, 0, 8, 131, 5, 1]);
        s.observe(105, &bad, Duration::from_secs(1), None);
        assert_eq!(s.quality.malformed_rnr_elements, 1);
        assert_eq!(s.rnr_neighbors.len(), 1);
        let mut filtered = Survey::default();
        filtered.observe(105, &b, Duration::ZERO, Some([2, 0, 0, 0, 0, 9]));
        assert!(filtered.rnr_neighbors.is_empty());
        s.expire(Duration::from_secs(20), Duration::from_secs(10));
        assert!(s.rnr_neighbors.is_empty());
    }
    #[test]
    fn streaming_reader_preserves_record_timestamp_and_original_length() {
        let mut bytes = pcap(true);
        bytes[24..28].copy_from_slice(&3u32.to_le_bytes());
        bytes[28..32].copy_from_slice(&456u32.to_le_bytes());
        let original = (beacon().len() + 9) as u32;
        bytes[36..40].copy_from_slice(&original.to_le_bytes());
        let mut stream = PcapStream::default();
        let mut seen = false;
        stream
            .poll_records(&mut bytes.as_slice(), |_, data, len, ts| {
                assert_eq!(data, beacon());
                assert_eq!(len, original);
                assert_eq!(ts, Some(Duration::new(3, 456_000)));
                seen = true;
            })
            .unwrap();
        assert!(seen);
        stream.finish().unwrap();
    }
    #[test]
    fn pcap_rejects_bad_lengths_link_types_and_truncation() {
        let bytes = pcap(true);
        for end in [0, 8, 23, 25, bytes.len() - 1] {
            let mut d = PcapStream::default();
            d.poll(&mut &bytes[..end], |_, _| {}).unwrap();
            assert!(d.finish().is_err());
        }
        for (offset, value) in [(20, 1u32), (16, 1000000), (32, 1000000), (36, 1)] {
            let mut b = bytes.clone();
            b[offset..offset + 4].copy_from_slice(&value.to_le_bytes());
            assert!(PcapStream::default()
                .poll(&mut b.as_slice(), |_, _| {})
                .is_err());
        }
    }
    #[test]
    fn audit_preserves_last_valid_and_rejects_damaged_records() {
        let mut s = Survey::default();
        let mut b = beacon();
        b[34] = 0x10;
        b.extend([
            48, 20, 1, 0, 0, 15, 172, 4, 1, 0, 0, 15, 172, 4, 1, 0, 0, 15, 172, 2, 0xc0, 0,
        ]);
        s.observe_record(
            105,
            &b,
            b.len() as u32,
            Some(Duration::from_secs(5)),
            Duration::ZERO,
            None,
        );
        assert_eq!(s.aps[&AP].pmf(), "required");
        let mut malformed = b.clone();
        let pos = malformed.len() - 8;
        malformed[pos] = 8;
        s.observe_record(
            105,
            &malformed,
            malformed.len() as u32,
            Some(Duration::from_secs(4)),
            Duration::from_secs(1),
            None,
        );
        assert_eq!(s.aps[&AP].audit_last_status, Some("malformed"));
        assert_eq!(s.aps[&AP].pmf(), "unknown");
        assert_eq!(s.aps[&AP].security_audit.as_ref().unwrap().record_index, 1);
        s.observe_record(
            105,
            &b,
            b.len() as u32 + 1,
            None,
            Duration::from_secs(2),
            None,
        );
        s.observe_record(
            127,
            &radiotap(&b, -30, 0x40),
            (b.len() + 17) as u32,
            None,
            Duration::from_secs(3),
            None,
        );
        assert_eq!(s.quality.truncated_records, 1);
        assert_eq!(s.quality.radiotap_bad_fcs, 1);
        assert_eq!(s.quality.timestamp_regressions, 1);
        assert_eq!(s.aps[&AP].audit_malformed, 1);
        assert_eq!(s.aps[&AP].beacons, 2);
    }
    #[test]
    fn audit_change_and_unknown_fcs_are_reported() {
        let mut s = Survey::default();
        let mut b = beacon();
        s.observe(105, &b, Duration::ZERO, None);
        b[34] = 0x10;
        s.observe(105, &b, Duration::from_secs(1), None);
        assert!(s.aps[&AP].audit_changed);
        assert_eq!(s.quality.fcs_unknown, 2);
        assert_eq!(
            s.aps[&AP]
                .security_audit
                .as_ref()
                .unwrap()
                .advertised
                .observations,
            ["privacy_without_rsn_or_wpa"]
        );
    }
    #[test]
    fn inventory_has_a_hard_row_limit() {
        let mut s = Survey::default();
        for n in 0..MAX_ROWS + 5 {
            let mac = [2, 0, 0, (n >> 16) as u8, (n >> 8) as u8, n as u8];
            let mut p = frame(0x40, [255; 6], mac, [255; 6]);
            p.extend([0, 0]);
            s.observe(105, &p, Duration::from_secs(n as u64), None);
        }
        assert_eq!(s.stations.len(), MAX_ROWS);
        assert_eq!(s.evicted, 5);
    }
}
