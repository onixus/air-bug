//! Unauthenticated management observations; no inferred association or outage.
use crate::survey::{mac_string, Mac};
use serde::Serialize;
use std::collections::VecDeque;
use std::time::Duration;
const MAX_EVENTS: usize = 512;

#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize)]
pub struct Capabilities {
    pub mobility_domain_hex: Option<String>,
    pub ft_over_ds: Option<bool>,
    pub resource_request: Option<bool>,
    pub neighbor_report: Option<bool>,
    pub bss_transition: Option<bool>,
}
impl Capabilities {
    pub fn summary(&self) -> String {
        let flag = |v| match v {
            Some(true) => "yes",
            Some(false) => "no",
            None => "?",
        };
        format!(
            "MD={} FT-over-DS={} resource-request={} neighbor-report={} BSS-transition={}",
            self.mobility_domain_hex.as_deref().unwrap_or("?"),
            flag(self.ft_over_ds),
            flag(self.resource_request),
            flag(self.neighbor_report),
            flag(self.bss_transition)
        )
    }
}
/// Absence of an IE is unknown, not proof that a feature is disabled.
pub(crate) fn capabilities(mut ies: &[u8]) -> Result<Capabilities, ()> {
    let mut result = Capabilities::default();
    let (mut md, mut rm, mut ext) = (false, false, false);
    while !ies.is_empty() {
        let id = ies[0];
        let n = *ies.get(1).ok_or(())? as usize;
        let value = ies.get(2..2 + n).ok_or(())?;
        match id {
            54 => {
                if md || n != 3 {
                    return Err(());
                }
                md = true;
                result.mobility_domain_hex = Some(format!("{:02x}{:02x}", value[0], value[1]));
                result.ft_over_ds = Some(value[2] & 1 != 0);
                result.resource_request = Some(value[2] & 2 != 0);
            }
            70 => {
                if rm || n != 5 {
                    return Err(());
                }
                rm = true;
                result.neighbor_report = Some(value[0] & 2 != 0);
            }
            127 => {
                if ext || n == 0 {
                    return Err(());
                }
                ext = true;
                result.bss_transition = value.get(2).map(|b| b & 8 != 0);
            }
            _ => {}
        }
        ies = &ies[2 + n..];
    }
    Ok(result)
}
#[derive(Clone, Debug, Serialize)]
pub struct Event {
    pub kind: &'static str,
    pub bssid: String,
    pub station: String,
    pub previous_bssid: Option<String>,
    pub status_code: Option<u16>,
    pub reason_code: Option<u16>,
    pub authentication_algorithm: Option<u16>,
    pub authentication_sequence: Option<u16>,
    pub from_ap: bool,
    pub retry: bool,
    pub record_index: u64,
    pub capture_timestamp_seconds: Option<f64>,
    pub processing_seconds: f64,
}
#[derive(Default)]
pub struct Diagnostics {
    pub events: VecDeque<Event>,
    pub evicted: u64,
    pub malformed_management: u64,
}
fn unicast(m: Mac) -> bool {
    m != [0; 6] && m[0] & 1 == 0
}
impl Diagnostics {
    pub(crate) fn observe(
        &mut self,
        frame: &[u8],
        record_index: u64,
        timestamp: Option<Duration>,
        now: Duration,
        filter: Option<Mac>,
    ) -> bool {
        if frame.len() < 24 {
            return false;
        }
        let fc = u16::from_le_bytes([frame[0], frame[1]]);
        // Protected/fragmented frames are opaque; DS bits must be clear for management.
        if fc & 0xc70f != 0 || frame[22] & 15 != 0 {
            return false;
        }
        let subtype = (fc >> 4) & 15;
        if !matches!(subtype, 0 | 1 | 2 | 3 | 10 | 11 | 12) {
            return false;
        }
        let a1: Mac = frame[4..10].try_into().unwrap();
        let a2: Mac = frame[10..16].try_into().unwrap();
        let ap: Mac = frame[16..22].try_into().unwrap();
        let from_ap = a2 == ap;
        let sta = if from_ap { a1 } else { a2 };
        if !unicast(ap)
            || !unicast(sta)
            || ap == sta
            || (!from_ap && a1 != ap)
            || filter.is_some_and(|m| m != ap)
        {
            return false;
        }
        let p = &frame[24..];
        let word = |i| p.get(i..i + 2).map(|v| u16::from_le_bytes([v[0], v[1]]));
        let needed = match subtype {
            0 => 4,
            2 => 10,
            1 | 3 | 11 => 6,
            _ => 2,
        };
        if p.len() < needed
            || (matches!(subtype, 0 | 2) && from_ap)
            || (matches!(subtype, 1 | 3) && !from_ap)
        {
            self.malformed_management += 1;
            return false;
        }
        // Validate TLV boundaries on association frames before recording them.
        if matches!(subtype, 0..=3) && capabilities(&p[needed..]).is_err() {
            self.malformed_management += 1;
            return false;
        }
        let previous_bssid = if subtype == 2 {
            let old: Mac = p[4..10].try_into().unwrap();
            if !unicast(old) {
                self.malformed_management += 1;
                return false;
            }
            Some(mac_string(&old))
        } else {
            None
        };
        let event = Event {
            kind: match subtype {
                0 => "association_request",
                1 => "association_response",
                2 => "reassociation_request",
                3 => "reassociation_response",
                10 => "disassociation",
                11 => "authentication",
                _ => "deauthentication",
            },
            bssid: mac_string(&ap),
            station: mac_string(&sta),
            previous_bssid,
            status_code: match subtype {
                1 | 3 => word(2),
                11 => word(4),
                _ => None,
            },
            reason_code: if matches!(subtype, 10 | 12) {
                word(0)
            } else {
                None
            },
            authentication_algorithm: if subtype == 11 { word(0) } else { None },
            authentication_sequence: if subtype == 11 { word(2) } else { None },
            from_ap,
            retry: fc & 0x0800 != 0,
            record_index,
            capture_timestamp_seconds: timestamp.map(|t| t.as_secs_f64()),
            processing_seconds: now.as_secs_f64(),
        };
        if self.events.len() == MAX_EVENTS {
            self.events.pop_front();
            self.evicted += 1;
        }
        self.events.push_back(event);
        true
    }
}
