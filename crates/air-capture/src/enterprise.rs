//! Passive EAP metadata only. Never retain identities, challenges or TLS bytes.
use serde::Serialize;
use std::collections::BTreeSet;

#[derive(Clone, Debug, Default, Serialize)]
pub struct EapAudit {
    pub requests: u64,
    pub responses: u64,
    pub success_frames: u64,
    pub failure_frames: u64,
    pub identity_responses: u64,
    pub malformed_or_wrong_direction: u64,
    pub unsupported_code_frames: u64,
    pub observed_types: BTreeSet<u8>,
    /// IETF types below 256 carried inside a valid Expanded header.
    pub expanded_ietf_types: BTreeSet<u8>,
}
impl EapAudit {
    pub(crate) fn observe(&mut self, bytes: &[u8], from_ap: bool) {
        let valid = || -> Option<(u8, Option<u8>, Option<u8>)> {
            if !matches!(*bytes.first()?, 1..=3) || *bytes.get(1)? != 0 {
                return None;
            }
            let body_len = u16::from_be_bytes(bytes.get(2..4)?.try_into().ok()?) as usize;
            let body = bytes.get(4..4 + body_len)?;
            let len = u16::from_be_bytes(body.get(2..4)?.try_into().ok()?) as usize;
            // RFC 3748 section 4: lower-layer padding outside EAP Length is ignored.
            if len < 4 {
                return None;
            }
            let eap = body.get(..len)?;
            let code = eap[0];
            match code {
                1 | 2 if (code == 1) == from_ap && len >= 5 && eap[4] != 0 => {
                    let wire_type = eap[4];
                    let expanded = if wire_type == 254 {
                        // Type + Vendor-Id (3) + Vendor-Type (4) are mandatory.
                        let header = eap.get(5..12)?;
                        let vendor_type = u32::from_be_bytes(header[3..7].try_into().ok()?);
                        if header[..3] == [0; 3] {
                            if vendor_type == 0 {
                                return None;
                            }
                            u8::try_from(vendor_type).ok()
                        } else {
                            None
                        }
                    } else {
                        None
                    };
                    let method = expanded.unwrap_or(wire_type);
                    if method == 3
                        && (code != 2
                            || if wire_type == 254 {
                                len < 20 || !(len - 12).is_multiple_of(8)
                            } else {
                                len < 6
                            })
                    {
                        return None;
                    }
                    Some((code, Some(wire_type), expanded))
                }
                3 | 4 if from_ap && len == 4 => Some((code, None, None)),
                // ERP/future codes retain only their unsupported-frame count.
                5..=255 => Some((code, None, None)),
                _ => None,
            }
        };
        let Some((code, method, expanded)) = valid() else {
            self.malformed_or_wrong_direction += 1;
            return;
        };
        match code {
            1 => self.requests += 1,
            2 => self.responses += 1,
            3 => self.success_frames += 1,
            4 => self.failure_frames += 1,
            _ => self.unsupported_code_frames += 1,
        }
        if let Some(method) = method {
            self.observed_types.insert(method);
            self.identity_responses += u64::from(code == 2 && expanded.unwrap_or(method) == 1);
        }
        if let Some(method) = expanded {
            self.expanded_ietf_types.insert(method);
        }
    }
    pub fn observations(&self) -> Vec<&'static str> {
        let mut notes = Vec::new();
        if self.identity_responses > 0 {
            notes.push("outer_identity_response_seen_review_anonymous_identity_policy");
        }
        if self.observed_types.contains(&4) || self.expanded_ietf_types.contains(&4) {
            notes.push("outer_eap_md5_seen_review_method_policy");
        }
        if self.failure_frames > 0 {
            notes.push("eap_failure_frame_seen_check_server_and_client_logs");
        }
        notes
    }
    pub fn type_names(&self) -> Vec<String> {
        let name = |t: &u8| {
            let name = match t {
                1 => "Identity",
                2 => "Notification",
                3 => "Nak",
                4 => "MD5-Challenge",
                13 => "EAP-TLS",
                21 => "EAP-TTLS",
                25 => "PEAP",
                29 => "EAP-MSCHAP-V2",
                43 => "EAP-FAST",
                55 => "TEAP",
                254 => "Expanded",
                _ => "Other",
            };
            format!("{name}({t})")
        };
        self.observed_types
            .iter()
            .map(name)
            .chain(
                self.expanded_ietf_types
                    .iter()
                    .map(|t| format!("Expanded/IETF:{}", name(t))),
            )
            .collect()
    }
    pub fn summary(&self) -> String {
        format!(
            "EAP req/resp={}/{} success/failure={}/{} identity={} types={:?} invalid={} unsupported={}",
            self.requests,
            self.responses,
            self.success_frames,
            self.failure_frames,
            self.identity_responses,
            self.type_names(),
            self.malformed_or_wrong_direction,
            self.unsupported_code_frames
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn eap_lengths_direction_padding_and_identity_redaction() {
        let mut audit = EapAudit::default();
        let identity = [
            2, 0, 0, 11, 2, 7, 0, 11, 1, b's', b'e', b'c', b'r', b'e', b't',
        ];
        audit.observe(&identity, false);
        assert_eq!(audit.identity_responses, 1);
        assert!(!format!("{audit:?}").contains("secret"));
        for len in 0..identity.len() {
            audit.observe(&identity[..len], false);
        }
        assert_eq!(audit.malformed_or_wrong_direction, identity.len() as u64);
        audit.observe(&identity, true);
        assert_eq!(audit.responses, 1);
        audit.observe(&[2, 0, 0, 4, 3, 7, 0, 4, 0, 0], true);
        audit.observe(&[2, 0, 0, 4, 4, 7, 0, 4], true);
        assert_eq!((audit.success_frames, audit.failure_frames), (1, 1));
        audit.observe(&[2, 0, 0, 5, 1, 8, 0, 5, 13], true);
        audit.observe(&[2, 0, 0, 5, 1, 9, 0, 5, 25], true);
        assert!(audit.observed_types.contains(&13));
        assert!(audit.observed_types.contains(&25));
        audit.observe(&[2, 0, 0, 4, 5, 7, 0, 4], true);
        assert_eq!(audit.unsupported_code_frames, 1);
        let before = audit.requests;
        audit.observe(&[2, 0, 0, 5, 1, 9, 0, 6, 4], true);
        assert_eq!(audit.requests, before);
    }
}

#[cfg(test)]
mod regression_tests {
    use super::*;
    fn packet(eap: &[u8]) -> Vec<u8> {
        let mut p = vec![2, 0];
        p.extend((eap.len() as u16).to_be_bytes());
        p.extend(eap);
        p
    }
    #[test]
    fn padding_is_ignored_but_truncated_eap_is_rejected() {
        let mut a = EapAudit::default();
        a.observe(&packet(&[2, 1, 0, 5, 1, 0xaa, 0xbb]), false);
        a.observe(&packet(&[3, 1, 0, 4, 0xaa]), true);
        assert_eq!(a.identity_responses, 1);
        assert_eq!(a.success_frames, 1);
        a.observe(&packet(&[2, 1, 0, 6, 1]), false);
        assert_eq!(a.malformed_or_wrong_direction, 1);
    }
    #[test]
    fn expanded_headers_are_complete_and_ietf_identity_md5_are_recognized() {
        let mut a = EapAudit::default();
        for len in 5..12 {
            let mut p = vec![2, 1, 0, len, 254];
            p.resize(len as usize, 0);
            a.observe(&packet(&p), false);
        }
        assert_eq!(a.responses, 0);
        assert_eq!(a.malformed_or_wrong_direction, 7);
        a.observe(&packet(&[2, 1, 0, 12, 254, 0, 0, 0, 0, 0, 0, 1]), false);
        a.observe(&packet(&[1, 1, 0, 12, 254, 0, 0, 0, 0, 0, 0, 4]), true);
        assert_eq!(a.identity_responses, 1);
        assert!(a.expanded_ietf_types.contains(&4));
        assert!(a
            .observations()
            .contains(&"outer_eap_md5_seen_review_method_policy"));
        // Vendor types are not interpreted as IETF types, even when the number matches.
        a.observe(&packet(&[2, 1, 0, 12, 254, 0, 0, 1, 0, 0, 0, 1]), false);
        assert_eq!(a.identity_responses, 1);
        // Invalid Nak requests and empty Nak responses cannot become method evidence.
        a.observe(&packet(&[1, 1, 0, 6, 3, 13]), true);
        a.observe(&packet(&[2, 1, 0, 5, 3]), false);
        assert!(!a.observed_types.contains(&3));
        a.observe(&packet(&[2, 1, 0, 12, 254, 0, 0, 0, 0, 0, 0, 3]), false);
        assert!(!a.expanded_ietf_types.contains(&3));
        let nak = [
            2, 1, 0, 20, 254, 0, 0, 0, 0, 0, 0, 3, 254, 0, 0, 0, 0, 0, 0, 13,
        ];
        a.observe(&packet(&nak), false);
        assert!(a.expanded_ietf_types.contains(&3));
    }
}
