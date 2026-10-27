//! Bounded metadata-only evidence tracker using the offline verifier's parsers.
use air_frames::{Dot11Frame, LLC_EAPOL};
use air_handshake::{extract_pmkid_targets, parse_eapol_key};
use std::collections::VecDeque;
use std::time::Duration;

type Mac = [u8; 6];
const MAX_PENDING: usize = 256;
const WINDOW: Duration = Duration::from_secs(120);
#[derive(PartialEq, Eq)]
struct Key {
    ap: Mac,
    sta: Mac,
    counter: u64,
    message: u8,
    descriptor_type: u8,
    descriptor_version: u8,
    nonce_present: bool,
}
struct Pending {
    key: Key,
    seen: Duration,
}
#[derive(Default)]
pub(crate) struct Tracker {
    pending: VecDeque<Pending>,
    pub evicted: u64,
}
pub(crate) struct Evidence {
    pub ft: bool,
    pub ap: Mac,
    pub m1m2: bool,
    pub m2m3: bool,
    pub m3m4: bool,
    pub pmkid: bool,
}
impl Tracker {
    pub fn expire(&mut self, now: Duration) {
        self.pending
            .retain(|p| now.saturating_sub(p.seen) <= WINDOW);
    }
    pub fn observe(
        &mut self,
        frame: &Dot11Frame,
        now: Duration,
        filter: Option<Mac>,
    ) -> Option<Evidence> {
        self.expire(now);
        if let Some(ft) = air_handshake::ft::parse(frame) {
            if filter.is_some_and(|f| f != ft.bssid) {
                return None;
            }
            return Some(Evidence {
                ap: ft.bssid,
                ft: true,
                m1m2: false,
                m2m3: false,
                m3m4: false,
                pmkid: false,
            });
        }
        if let Some((ap, sta, from_ap)) = frame.endpoints() {
            if ap == sta
                || ap == [0; 6]
                || sta == [0; 6]
                || ap[0] & 1 != 0
                || sta[0] & 1 != 0
                || filter.is_some_and(|f| f != ap)
            {
                return None;
            }
            let key = frame
                .payload
                .strip_prefix(&LLC_EAPOL)
                .and_then(parse_eapol_key)?;
            if key.message > 4 || matches!(key.message, 1 | 3) != from_ap {
                return None;
            }
            let counter = key.replay_counter;
            let mut result = Evidence {
                ft: false,
                ap,
                m1m2: false,
                m2m3: false,
                m3m4: false,
                pmkid: !extract_pmkid_targets(std::slice::from_ref(frame)).is_empty(),
            };
            for p in &self.pending {
                if (
                    p.key.ap,
                    p.key.sta,
                    p.key.descriptor_type,
                    p.key.descriptor_version,
                ) == (ap, sta, key.descriptor_type, key.descriptor_version)
                {
                    result.m1m2 |= matches!((p.key.message, key.message), (1, 2) | (2, 1))
                        && p.key.counter == counter;
                    result.m2m3 |= (p.key.message == 2
                        && key.message == 3
                        && p.key.counter.checked_add(1) == Some(counter))
                        || (p.key.message == 3
                            && key.message == 2
                            && counter.checked_add(1) == Some(p.key.counter));
                }
            }
            let result_descriptor = (key.descriptor_type, key.descriptor_version);
            let key = Key {
                ap,
                sta,
                counter,
                message: key.message,
                descriptor_type: key.descriptor_type,
                descriptor_version: key.descriptor_version,
                nonce_present: key.nonce != [0; 32],
            };
            // Refresh duplicates without allowing retransmissions to fill the cache.
            self.pending.retain(|p| p.key != key);
            if self.pending.len() == MAX_PENDING {
                self.pending.pop_front();
                self.evicted += 1;
            }
            self.pending.push_back(Pending { key, seen: now });
            for auth in &self.pending {
                if auth.key.ap != ap
                    || auth.key.sta != sta
                    || auth.key.message != 3
                    || auth.key.descriptor_type != result_descriptor.0
                    || auth.key.descriptor_version != result_descriptor.1
                {
                    continue;
                }
                let m2 = self.pending.iter().any(|p| {
                    p.key.ap == ap
                        && p.key.sta == sta
                        && p.key.message == 2
                        && p.key.descriptor_type == result_descriptor.0
                        && p.key.descriptor_version == result_descriptor.1
                        && p.key.counter.checked_add(1) == Some(auth.key.counter)
                });
                result.m3m4 |= self.pending.iter().any(|p| {
                    p.key.ap == ap
                        && p.key.sta == sta
                        && p.key.message == 4
                        && p.key.descriptor_type == result_descriptor.0
                        && p.key.descriptor_version == result_descriptor.1
                        && p.key.counter == auth.key.counter
                        && (m2 || p.key.nonce_present && !matches!(p.key.descriptor_version, 0 | 3))
                });
            }
            Some(result)
        } else {
            let targets = extract_pmkid_targets(std::slice::from_ref(frame));
            let target = targets.first()?;
            if filter.is_some_and(|f| f != target.bssid) {
                return None;
            }
            Some(Evidence {
                ft: false,
                ap: target.bssid,
                m1m2: false,
                m2m3: false,
                m3m4: false,
                pmkid: true,
            })
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    fn message(n: u8, sta: u8, counter: u64) -> Dot11Frame {
        let ap = [2, 0, 0, 0, 0, 1];
        let sta = [2, 0, 0, 0, 0, sta];
        let mut key = vec![0; 99];
        key[..5].copy_from_slice(&[2, 3, 0, 95, 2]);
        let flags: u16 = match n {
            1 => 0x008a,
            2 => 0x010a,
            _ => 0x13ca,
        };
        key[5..7].copy_from_slice(&flags.to_be_bytes());
        key[9..17].copy_from_slice(&counter.to_be_bytes());
        key[17..49].fill(n);
        if n != 1 {
            key[81..97].fill(3);
        }
        let mut payload = LLC_EAPOL.to_vec();
        payload.extend(key);
        Dot11Frame {
            kind: air_frames::FrameKind::Data,
            frame_control: if n == 2 { 0x0108 } else { 0x0208 },
            addr1: if n == 2 { ap } else { sta },
            addr2: if n == 2 { sta } else { ap },
            addr3: ap,
            addr4: None,
            payload,
        }
    }
    #[test]
    fn reordered_pairs_are_endpoint_counter_and_direction_specific() {
        let mut t = Tracker::default();
        assert!(
            !t.observe(&message(2, 2, 7), Duration::ZERO, None)
                .unwrap()
                .m1m2
        );
        assert!(
            !t.observe(&message(1, 3, 7), Duration::ZERO, None)
                .unwrap()
                .m1m2
        );
        assert!(
            !t.observe(&message(1, 2, 8), Duration::ZERO, None)
                .unwrap()
                .m1m2
        );
        assert!(
            t.observe(&message(1, 2, 7), Duration::ZERO, None)
                .unwrap()
                .m1m2
        );
        assert!(
            t.observe(&message(3, 2, 8), Duration::ZERO, None)
                .unwrap()
                .m2m3
        );
        let len = t.pending.len();
        t.observe(&message(3, 2, 8), Duration::ZERO, None);
        assert_eq!(t.pending.len(), len);
        assert!(
            !t.observe(&message(3, 2, 0), Duration::ZERO, None)
                .unwrap()
                .m2m3
        );
        let mut bad = message(2, 2, 7);
        bad.frame_control = 0x0208;
        assert!(Tracker::default()
            .observe(&bad, Duration::ZERO, None)
            .is_none());
        assert!(Tracker::default()
            .observe(&message(1, 2, 7), Duration::ZERO, Some([2; 6]))
            .is_none());
    }
    #[test]
    fn pending_evidence_has_a_time_window_and_hard_capacity() {
        let mut t = Tracker::default();
        t.observe(&message(1, 2, 0), Duration::ZERO, None);
        assert!(
            !t.observe(&message(2, 2, 0), Duration::from_secs(121), None)
                .unwrap()
                .m1m2
        );
        let mut t = Tracker::default();
        for counter in 0..=MAX_PENDING as u64 {
            t.observe(&message(1, 2, counter), Duration::ZERO, None);
        }
        assert_eq!(t.pending.len(), MAX_PENDING);
        assert_eq!(t.evicted, 1);
        assert!(
            !t.observe(&message(2, 2, 0), Duration::ZERO, None)
                .unwrap()
                .m1m2
        );
    }
}
