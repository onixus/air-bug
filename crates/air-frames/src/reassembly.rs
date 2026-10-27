//! Bounded, fail-closed 802.11 fragment assembly. Authentication is per fragment;
//! callers bind the security context to the actual key and verify TKIP Michael
//! after this layer returns a complete MSDU. No ciphertext is assembled here.
use crate::wire_header_len;
use std::{collections::BTreeMap, time::Duration};
const MAX_CHAINS: usize = 256;
const MAX_BYTES: usize = 4 * 1024 * 1024;
const MAX_MSDU: usize = 65535;
const TTL: Duration = Duration::from_secs(2);
#[derive(Debug, Default)]
pub struct Stats {
    pub completed: u64,
    pub dropped: u64,
    pub evicted: u64,
    pub duplicates: u64,
}
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Security {
    pub key: [u8; 32],
    pub protected: bool,
    pub key_id: u8,
}
impl Security {
    pub fn clear() -> Self {
        Self {
            key: [0; 32],
            protected: false,
            key_id: 0,
        }
    }
}
#[derive(PartialEq, Eq, PartialOrd, Ord)]
struct Identity {
    receiver: [u8; 6],
    transmitter: [u8; 6],
    sequence: u16,
    tid: u8,
}
struct Part {
    header: Vec<u8>,
    body: Vec<u8>,
    pn: Option<u64>,
    more: bool,
    time: Duration,
    known: bool,
}
struct Chain {
    seen: Duration,
    security: Security,
    signature: Vec<u8>,
    parts: [Option<Part>; 16],
    last: Option<usize>,
    poisoned: bool,
}
pub struct Complete {
    pub frame: Vec<u8>,
    pub time: Duration,
    pub timestamp_known: bool,
}
#[derive(Default)]
pub struct Reassembler {
    chains: BTreeMap<Identity, Chain>,
    bytes: usize,
    pub stats: Stats,
}
impl Reassembler {
    pub fn pending(&self) -> usize {
        self.chains.values().filter(|c| !c.poisoned).count()
    }
    fn remove(&mut self, key: &Identity) {
        if let Some(c) = self.chains.remove(key) {
            self.bytes -= c
                .parts
                .iter()
                .flatten()
                .map(|p| p.body.len() + p.header.len())
                .sum::<usize>();
        }
    }
    pub fn expire(&mut self, now: Duration) {
        let stale: Vec<_> = self
            .chains
            .iter()
            .filter(|(_, c)| now.saturating_sub(c.seen) > TTL)
            .map(|(k, _)| Identity {
                receiver: k.receiver,
                transmitter: k.transmitter,
                sequence: k.sequence,
                tid: k.tid,
            })
            .collect();
        for k in stale {
            self.remove(&k);
            self.stats.evicted += 1;
        }
    }
    fn poison(&mut self, key: &Identity) {
        if let Some(c) = self.chains.get_mut(key) {
            self.bytes -= c
                .parts
                .iter()
                .flatten()
                .map(|p| p.body.len() + p.header.len())
                .sum::<usize>();
            c.parts = std::array::from_fn(|_| None);
            c.poisoned = true;
        }
        self.stats.dropped += 1;
    }
    pub fn push(
        &mut self,
        frame: &[u8],
        body: Vec<u8>,
        security: Security,
        pn: Option<u64>,
        now: Duration,
    ) -> Option<Complete> {
        self.push_timed(frame, body, security, pn, now, Some(now))
    }
    pub fn push_timed(
        &mut self,
        frame: &[u8],
        body: Vec<u8>,
        security: Security,
        pn: Option<u64>,
        now: Duration,
        timestamp: Option<Duration>,
    ) -> Option<Complete> {
        self.expire(now);
        let length = wire_header_len(frame).ok()?;
        let seq = u16::from_le_bytes(frame[22..24].try_into().ok()?);
        let fragment = (seq & 15) as usize;
        let more = frame[1] & 4 != 0;
        if body.len() + length > MAX_MSDU {
            self.stats.dropped += 1;
            return None;
        }
        if !more && fragment == 0 {
            let mut out = frame[..length].to_vec();
            out.extend(body);
            return Some(Complete {
                frame: out,
                time: timestamp.unwrap_or_default(),
                timestamp_known: timestamp.is_some(),
            });
        }
        if frame[4] & 1 != 0 || fragment == 15 && more {
            self.stats.dropped += 1;
            return None;
        }
        let key = Identity {
            receiver: frame[4..10].try_into().ok()?,
            transmitter: frame[10..16].try_into().ok()?,
            sequence: seq >> 4,
            tid: if frame[0] & 0x8c == 0x88 {
                crate::qos_tid(frame)?
            } else {
                16
            },
        };
        let mut signature = frame[..length].to_vec();
        signature[1] &= !0x0c;
        signature[2..4].fill(0);
        signature[22] &= 0xf0;
        if !self.chains.contains_key(&key) {
            if self.chains.len() == MAX_CHAINS {
                let oldest = self
                    .chains
                    .iter()
                    .min_by_key(|(_, c)| c.seen)
                    .map(|(k, _)| Identity {
                        receiver: k.receiver,
                        transmitter: k.transmitter,
                        sequence: k.sequence,
                        tid: k.tid,
                    })
                    .unwrap();
                self.remove(&oldest);
                self.stats.evicted += 1;
            }
            self.chains.insert(
                Identity {
                    receiver: key.receiver,
                    transmitter: key.transmitter,
                    sequence: key.sequence,
                    tid: key.tid,
                },
                Chain {
                    seen: now,
                    security: security.clone(),
                    signature: signature.clone(),
                    parts: std::array::from_fn(|_| None),
                    last: None,
                    poisoned: false,
                },
            );
        }
        let c = self.chains.get(&key)?;
        if c.poisoned {
            return None;
        }
        if c.security != security
            || c.signature != signature
            || c.last.is_some_and(|n| fragment > n)
            || (!more && c.last.is_some_and(|n| n != fragment))
            || (!more && c.parts[fragment + 1..].iter().any(Option::is_some))
        {
            self.poison(&key);
            return None;
        }
        if let Some(old) = &c.parts[fragment] {
            if old.body == body && old.pn == pn && old.more == more {
                self.stats.duplicates += 1;
            } else {
                self.poison(&key);
            }
            return None;
        }
        let total = c
            .parts
            .iter()
            .flatten()
            .map(|p| p.body.len())
            .sum::<usize>()
            + body.len()
            + length;
        if total > MAX_MSDU || self.bytes + body.len() + length > MAX_BYTES {
            self.poison(&key);
            return None;
        }
        self.bytes += body.len() + length;
        let c = self.chains.get_mut(&key)?;
        c.parts[fragment] = Some(Part {
            header: frame[..length].to_vec(),
            body,
            pn,
            more,
            time: timestamp.unwrap_or_default(),
            known: timestamp.is_some(),
        });
        if !more {
            c.last = Some(fragment);
        }
        let last = c.last?;
        if c.parts[..=last].iter().any(Option::is_none) {
            return None;
        }
        for i in 1..=last {
            let a = c.parts[i - 1].as_ref()?.pn;
            let b = c.parts[i].as_ref()?.pn;
            if match (a, b) {
                (Some(a), Some(b)) => a.checked_add(1) != Some(b),
                (None, None) => false,
                _ => true,
            } {
                self.poison(&key);
                return None;
            }
        }
        let first = c.parts[0].as_ref()?;
        let time = first.time;
        let timestamp_known = first.known;
        let mut out = first.header.clone();
        out[1] &= !0x0c;
        out[22] &= 0xf0;
        for p in c.parts[..=last].iter().flatten() {
            out.extend(&p.body);
        }
        self.remove(&key);
        self.stats.completed += 1;
        Some(Complete {
            frame: out,
            time,
            timestamp_known,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    fn frame(fragment: u8, more: bool) -> Vec<u8> {
        let mut f = vec![0; 26];
        f[..2].copy_from_slice(&(0x0288u16 | if more { 0x400 } else { 0 }).to_le_bytes());
        f[4..10].copy_from_slice(&[2, 0, 0, 0, 0, 1]);
        f[10..16].copy_from_slice(&[2, 0, 0, 0, 0, 2]);
        f[16..22].copy_from_slice(&[2, 0, 0, 0, 0, 3]);
        f[22..24].copy_from_slice(&(0x1230u16 | fragment as u16).to_le_bytes());
        f[24] = 5;
        f
    }
    #[test]
    fn reordered_fragments_and_identical_retries_produce_one_complete_msdu() {
        let mut s = Reassembler::default();
        let sec = Security::clear();
        assert!(s
            .push(
                &frame(2, false),
                b"c".to_vec(),
                sec.clone(),
                Some(9),
                Duration::ZERO
            )
            .is_none());
        assert!(s
            .push(
                &frame(0, true),
                b"a".to_vec(),
                sec.clone(),
                Some(7),
                Duration::ZERO
            )
            .is_none());
        let mut retry = frame(0, true);
        retry[1] |= 8;
        assert!(s
            .push(&retry, b"a".to_vec(), sec.clone(), Some(7), Duration::ZERO)
            .is_none());
        let out = s
            .push(&frame(1, true), b"b".to_vec(), sec, Some(8), Duration::ZERO)
            .unwrap();
        assert_eq!(&out.frame[26..], b"abc");
        assert_eq!(out.frame[1] & 0x0c, 0);
        assert_eq!(out.frame[22] & 15, 0);
        assert_eq!(s.stats.duplicates, 1);
        assert_eq!(s.pending(), 0);
        assert_eq!(s.bytes, 0);
    }
    #[test]
    fn conflicting_payload_or_key_epoch_poison_the_entire_chain() {
        for key_change in [false, true] {
            let mut s = Reassembler::default();
            let first = Security::clear();
            let mut other = first.clone();
            if key_change {
                other.key[0] = 1;
            }
            s.push(
                &frame(0, true),
                b"a".to_vec(),
                first.clone(),
                Some(1),
                Duration::ZERO,
            );
            let f = if key_change {
                frame(1, false)
            } else {
                frame(0, true)
            };
            assert!(s
                .push(&f, b"different".to_vec(), other, Some(2), Duration::ZERO)
                .is_none());
            assert!(s
                .push(
                    &frame(1, false),
                    b"b".to_vec(),
                    first,
                    Some(2),
                    Duration::ZERO
                )
                .is_none());
            assert_eq!(s.pending(), 0);
            assert_eq!(s.stats.dropped, 1);
            assert_eq!(s.bytes, 0);
        }
    }
    #[test]
    fn packet_number_gaps_and_header_mixing_do_not_assemble() {
        for address_change in [false, true] {
            let mut s = Reassembler::default();
            s.push(
                &frame(0, true),
                vec![1],
                Security::clear(),
                Some(1),
                Duration::ZERO,
            );
            let mut f = frame(1, false);
            if address_change {
                f[21] ^= 1;
            }
            assert!(s
                .push(
                    &f,
                    vec![2],
                    Security::clear(),
                    Some(if address_change { 2 } else { 3 }),
                    Duration::ZERO
                )
                .is_none());
            assert_eq!(s.stats.dropped, 1);
        }
    }
    #[test]
    fn timeout_capacity_and_size_are_bounded() {
        let mut s = Reassembler::default();
        s.push(
            &frame(0, true),
            vec![1],
            Security::clear(),
            None,
            Duration::ZERO,
        );
        assert!(s
            .push(
                &frame(1, false),
                vec![2],
                Security::clear(),
                None,
                Duration::from_secs(3)
            )
            .is_none());
        assert_eq!(s.stats.evicted, 1);
        for i in 0..300u16 {
            let mut f = frame(0, true);
            f[22..24].copy_from_slice(&(i << 4).to_le_bytes());
            s.push(
                &f,
                vec![0; 20000],
                Security::clear(),
                None,
                Duration::from_secs(3),
            );
        }
        assert!(s.chains.len() <= MAX_CHAINS);
        assert!(s.bytes <= MAX_BYTES);
        assert!(s.stats.dropped > 0);
        assert!(s
            .push(
                &frame(0, true),
                vec![0; MAX_MSDU],
                Security::clear(),
                None,
                Duration::from_secs(3)
            )
            .is_none());
    }
    #[test]
    fn multicast_and_impossible_fragment_tail_are_rejected() {
        let mut s = Reassembler::default();
        let mut f = frame(0, true);
        f[4] |= 1;
        assert!(s
            .push(&f, vec![1], Security::clear(), None, Duration::ZERO)
            .is_none());
        assert!(s
            .push(
                &frame(15, true),
                vec![1],
                Security::clear(),
                None,
                Duration::ZERO
            )
            .is_none());
        assert_eq!(s.pending(), 0);
    }
}
