//! Authenticated pairwise and GTK key collection for bounded offline decryption.
use air_core::{mic_version, ptk_extended, unwrap_key_data, unwrap_wpa1};
use air_crack::{constant_time_eq, Engine};
use air_frames::{Dot11Frame, LLC_EAPOL};
use air_handshake::{extract_targets_limited, parse_eapol_key, VerificationTarget};
use anyhow::{bail, Result};
use std::collections::BTreeMap;
type Mac = [u8; 6];
type Peer = (Mac, Mac);
#[derive(PartialEq, Eq)]
struct PairKey {
    ptk: [u8; 64],
    version: u8,
    descriptor: u8,
    cipher: u8,
    group_cipher: Option<u8>,
    anonce: [u8; 32],
    counter: Option<u64>,
}
#[derive(PartialEq, Eq)]
struct GroupKey {
    bytes: Vec<u8>,
}
pub struct Piece {
    pub body: Vec<u8>,
    pub security: air_frames::reassembly::Security,
    pub pn: Option<u64>,
    pub michael: Option<[u8; 8]>,
}
#[derive(Default)]
pub struct Keys {
    pairs: BTreeMap<Peer, Vec<PairKey>>,
    groups: BTreeMap<(Mac, u8), Vec<GroupKey>>,
    pub gtk_installed: usize,
    pub gtk_rejected: usize,
}
impl Keys {
    pub fn collect(
        frames: &[Dot11Frame],
        pmk: &[u8; 32],
        ssid: &[u8],
        filter: Option<Mac>,
        exported_pmk: bool,
    ) -> Result<Self> {
        let mut out = Self::default();
        for target in extract_targets_limited(frames, 1024, 1024)? {
            if let VerificationTarget::Ft(ft) = &target {
                if filter.is_some_and(|b| b != ft.bssid) {
                    continue;
                }
                if ssid.is_empty() {
                    bail!("FT key derivation requires --essid");
                }
                if ft.akm == 9 && !exported_pmk {
                    continue;
                }
                let Some(ptk) = ft.verified_ptk(pmk, ssid) else {
                    continue;
                };
                if let Some(gtk) = &ft.gtk {
                    // FT GTK subelement: Key Info(2), Key Length(1), RSC(8), AES-wrapped key.
                    if gtk.len() < 11 || gtk[2] != 16 || gtk[0] & 0xfc != 0 || gtk[1] != 0 {
                        out.gtk_rejected += 1;
                    } else if let Some(bytes) =
                        unwrap_key_data(ptk[16..32].try_into().unwrap(), &gtk[11..])
                            .filter(|b| b.len() == 16)
                    {
                        let list = out.groups.entry((ft.bssid, gtk[0] & 3)).or_default();
                        let key = GroupKey { bytes };
                        if !list.contains(&key) {
                            if list.len() >= 64 || out.gtk_installed >= 1024 {
                                bail!("GTK resource limit exceeded");
                            }
                            list.push(key);
                            out.gtk_installed += 1;
                        }
                    } else {
                        out.gtk_rejected += 1;
                    }
                }
                let pair = PairKey {
                    ptk,
                    version: if ft.akm == 9 { 0 } else { 3 },
                    descriptor: 2,
                    cipher: 4,
                    group_cipher: Some(4),
                    anonce: ft.anonce,
                    counter: None,
                };
                let list = out.pairs.entry((ft.bssid, ft.sta)).or_default();
                if !list.contains(&pair) {
                    if list.len() >= 64 {
                        bail!("temporal-key limit exceeded");
                    }
                    list.push(pair);
                }
                continue;
            }
            let VerificationTarget::Handshake(session) = target else {
                continue;
            };
            if filter.is_some_and(|b| b != session.bssid) {
                continue;
            }
            let mut original = session.eapol.clone();
            original[81..97].copy_from_slice(&session.mic.unwrap());
            let Some(key) = parse_eapol_key(&original) else {
                continue;
            };
            if session.profile().is_some_and(|p| p.akm == 8) && !exported_pmk {
                continue;
            }
            let engine_ssid = if ssid.is_empty() {
                b"PMK".as_slice()
            } else {
                ssid
            };
            if !Engine::new(session.clone(), engine_ssid.to_vec())?.verify_pmk(pmk) {
                continue;
            }
            let pair = PairKey {
                ptk: ptk_extended(
                    pmk,
                    &session.bssid,
                    &session.sta,
                    &session.anonce.unwrap(),
                    &session.snonce.unwrap(),
                    session.profile().is_some_and(|p| matches!(p.akm, 6 | 8)),
                ),
                version: key.descriptor_version,
                descriptor: key.descriptor_type,
                cipher: session
                    .profile()
                    .map_or(if key.descriptor_version == 1 { 2 } else { 4 }, |p| {
                        p.cipher
                    }),
                group_cipher: session.profile().map(|p| p.group_cipher),
                anonce: session.anonce.unwrap(),
                counter: Some(if key.message == 4 {
                    key.replay_counter.checked_sub(1).unwrap_or(u64::MAX)
                } else {
                    key.replay_counter
                }),
            };
            let list = out.pairs.entry((session.bssid, session.sta)).or_default();
            if !list.contains(&pair) {
                if list.len() >= 64 {
                    bail!("temporal-key limit exceeded (64 per AP/client)");
                }
                list.push(pair);
            }
        }
        if out.pairs.is_empty() {
            bail!("no authenticated handshake for the supplied key and selection; SAE/FT-SAE require an exported PMK (--pmk), not a password");
        }
        // The whole capture is available: reordered M3/G1 can be authenticated
        // against the corresponding peer's PTK without trusting packet order.
        for frame in frames {
            let Some((ap, sta, true)) = frame.endpoints() else {
                continue;
            };
            let Some(peer_keys) = out.pairs.get(&(ap, sta)) else {
                continue;
            };
            let Some(key) = frame
                .payload
                .strip_prefix(&LLC_EAPOL)
                .and_then(parse_eapol_key)
            else {
                continue;
            };
            if !matches!(key.message, 3 | 5) || key.key_data.is_empty() {
                continue;
            }
            if key.key_data.len() > 4096 {
                out.gtk_rejected += 1;
                continue;
            }
            let mut accepted = false;
            for pair in peer_keys {
                if pair.version != key.descriptor_version || pair.descriptor != key.descriptor_type
                {
                    continue;
                }
                if key.message == 3
                    && (key.nonce != pair.anonce
                        || pair
                            .counter
                            .is_some_and(|c| c.checked_add(1) != Some(key.replay_counter)))
                {
                    continue;
                }
                let mut eapol = key.bytes.to_vec();
                eapol[81..97].fill(0);
                if !mic_version(pair.ptk[..48].try_into().unwrap(), &eapol, pair.version)
                    .is_some_and(|mic| constant_time_eq(&mic, &key.mic))
                {
                    continue;
                }
                let info = u16::from_be_bytes([key.bytes[5], key.bytes[6]]);
                if pair.descriptor == 2 && info & 0x1000 == 0 {
                    continue;
                }
                let kek: &[u8; 16] = pair.ptk[16..32].try_into().unwrap();
                let decoded = if pair.version == 1 {
                    unwrap_wpa1(kek, key.bytes[49..65].try_into().unwrap(), key.key_data)
                } else {
                    unwrap_key_data(kek, key.key_data)
                };
                let Some(decoded) = decoded else {
                    continue;
                };
                let gtks = if pair.descriptor == 254 && key.message == 5 {
                    let len = u16::from_be_bytes([key.bytes[7], key.bytes[8]]) as usize;
                    if !matches!(len, 16 | 32) || decoded.len() != len {
                        continue;
                    }
                    vec![(((info >> 4) & 3) as u8, decoded)]
                } else {
                    let Some(keys) = gtk_kdes(&decoded) else {
                        continue;
                    };
                    keys
                };
                if gtks.iter().any(|(_, bytes)| {
                    pair.group_cipher
                        .is_some_and(|c| (c == 4) != (bytes.len() == 16))
                }) {
                    continue;
                }
                for (id, bytes) in gtks {
                    let list = out.groups.entry((ap, id)).or_default();
                    let group = GroupKey { bytes };
                    if !list.contains(&group) {
                        if list.len() >= 64 || out.gtk_installed >= 1024 {
                            bail!("GTK resource limit exceeded");
                        }
                        list.push(group);
                        out.gtk_installed += 1;
                    }
                }
                accepted = true;
                break;
            }
            if !accepted {
                out.gtk_rejected += 1;
            }
        }
        Ok(out)
    }
    pub fn decrypt(&self, frame: &[u8], length: usize) -> Option<Piece> {
        let header = frame.get(length..length + 8)?;
        let key_id = header[3] >> 6;
        if frame[1] & 3 == 3 {
            // WDS has no BSSID. Only keys authenticated for exactly this pair
            // of radio peers are candidates, in either authenticator orientation.
            if frame[4] & 1 != 0 || frame[10] & 1 != 0 || key_id != 0 {
                return None;
            }
            let receiver: Mac = frame[4..10].try_into().ok()?;
            let transmitter: Mac = frame[10..16].try_into().ok()?;
            for (ap, sta, from_ap) in [
                (transmitter, receiver, true),
                (receiver, transmitter, false),
            ] {
                if let Some(keys) = self.pairs.get(&(ap, sta)) {
                    for key in keys {
                        let piece = if key.cipher == 4 {
                            decrypt_data(frame, length, &key.ptk[32..48], 4)
                        } else {
                            let mut bytes = key.ptk[32..64].to_vec();
                            if !from_ap {
                                bytes[16..24].copy_from_slice(&key.ptk[56..64]);
                            }
                            decrypt_data(frame, length, &bytes, 2)
                        };
                        if piece.is_some() {
                            return piece;
                        }
                    }
                }
            }
            return None;
        }
        let ap: Mac = match frame[1] & 3 {
            1 => frame[4..10].try_into().ok()?,
            2 => frame[10..16].try_into().ok()?,
            _ => return None,
        };
        let group = frame[4] & 1 != 0;
        if group {
            if frame[1] & 3 != 2 {
                return None;
            }
            self.groups.get(&(ap, key_id))?.iter().find_map(|key| {
                decrypt_data(
                    frame,
                    length,
                    &key.bytes,
                    if key.bytes.len() == 16 { 4 } else { 2 },
                )
            })
        } else {
            if key_id != 0 {
                return None;
            }
            let sta = if frame[1] & 3 == 1 {
                frame[10..16].try_into().ok()?
            } else {
                frame[4..10].try_into().ok()?
            };
            self.pairs.get(&(ap, sta))?.iter().find_map(|key| {
                if key.cipher == 4 {
                    decrypt_data(frame, length, &key.ptk[32..48], 4)
                } else {
                    let mut bytes = key.ptk[32..64].to_vec();
                    if frame[1] & 3 == 1 {
                        bytes[16..24].copy_from_slice(&key.ptk[56..64]);
                    }
                    decrypt_data(frame, length, &bytes, 2)
                }
            })
        }
    }
}
fn gtk_kdes(mut data: &[u8]) -> Option<Vec<(u8, Vec<u8>)>> {
    let mut out = Vec::new();
    while !data.is_empty() {
        if data[0] == 0xdd && data.get(1) == Some(&0) && data[2..].iter().all(|b| *b == 0) {
            break;
        }
        let len = *data.get(1)? as usize;
        let value = data.get(2..2 + len)?;
        if data[0] == 221 && value.starts_with(&[0, 15, 172, 1]) {
            if !matches!(len, 22 | 38) || value[4] & 0xf8 != 0 || value[5] != 0 {
                return None;
            }
            let id = value[4] & 3;
            if out.iter().any(|(seen, _)| *seen == id) {
                return None;
            }
            out.push((id, value[6..].to_vec()));
        }
        data = &data[2 + len..];
    }
    Some(out)
}
fn decrypt_data(frame: &[u8], length: usize, key: &[u8], cipher: u8) -> Option<Piece> {
    let hdr = frame.get(length..length + 8)?;
    let qos = frame[0] & 0x80 != 0;
    let tid = air_frames::qos_tid(frame)?;
    if cipher == 2 {
        if key.len() != 32 {
            return None;
        }
        let (destination, source) = air_frames::data_addresses(frame)?;
        let fragmented = frame[1] & 4 != 0 || frame[22] & 15 != 0;
        let body = if fragmented {
            air_core::tkip::decrypt_mpdu(
                key[..16].try_into().ok()?,
                frame[10..16].try_into().ok()?,
                &frame[length..],
            )?
        } else {
            air_core::tkip::decrypt(
                key[..16].try_into().ok()?,
                key[16..24].try_into().ok()?,
                frame[10..16].try_into().ok()?,
                &destination,
                &source,
                tid,
                &frame[length..],
            )?
        };
        let mut pn = [0; 8];
        pn[..6].copy_from_slice(&[hdr[2], hdr[0], hdr[4], hdr[5], hdr[6], hdr[7]]);
        Some(Piece {
            body,
            security: air_frames::reassembly::Security {
                key: air_core::key_fingerprint(key),
                protected: true,
                key_id: hdr[3] >> 6,
            },
            pn: Some(u64::from_le_bytes(pn)),
            michael: if fragmented {
                Some(key[16..24].try_into().ok()?)
            } else {
                None
            },
        })
    } else {
        if hdr[2] != 0 || hdr[3] & 0x3f != 0x20 {
            return None;
        }
        let mut nonce = [0; 13];
        nonce[0] = tid;
        nonce[1..7].copy_from_slice(&frame[10..16]);
        nonce[7..].copy_from_slice(&[hdr[7], hdr[6], hdr[5], hdr[4], hdr[1], hdr[0]]);
        let mut aad = vec![frame[0] & 0x8f, frame[1] & 0xc7];
        aad.extend_from_slice(&frame[4..22]);
        aad.extend([frame[22] & 15, 0]);
        if frame[1] & 3 == 3 {
            aad.extend_from_slice(&frame[24..30]);
        }
        if qos {
            aad.extend([tid, 0]);
        }
        let body =
            air_core::decrypt_ccmp(key.try_into().ok()?, &nonce, &aad, &frame[length + 8..])?;
        let mut pn = [0; 8];
        pn[..6].copy_from_slice(&[hdr[0], hdr[1], hdr[4], hdr[5], hdr[6], hdr[7]]);
        Some(Piece {
            body,
            security: air_frames::reassembly::Security {
                key: air_core::key_fingerprint(key),
                protected: true,
                key_id: hdr[3] >> 6,
            },
            pn: Some(u64::from_le_bytes(pn)),
            michael: None,
        })
    }
}
