use air_core::{candidate_pmk, kck, mic_version, pmkid};
use air_handshake::{
    parse_eapol_key, HandshakeError, HandshakeSession, PmkidSession, VerificationTarget,
};
use rayon::prelude::*;
use std::io;
use thiserror::Error;

#[derive(Debug, Error)]
pub enum CrackError {
    #[error(transparent)]
    Handshake(#[from] HandshakeError),
    #[error("SSID must contain 1 to 32 bytes")]
    InvalidSsid,
    #[error("wordlist: {0}")]
    Wordlist(#[from] io::Error),
}

pub struct Engine {
    ssid: Vec<u8>,
    target: ValidatedTarget,
    allow_passphrase: bool,
}

enum ValidatedTarget {
    Handshake {
        session: HandshakeSession,
        anonce: [u8; 32],
        snonce: [u8; 32],
        mic: [u8; 16],
        version: u8,
        sha256: bool,
    },
    Pmkid(PmkidSession),
    Ft(air_handshake::ft::FtSession),
}

impl Engine {
    pub fn new(session: HandshakeSession, ssid: Vec<u8>) -> Result<Self, CrackError> {
        if ssid.is_empty() || ssid.len() > 32 {
            return Err(CrackError::InvalidSsid);
        }
        let anonce = session
            .anonce
            .filter(|n| *n != [0; 32])
            .ok_or(HandshakeError::Incomplete)?;
        let snonce = session
            .snonce
            .filter(|n| *n != [0; 32])
            .ok_or(HandshakeError::Incomplete)?;
        let target_mic = session
            .mic
            .filter(|m| *m != [0; 16])
            .ok_or(HandshakeError::Incomplete)?;
        if session.bssid == session.sta
            || session.bssid == [0; 6]
            || session.sta == [0; 6]
            || session.bssid[0] & 1 != 0
            || session.sta[0] & 1 != 0
            || session.eapol.get(81..97) != Some(&[0; 16])
        {
            return Err(HandshakeError::Incomplete.into());
        }
        let mut original = session.eapol.clone();
        original[81..97].copy_from_slice(&target_mic);
        let key = parse_eapol_key(&original).ok_or(HandshakeError::Incomplete)?;
        if key.bytes.len() != original.len() {
            return Err(HandshakeError::Incomplete.into());
        }
        match key.message {
            2 if key.nonce == snonce && session.nonce_source.is_none() => {}
            4 => {
                if let Some(source) = &session.nonce_source {
                    let m2 = parse_eapol_key(source).ok_or(HandshakeError::Incomplete)?;
                    if m2.message != 2
                        || m2.bytes.len() != source.len()
                        || m2.nonce != snonce
                        || m2.descriptor_type != key.descriptor_type
                        || m2.descriptor_version != key.descriptor_version
                        || m2.replay_counter.checked_add(1) != Some(key.replay_counter)
                        || (key.nonce != [0; 32] && key.nonce != snonce)
                    {
                        return Err(HandshakeError::Incomplete.into());
                    }
                } else if key.nonce != snonce || matches!(key.descriptor_version, 0 | 3) {
                    return Err(HandshakeError::Incomplete.into());
                }
            }
            _ => return Err(HandshakeError::Incomplete.into()),
        }
        let profile = session.profile();
        Ok(Self {
            allow_passphrase: !profile.is_some_and(|p| p.akm == 8),
            ssid,
            target: ValidatedTarget::Handshake {
                session,
                anonce,
                snonce,
                mic: target_mic,
                version: key.descriptor_version,
                sha256: profile.is_some_and(|p| matches!(p.akm, 6 | 8)),
            },
        })
    }

    pub fn from_target(target: VerificationTarget, ssid: Vec<u8>) -> Result<Self, CrackError> {
        match target {
            VerificationTarget::Handshake(session) => Self::new(session, ssid),
            VerificationTarget::Ft(session) => {
                if ssid.is_empty() || ssid.len() > 32 {
                    return Err(CrackError::InvalidSsid);
                }
                Ok(Self {
                    ssid,
                    allow_passphrase: session.akm == 4,
                    target: ValidatedTarget::Ft(session),
                })
            }
            VerificationTarget::Pmkid(session) => {
                if ssid.is_empty() || ssid.len() > 32 {
                    return Err(CrackError::InvalidSsid);
                }
                if session.bssid == session.sta
                    || session.bssid == [0; 6]
                    || session.sta == [0; 6]
                    || session.bssid[0] & 1 != 0
                    || session.sta[0] & 1 != 0
                    || session.pmkid == [0; 16]
                {
                    return Err(HandshakeError::Incomplete.into());
                }
                Ok(Self {
                    ssid,
                    target: ValidatedTarget::Pmkid(session),
                    allow_passphrase: true,
                })
            }
        }
    }

    pub fn verify_candidate(&self, pass: &str) -> bool {
        if !self.allow_passphrase && pass.len() != 64 {
            return false;
        }
        let Some(pmk) = candidate_pmk(pass, &self.ssid) else {
            return false;
        };
        self.verify_pmk(&pmk)
    }

    pub fn verify_pmk(&self, pmk: &[u8; 32]) -> bool {
        match &self.target {
            ValidatedTarget::Handshake {
                session,
                anonce,
                snonce,
                mic: target_mic,
                version,
                sha256,
            } => {
                let mut ptk = [0; 48];
                ptk[..16].copy_from_slice(&kck(
                    pmk,
                    &session.bssid,
                    &session.sta,
                    anonce,
                    snonce,
                    *sha256,
                ));
                mic_version(ptk[..48].try_into().unwrap(), &session.eapol, *version)
                    .is_some_and(|mic| crate::verify::mic_matches(&mic, target_mic))
            }
            ValidatedTarget::Ft(session) => session.verified_ptk(pmk, &self.ssid).is_some(),
            ValidatedTarget::Pmkid(session) => crate::verify::mic_matches(
                &pmkid(pmk, &session.bssid, &session.sta),
                &session.pmkid,
            ),
        }
    }

    pub fn crack<I>(&self, candidates: I) -> Option<String>
    where
        I: IntoParallelIterator<Item = String> + Send,
    {
        candidates
            .into_par_iter()
            .find_any(|pass| self.verify_candidate(pass))
    }

    /// Bound dictionary memory and propagate read/encoding errors rather than
    /// silently treating an unreadable suffix as an exhausted wordlist.
    pub fn crack_wordlist<I>(&self, candidates: I) -> Result<Option<String>, CrackError>
    where
        I: IntoIterator<Item = io::Result<String>>,
    {
        let mut candidates = candidates.into_iter();
        loop {
            let batch: Vec<String> = candidates.by_ref().take(256).collect::<io::Result<_>>()?;
            if batch.is_empty() {
                return Ok(None);
            }
            if let Some(pass) = self.crack(batch) {
                return Ok(Some(pass));
            }
        }
    }
}

/// A single SSID's targets. PBKDF2 runs once per candidate, irrespective of
/// handshake/PMKID count. A match against any target verifies the network key.
pub struct TargetSet {
    ssid: Vec<u8>,
    engines: Vec<Engine>,
}
impl TargetSet {
    pub fn new(targets: Vec<VerificationTarget>, ssid: Vec<u8>) -> Result<Self, CrackError> {
        if targets.is_empty() {
            return Err(HandshakeError::Incomplete.into());
        }
        let engines = targets
            .into_iter()
            .map(|target| Engine::from_target(target, ssid.clone()))
            .collect::<Result<_, _>>()?;
        Ok(Self { ssid, engines })
    }
    pub(crate) fn belongs_to(&self, ssid: &[u8], bssid: [u8; 6]) -> bool {
        self.ssid == ssid
            && self.engines.iter().all(|engine| match &engine.target {
                ValidatedTarget::Handshake { session, .. } => session.bssid == bssid,
                ValidatedTarget::Pmkid(session) => session.bssid == bssid,
                ValidatedTarget::Ft(session) => session.bssid == bssid,
            })
    }
    pub fn requires_exported_pmk(&self) -> bool {
        self.engines.iter().all(|e| !e.allow_passphrase)
    }
    pub fn verify_candidate(&self, pass: &str) -> bool {
        if pass.len() != 64 && !self.engines.iter().any(|e| e.allow_passphrase) {
            return false;
        }
        let Some(pmk) = candidate_pmk(pass, &self.ssid) else {
            return false;
        };
        self.engines
            .iter()
            .any(|engine| (pass.len() == 64 || engine.allow_passphrase) && engine.verify_pmk(&pmk))
    }
    /// Verify a supplied PMK while retaining the original candidate's provenance.
    /// A PBKDF2-derived key must never turn a passphrase into an exported SAE PMK.
    pub fn verify_precomputed(&self, pass: &str, pmk: &[u8; 32]) -> bool {
        let raw = if pass.len() == 64 {
            match air_core::candidate_pmk(pass, &self.ssid) {
                Some(decoded) if crate::verify::constant_time_eq(&decoded, pmk) => true,
                _ => return false,
            }
        } else {
            false
        };
        if !raw && !air_core::valid_passphrase(pass) {
            return false;
        }
        self.engines
            .iter()
            .any(|engine| (raw || engine.allow_passphrase) && engine.verify_pmk(pmk))
    }
    /// One bounded batch; disk lookups/writes stay outside Rayon workers.
    /// Exact duplicate passphrases in the batch share one derivation.
    pub fn crack_batch_cached(
        &self,
        candidates: &[String],
        cache: &mut crate::cache::Cache,
    ) -> io::Result<Option<(usize, String)>> {
        if candidates.len() > 256 {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "cached batches are limited to 256 candidates",
            ));
        }
        let prepared = prepare_candidates(
            &self.ssid,
            candidates,
            !self.requires_exported_pmk(),
            Some(cache),
        )?;
        Ok(candidates
            .par_iter()
            .enumerate()
            .find_first(|(index, pass)| {
                prepared[*index].is_some_and(|pmk| self.verify_precomputed(pass, &pmk))
            })
            .map(|(index, pass)| (index, pass.clone())))
    }
    pub fn crack_batch(&self, candidates: &[String]) -> Option<(usize, String)> {
        candidates
            .par_iter()
            .enumerate()
            .find_first(|(_, pass)| self.verify_candidate(pass))
            .map(|(index, pass)| (index, pass.clone()))
    }
}

/// Shared, bounded preparation for every network having the same exact SSID.
/// Raw PMKs are decoded directly; only passphrases enter the persistent cache.
pub(crate) fn prepare_candidates(
    ssid: &[u8],
    candidates: &[String],
    allow_passphrases: bool,
    mut cache: Option<&mut crate::cache::Cache>,
) -> io::Result<Vec<Option<[u8; 32]>>> {
    if candidates.len() > 256 {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "batches are limited to 256 candidates",
        ));
    }
    let mut keys: std::collections::BTreeMap<&str, ([u8; 32], Option<[u8; 32]>)> =
        std::collections::BTreeMap::new();
    if allow_passphrases {
        for pass in candidates {
            if air_core::valid_passphrase(pass) && !keys.contains_key(pass.as_str()) {
                let key = crate::cache::key(ssid, pass);
                let pmk = match cache.as_deref_mut() {
                    Some(cache) => cache.get(&key)?,
                    None => None,
                };
                keys.insert(pass, (key, pmk));
            }
        }
    }
    let missing: Vec<_> = keys
        .iter()
        .filter(|(_, (_, pmk))| pmk.is_none())
        .map(|(&pass, _)| pass)
        .collect();
    let derived: Vec<_> = missing
        .par_iter()
        .map(|pass| air_core::pmk(pass, ssid))
        .collect();
    if let Some(cache) = cache.as_deref_mut() {
        cache.stats.derived += derived.len() as u64;
    }
    for (pass, pmk) in missing.into_iter().zip(derived) {
        let entry = keys.get_mut(pass).unwrap();
        if let Some(cache) = cache.as_deref_mut() {
            cache.put(&entry.0, &pmk)?;
        }
        entry.1 = Some(pmk);
    }
    if let Some(cache) = cache {
        cache.flush()?;
    }
    Ok(candidates
        .iter()
        .map(|pass| {
            if pass.len() == 64 {
                candidate_pmk(pass, ssid)
            } else {
                keys.get(pass.as_str()).and_then(|(_, pmk)| *pmk)
            }
        })
        .collect())
}
