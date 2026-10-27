//! Multiple BSSIDs, sharing one candidate derivation per exact SSID.
use crate::{
    cache::Cache,
    engine::{prepare_candidates, TargetSet},
};
use rayon::prelude::*;
use std::{collections::BTreeMap, io};
pub struct Network {
    pub bssid: [u8; 6],
    pub ssid: Vec<u8>,
    pub targets: TargetSet,
}
pub struct Networks {
    networks: Vec<Network>,
    groups: BTreeMap<Vec<u8>, Vec<usize>>,
}
impl Networks {
    pub fn new(networks: Vec<Network>) -> io::Result<Self> {
        if networks.is_empty() || networks.len() > 256 {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "network count must be 1..256",
            ));
        }
        let mut groups: BTreeMap<Vec<u8>, Vec<usize>> = BTreeMap::new();
        let mut seen = std::collections::BTreeSet::new();
        for (index, network) in networks.iter().enumerate() {
            if network.ssid.is_empty()
                || network.ssid.len() > 32
                || !network.targets.belongs_to(&network.ssid, network.bssid)
                || !seen.insert(network.bssid)
            {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidInput,
                    "invalid SSID or duplicate network BSSID",
                ));
            }
            groups.entry(network.ssid.clone()).or_default().push(index);
        }
        Ok(Self { networks, groups })
    }
    pub fn networks(&self) -> &[Network] {
        &self.networks
    }
    pub fn groups(&self) -> usize {
        self.groups.len()
    }
    /// Return each unresolved BSSID's earliest match in this batch. Input order
    /// remains authoritative, even when targets or PBKDF2 execute in parallel.
    pub fn crack_batch(
        &self,
        candidates: &[String],
        solved: &[bool],
        mut cache: Option<&mut Cache>,
    ) -> io::Result<Vec<Option<usize>>> {
        if solved.len() != self.networks.len() || candidates.len() > 256 {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "invalid multi-network batch",
            ));
        }
        let mut found = vec![None; self.networks.len()];
        for (ssid, indices) in &self.groups {
            let active: Vec<_> = indices
                .iter()
                .copied()
                .filter(|&index| !solved[index])
                .collect();
            if active.is_empty() {
                continue;
            }
            let allow = active
                .iter()
                .any(|&i| !self.networks[i].targets.requires_exported_pmk());
            let prepared = prepare_candidates(ssid, candidates, allow, cache.as_deref_mut())?;
            let matches: Vec<_> = active
                .par_iter()
                .map(|&index| {
                    let first = candidates.iter().enumerate().position(|(i, pass)| {
                        prepared[i].is_some_and(|pmk| {
                            self.networks[index].targets.verify_precomputed(pass, &pmk)
                        })
                    });
                    (index, first)
                })
                .collect();
            for (index, first) in matches {
                found[index] = first;
            }
        }
        Ok(found)
    }
}
