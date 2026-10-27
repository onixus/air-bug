//! Bounded two-pass multi-input capture discovery and network selection.
use air_capture::{CaptureError, CaptureLimits, CaptureReader, FrameDecoder, PacketRecord};
use air_crack::{
    engine::TargetSet,
    networks::{Network, Networks},
};
use air_frames::{ssid_bytes_from_beacon, Dot11Frame};
use air_handshake::{extract_targets_limited, VerificationTarget};
use anyhow::{bail, Context, Result};
use serde::Deserialize;
use std::{
    collections::{BTreeMap, BTreeSet},
    io::Read,
    path::PathBuf,
};
type Mac = [u8; 6];
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct SsidEntry {
    bssid: String,
    ssid_hex: String,
}
fn mappings(path: Option<PathBuf>) -> Result<BTreeMap<Mac, Vec<u8>>> {
    let Some(path) = path else {
        return Ok(BTreeMap::new());
    };
    let file = std::fs::File::open(path)?;
    if !file.metadata()?.is_file() || file.metadata()?.len() > 65536 {
        bail!("SSID map must be a regular JSON file up to 64 KiB");
    }
    let mut bytes = Vec::new();
    file.take(65537).read_to_end(&mut bytes)?;
    if bytes.len() > 65536 {
        bail!("SSID map exceeds 64 KiB");
    }
    let entries: Vec<SsidEntry> = serde_json::from_slice(&bytes).context("invalid SSID map")?;
    if entries.len() > 256 {
        bail!("SSID map exceeds 256 networks");
    }
    let mut out = BTreeMap::new();
    for entry in entries {
        let ap = super::parse_mac(&entry.bssid).map_err(anyhow::Error::msg)?;
        let ssid = hex::decode(&entry.ssid_hex).context("invalid SSID map hexadecimal bytes")?;
        if ap == [0; 6]
            || ap[0] & 1 != 0
            || ssid.is_empty()
            || ssid.len() > 32
            || out.insert(ap, ssid).is_some()
        {
            bail!("invalid or duplicate SSID map entry");
        }
    }
    Ok(out)
}
fn ap(frame: &Dot11Frame) -> Option<Mac> {
    if frame.kind == air_frames::FrameKind::Mgmt {
        Some(frame.addr3)
    } else {
        frame.endpoints().map(|(ap, _, _)| ap)
    }
}
fn read_inputs(
    paths: &[PathBuf],
    sizes: &[u64],
    limits: CaptureLimits,
    mut observe: impl FnMut(usize, PacketRecord) -> Result<()>,
) -> Result<Vec<String>> {
    let mut remaining = limits.packets;
    let mut hashes = Vec::new();
    for (index, path) in paths.iter().enumerate() {
        let mut identity = super::dictionary::CaptureIdentity::new();
        for record in CaptureReader::open(
            path,
            CaptureLimits {
                bytes: sizes[index],
                packets: remaining,
            },
        )
        .with_context(|| format!("cannot read capture {}", index + 1))?
        {
            let record = record.context("cannot read capture")?;
            remaining -= 1;
            identity.update(&record);
            observe(index, record)?;
        }
        hashes.push(identity.finish());
    }
    Ok(hashes)
}
#[allow(clippy::too_many_arguments)]
pub fn run(
    captures: Vec<PathBuf>,
    words: Vec<PathBuf>,
    essid: Option<String>,
    bssids: Vec<Mac>,
    ssid_map: Option<PathBuf>,
    options: super::dictionary::Options,
    limits: (CaptureLimits, usize, usize),
) -> Result<()> {
    if captures.is_empty() || captures.len() > 64 || words.len() > 64 || bssids.len() > 256 {
        bail!("at most 64 captures, 64 dictionaries and 256 BSSID selections are supported");
    }
    options.validate(words.first().map(|p| p.as_path()))?;
    if words.iter().any(|p| p.as_os_str() == "-") && words.len() != 1 {
        bail!("stdin must be the only dictionary");
    }
    if essid.as_ref().is_some_and(|s| s.is_empty() || s.len() > 32) {
        bail!("SSID must contain 1 to 32 bytes");
    }
    let map = mappings(ssid_map)?;
    let filter: BTreeSet<_> = bssids.into_iter().collect();
    let (limits, max_records, max_targets) = limits;
    let mut total = 0u64;
    let mut sizes = Vec::new();
    for path in &captures {
        let meta = std::fs::metadata(path).context("cannot read capture")?;
        total = total
            .checked_add(meta.len())
            .context("capture byte budget overflow")?;
        if !meta.is_file() || total > limits.bytes {
            bail!("capture byte limit exceeded or not a regular file");
        }
        sizes.push(meta.len());
    }
    let mut names: BTreeMap<Mac, BTreeSet<Vec<u8>>> = BTreeMap::new();
    let mut name_count = 0;
    let mut decoder = FrameDecoder::default();
    let mut previous = usize::MAX;
    let identities = read_inputs(&captures, &sizes, limits, |index, record| {
        if index != previous {
            decoder = FrameDecoder::default();
            previous = index;
        }
        match decoder.decode(&record.packet, record.timestamp.unwrap_or_default()) {
            Ok(Some(frame)) => {
                if !filter.is_empty() && !filter.contains(&frame.addr3) {
                    return Ok(());
                }
                if let Some(name) = ssid_bytes_from_beacon(&frame) {
                    let set = names.entry(frame.addr3).or_default();
                    if !set.contains(name) {
                        if name_count >= 1024 {
                            bail!("SSID discovery limit exceeded; select BSSIDs explicitly");
                        }
                        set.insert(name.to_vec());
                        name_count += 1;
                    }
                }
            }
            Err(CaptureError::UnsupportedDlt(dlt)) => bail!("unsupported capture link type: {dlt}"),
            _ => {}
        }
        Ok(())
    })?;
    let selected = |ap: Mac| {
        (filter.is_empty() || filter.contains(&ap))
            && essid.as_ref().is_none_or(|name| {
                if let Some(mapped) = map.get(&ap) {
                    mapped == name.as_bytes()
                } else {
                    names
                        .get(&ap)
                        .is_none_or(|known| known.contains(name.as_bytes()))
                }
            })
    };
    let mut evidence = air_capture::evidence::Evidence::new(max_records);
    let (mut count, mut parsed, mut skipped) = (0usize, 0usize, 0usize);
    decoder = FrameDecoder::default();
    previous = usize::MAX;
    let verified = read_inputs(&captures, &sizes, limits, |index, record| {
        if index != previous {
            decoder = FrameDecoder::default();
            previous = index;
        }
        count += 1;
        match decoder.decode(&record.packet, record.timestamp.unwrap_or_default()) {
            Ok(Some(frame)) => {
                parsed += 1;
                if ap(&frame).is_some_and(&selected) {
                    evidence.push(frame)?;
                }
            }
            Ok(None) => {}
            Err(CaptureError::UnsupportedDlt(dlt)) => bail!("unsupported capture link type: {dlt}"),
            Err(_) => skipped += 1,
        }
        Ok(())
    })?;
    if identities != verified {
        bail!("capture changed between discovery and evidence collection");
    }
    println!("[*] packets: {count}");
    println!("[*] parsed frames: {parsed}; skipped: {skipped}");
    let sessions = extract_targets_limited(&evidence.frames, max_records, max_targets)?;
    let pmkids = sessions
        .iter()
        .filter(|s| matches!(s, VerificationTarget::Pmkid(_)))
        .count();
    println!(
        "[*] handshake sessions: {}; PMKID targets: {}",
        sessions.len() - pmkids,
        pmkids
    );
    if sessions.is_empty() {
        bail!("no complete WPA/WPA2-PSK M1/M2, M2/M3 or M3/M4 handshake or PMKID target (including FT and SAE exported-PMK targets) matching the selected network");
    }
    let mut by_ap: BTreeMap<Mac, Vec<VerificationTarget>> = BTreeMap::new();
    for target in sessions {
        by_ap.entry(target.bssid()).or_default().push(target);
    }
    if by_ap.len() > 256 {
        bail!("network limit exceeded (maximum 256)");
    }
    if by_ap.len() == 1 {
        println!(
            "[*] selected BSSID: {}",
            super::multi::mac(by_ap.keys().next().unwrap())
        );
    } else {
        println!("[*] networks: {}", by_ap.len());
    }
    if words.is_empty() {
        for ap in by_ap.keys() {
            println!("[*] network: {}", super::multi::mac(ap));
        }
        return Ok(());
    }
    let mut networks = Vec::new();
    for (ap, targets) in by_ap {
        let ssid = if let Some(mapped) = map.get(&ap) {
            mapped.clone()
        } else if let Some(name) = &essid {
            name.as_bytes().to_vec()
        } else {
            let known = names.get(&ap).with_context(|| {
                format!(
                    "SSID is missing or hidden for {}; provide --essid or --ssid-map",
                    super::multi::mac(&ap)
                )
            })?;
            if known.len() != 1 {
                bail!(
                    "conflicting SSIDs for {}; provide --essid or --ssid-map explicitly",
                    super::multi::mac(&ap)
                );
            }
            known.iter().next().unwrap().clone()
        };
        networks.push(Network {
            bssid: ap,
            targets: TargetSet::new(targets, ssid.clone())?,
            ssid,
        });
    }
    // Keep the established single-input CLI/checkpoint-v5 contract intact.
    if networks.len() == 1
        && captures.len() == 1
        && words.len() == 1
        && options.results_json.is_none()
    {
        let network = networks.pop().unwrap();
        return super::dictionary::run(
            &network.targets,
            identities[0].clone(),
            &words[0],
            &network.ssid,
            network.bssid,
            options,
        );
    }
    let networks = Networks::new(networks)?;
    println!("[*] SSID groups: {}", networks.groups());
    super::multi::run(&networks, identities, &words, options)
}
