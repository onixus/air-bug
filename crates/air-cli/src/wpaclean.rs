use air_capture::{
    evidence::{relevant, Evidence},
    CaptureError, CaptureLimits, CaptureReader, FrameDecoder,
};
use air_frames::{ssid_bytes_from_beacon, Dot11Frame, LLC_EAPOL};
use air_handshake::{extract_targets_limited, parse_eapol_key, VerificationTarget};
use anyhow::{bail, Context, Result};
use clap::Args;
use std::collections::BTreeSet;
use std::path::PathBuf;

#[derive(Args, Debug)]
pub struct CleanArgs {
    #[arg(short, long)]
    input: PathBuf,
    /// New PCAP; default <input stem>-clean.cap; never overwritten
    #[arg(short, long)]
    output: Option<PathBuf>,
    #[arg(short = 'b', long, value_parser = super::parse_mac)]
    bssid: Option<[u8; 6]>,
    /// Maximum input MiB; independent of retained evidence memory
    #[arg(long, default_value = "4096", value_parser = clap::value_parser!(u64).range(1..=1048576))]
    max_capture_mib: u64,
    #[arg(long, default_value = "10000000", value_parser = clap::value_parser!(u32).range(1..))]
    max_packets: u32,
    #[arg(long, default_value = "1024", value_parser = clap::value_parser!(u32).range(1..=1024))]
    max_records: u32,
}

/// Select provenance for each target: one exact M2 and its matching M1/M3,
/// or the single authenticated-structure FT/PMKID record. No MIC is verified
/// without credentials; "clean" means usable structure, never a proven key.
fn supporting(frames: &[Dot11Frame], targets: &[VerificationTarget]) -> BTreeSet<usize> {
    let mut selected = BTreeSet::new();
    for target in targets {
        match target {
            VerificationTarget::Handshake(session) => {
                for (i, frame) in frames.iter().enumerate() {
                    if frame.endpoints() != Some((session.bssid, session.sta, false)) {
                        continue;
                    }
                    let Some(m2) = frame
                        .payload
                        .strip_prefix(&LLC_EAPOL)
                        .and_then(parse_eapol_key)
                    else {
                        continue;
                    };
                    if !matches!(m2.message, 2 | 4)
                        || Some(m2.mic) != session.mic
                        || m2.bytes.len() != session.eapol.len()
                        || m2.bytes[..81] != session.eapol[..81]
                        || m2.bytes[97..] != session.eapol[97..]
                    {
                        continue;
                    }
                    if let Some((j, _)) = frames.iter().enumerate().find(|(_, auth)| {
                        if auth.endpoints() != Some((session.bssid, session.sta, true)) {
                            return false;
                        }
                        let Some(key) = auth
                            .payload
                            .strip_prefix(&LLC_EAPOL)
                            .and_then(parse_eapol_key)
                        else {
                            return false;
                        };
                        Some(key.nonce) == session.anonce
                            && key.descriptor_type == m2.descriptor_type
                            && key.descriptor_version == m2.descriptor_version
                            && if m2.message == 4 {
                                key.message == 3 && key.replay_counter == m2.replay_counter
                            } else {
                                (key.message == 1 && key.replay_counter == m2.replay_counter)
                                    || (key.message == 3
                                        && key.replay_counter.checked_sub(1)
                                            == Some(m2.replay_counter))
                            }
                    }) {
                        selected.extend([i, j]);
                        if let Some(source) = &session.nonce_source {
                            if let Some(k) = frames.iter().position(|frame| {
                                frame.endpoints() == Some((session.bssid, session.sta, false))
                                    && frame
                                        .payload
                                        .strip_prefix(&LLC_EAPOL)
                                        .and_then(parse_eapol_key)
                                        .is_some_and(|key| key.bytes == source)
                            }) {
                                selected.insert(k);
                            }
                        }
                        break;
                    }
                }
            }
            VerificationTarget::Pmkid(id) => {
                if let Some(i) = frames.iter().position(|frame| {
                    air_handshake::extract_pmkid_targets(std::slice::from_ref(frame)).contains(id)
                }) {
                    selected.insert(i);
                }
            }
            VerificationTarget::Ft(ft) => {
                if let Some(i) = frames.iter().position(|frame| {
                    air_handshake::ft::parse(frame).is_some_and(|candidate| {
                        candidate.bssid == ft.bssid
                            && candidate.sta == ft.sta
                            && candidate.mic == ft.mic
                            && candidate.mic_data == ft.mic_data
                    })
                }) {
                    selected.insert(i);
                }
            }
        }
    }
    selected
}

pub fn run(args: CleanArgs) -> Result<()> {
    let reader = CaptureReader::open(
        &args.input,
        CaptureLimits {
            bytes: args.max_capture_mib * 1024 * 1024,
            packets: args.max_packets as usize,
        },
    )?;
    let mut decoder = FrameDecoder::default();
    let mut evidence = Evidence::new(args.max_records as usize);
    let mut records = Vec::new();
    let (mut packets, mut skipped) = (0u64, 0u64);
    for record in reader {
        let record = record.context("cannot read capture")?;
        packets += 1;
        if record.packet.data.len() != record.original_len as usize {
            skipped += 1;
            continue;
        }
        match decoder.decode_normalized(&record.packet, record.timestamp) {
            Ok(Some((frame, normalized))) => {
                if evidence.push(frame)? {
                    records.push(normalized);
                }
            }
            Ok(None) => {}
            Err(CaptureError::UnsupportedDlt(dlt)) => bail!("unsupported capture link type: {dlt}"),
            Err(_) => skipped += 1,
        }
    }
    let frames = &evidence.frames;
    let targets: Vec<_> = extract_targets_limited(frames, args.max_records as usize, 1024)?
        .into_iter()
        .filter(|target| args.bssid.is_none_or(|ap| target.bssid() == ap))
        .collect();
    if targets.is_empty() {
        bail!("no complete supported handshake, FT or PMKID target; no output created");
    }
    let aps: BTreeSet<_> = targets.iter().map(VerificationTarget::bssid).collect();
    let mut selected = supporting(frames, &targets);
    for (i, frame) in frames.iter().enumerate() {
        if !relevant(frame) && aps.contains(&frame.addr3) && ssid_bytes_from_beacon(frame).is_some()
        {
            selected.insert(i);
        }
    }
    // Ensure normalized output preserves every selected target before publishing.
    let retained: Vec<_> = selected.iter().map(|&i| frames[i].clone()).collect();
    if extract_targets_limited(&retained, args.max_records as usize, 1024)?.len() != targets.len() {
        bail!("cleaned evidence does not preserve selected targets; no output created");
    }
    let path = args.output.unwrap_or_else(|| {
        let mut name = args.input.file_stem().unwrap_or_default().to_os_string();
        name.push("-clean.cap");
        args.input.with_file_name(name)
    });
    let mut out = super::capture_output::PrivatePcap::create(&path, 105)?;
    let mut missing = 0;
    for i in selected {
        missing += usize::from(records[i].timestamp.is_none());
        out.write(
            records[i].timestamp.unwrap_or_default(),
            &records[i].packet.data,
        )?;
    }
    let written = out.finish()?;
    println!("Cleaned {packets} packets into {written} records; targets={} networks={} skipped={skipped} missing-timestamps={missing} fragments-pending={}\nOutput: {}", targets.len(), aps.len(), decoder.reassembly.pending(), path.display());
    Ok(())
}
