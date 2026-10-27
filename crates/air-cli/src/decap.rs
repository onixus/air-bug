use air_capture::{dlt_decode, CaptureLimits, CaptureReader, FrameDecoder};
use air_core::{candidate_pmk, decrypt_wep};
use air_frames::{wire_header_len, LLC_EAPOL};
use anyhow::{bail, Context, Result};
use clap::Args;
use std::path::PathBuf;

#[derive(Args, Debug)]
pub struct DecapArgs {
    #[arg(short, long)]
    input: PathBuf,
    /// New PCAP output, default <input stem>-dec.cap; never overwritten
    #[arg(short, long)]
    output: Option<PathBuf>,
    #[arg(short = 'e', long)]
    essid: Option<String>,
    /// WPA/WPA2 passphrase or 64-hex PSK (avoid shared shell history)
    #[arg(short = 'p', long, conflicts_with_all = ["pmk", "wep_key"], requires = "essid")]
    pass: Option<String>,
    /// Explicit 32-byte WPA/WPA2 PMK in hexadecimal; SSID is not required
    #[arg(short = 'k', long, conflicts_with = "wep_key")]
    pmk: Option<String>,
    /// WEP40/WEP104 key: exactly 10 or 26 hexadecimal characters
    #[arg(short = 'w', long)]
    wep_key: Option<String>,
    #[arg(short = 'b', long, value_parser = super::parse_mac)]
    bssid: Option<[u8; 6]>,
    /// Emit raw 802.11 instead of Ethernet (Radiotap/FCS removed)
    #[arg(short = 'l', long)]
    keep_wireless: bool,
    /// Input work budget in MiB; independent of retained memory
    #[arg(long, default_value = "4096", value_parser = clap::value_parser!(u64).range(1..=1048576))]
    max_capture_mib: u64,
    #[arg(long, default_value = "10000000", value_parser = clap::value_parser!(u32).range(1..))]
    max_packets: u32,
}
fn ethernet(frame: &[u8], payload: &[u8]) -> Option<Vec<u8>> {
    if payload.len() < 8
        || payload[..3] != [0xaa, 0xaa, 3]
        || !matches!(&payload[3..6], [0, 0, 0] | [0, 0, 0xf8])
    {
        return None;
    }
    let (dst, src) = air_frames::data_addresses(frame)?;
    let mut out = dst.to_vec();
    out.extend_from_slice(&src);
    out.extend_from_slice(&payload[6..]);
    Some(out)
}

pub fn run(args: DecapArgs) -> Result<()> {
    if args
        .essid
        .as_ref()
        .is_some_and(|s| s.is_empty() || s.len() > 32)
    {
        bail!("SSID must contain 1 to 32 bytes");
    }
    let pmk = if let Some(hex) = &args.pmk {
        let mut key = [0; 32];
        if hex.len() != 64 || hex::decode_to_slice(hex, &mut key).is_err() {
            bail!("PMK must contain exactly 64 hexadecimal characters");
        }
        Some(key)
    } else if let Some(pass) = &args.pass {
        Some(
            candidate_pmk(pass, args.essid.as_deref().unwrap_or_default().as_bytes())
                .context("invalid passphrase or hexadecimal PSK")?,
        )
    } else {
        None
    };
    let wep = if let Some(key) = &args.wep_key {
        let decoded = hex::decode(key)
            .ok()
            .filter(|v| matches!(v.len(), 5 | 13))
            .context("WEP key must contain exactly 10 or 26 hexadecimal characters")?;
        Some(decoded)
    } else {
        None
    };
    let limits = CaptureLimits {
        bytes: args.max_capture_mib * 1024 * 1024,
        packets: args.max_packets as usize,
    };
    let mut identity = super::dictionary::CaptureIdentity::new();
    let mut evidence = air_capture::evidence::Evidence::new(1024);
    let mut decoder = FrameDecoder::default();
    for record in CaptureReader::open(&args.input, limits)? {
        let record = record.context("cannot read capture")?;
        if !matches!(record.packet.dlt, 105 | 127) {
            bail!("airdecap requires raw 802.11 or Radiotap packets");
        }
        identity.update(&record);
        if pmk.is_some() && record.packet.data.len() == record.original_len as usize {
            if let Ok(Some(frame)) =
                decoder.decode(&record.packet, record.timestamp.unwrap_or_default())
            {
                evidence.push(frame)?;
            }
        }
    }
    let expected_identity = identity.finish();
    let mut keys = super::decap_keys::Keys::default();
    if let Some(pmk) = pmk {
        keys = super::decap_keys::Keys::collect(
            &evidence.frames,
            &pmk,
            args.essid.as_deref().unwrap_or_default().as_bytes(),
            args.bssid,
            args.pmk.is_some() || args.pass.as_ref().is_some_and(|p| p.len() == 64),
        )?;
    }
    drop(evidence);
    drop(decoder);
    let path = args.output.unwrap_or_else(|| {
        let mut name = args.input.file_stem().unwrap_or_default().to_os_string();
        name.push("-dec.cap");
        args.input.with_file_name(name)
    });
    let mut writer = super::capture_output::PrivatePcap::create(
        &path,
        if args.keep_wireless { 105 } else { 1 },
    )?;
    let mut identity = super::dictionary::CaptureIdentity::new();
    let (mut decrypted, mut rejected, mut skipped, mut missing_times) = (0u64, 0u64, 0u64, 0u64);
    let mut assembler = air_frames::reassembly::Reassembler::default();
    for record in CaptureReader::open(&args.input, limits)? {
        let record = record.context("cannot read capture")?;
        identity.update(&record);
        if record.packet.data.len() != record.original_len as usize {
            skipped += 1;
            continue;
        }
        let Ok(frame) = dlt_decode(record.packet.dlt, &record.packet.data) else {
            skipped += 1;
            continue;
        };
        let Ok(length) = wire_header_len(&frame) else {
            skipped += 1;
            continue;
        };
        if frame[0] & 0x0c != 8 {
            skipped += 1;
            continue;
        }
        let bssid = match frame[1] & 3 {
            1 => &frame[4..10],
            2 => &frame[10..16],
            _ => &frame[16..22],
        };
        if args.bssid.is_some_and(|b| {
            if frame[1] & 3 == 3 {
                frame[4..10] != b && frame[10..16] != b
            } else {
                bssid != b
            }
        }) {
            skipped += 1;
            continue;
        }
        let protected = frame[1] & 0x40 != 0;
        let mut michael = None;
        let mut security = air_frames::reassembly::Security::clear();
        let mut pn = None;
        let payload = if !protected {
            frame[length..].to_vec()
        } else if let Some(secret) = &wep {
            let Some(header) = frame.get(length..length + 4).filter(|h| h[3] & 0x3f == 0) else {
                rejected += 1;
                continue;
            };
            let Some(plain) = decrypt_wep(
                secret,
                header[..3].try_into().unwrap(),
                &frame[length + 4..],
            ) else {
                rejected += 1;
                continue;
            };
            security = air_frames::reassembly::Security {
                key: air_core::key_fingerprint(secret),
                protected: true,
                key_id: header[3] >> 6,
            };
            plain
        } else {
            let Some(plain) = keys.decrypt(&frame, length) else {
                rejected += 1;
                continue;
            };
            michael = plain.michael;
            security = plain.security;
            pn = plain.pn;
            plain.body
        };
        let Some(complete) = assembler.push_timed(
            &frame,
            payload,
            security,
            pn,
            record.timestamp.unwrap_or_default(),
            record.timestamp,
        ) else {
            continue;
        };
        let frame = complete.frame;
        let length = wire_header_len(&frame).context("invalid reassembled header")?;
        let mut payload = frame[length..].to_vec();
        if let Some(mic) = michael {
            let (destination, source) =
                air_frames::data_addresses(&frame).context("invalid data addresses")?;
            let priority = air_frames::qos_tid(&frame).context("invalid QoS header")?;
            let Some(plain) =
                air_core::tkip::verify_msdu(&mic, &destination, &source, priority, payload)
            else {
                rejected += 1;
                continue;
            };
            payload = plain;
        }
        if payload.starts_with(&LLC_EAPOL) {
            skipped += 1;
            continue;
        }
        let output = if args.keep_wireless {
            let mut out = frame[..length].to_vec();
            out[1] &= !0x40;
            out.extend_from_slice(&payload);
            out
        } else {
            let Some(out) = ethernet(&frame, &payload) else {
                skipped += 1;
                continue;
            };
            out
        };
        if protected {
            decrypted += 1;
        }
        if !complete.timestamp_known {
            missing_times += 1;
        }
        let time = complete.time;
        if time.as_secs() > u32::MAX as u64 {
            bail!("timestamp cannot be represented in classic PCAP");
        }
        writer.write(time, &output)?;
    }
    if identity.finish() != expected_identity {
        bail!("capture changed between key collection and decryption; output removed");
    }
    if writer.count == 0 {
        bail!("no data frames decoded; rejected protected frames: {rejected}; skipped: {skipped}; GTK installed={} rejected={}",keys.gtk_installed,keys.gtk_rejected);
    }
    let count = writer.finish()?;
    println!("Decoded {count} data frames; decrypted={decrypted} rejected-protected={rejected} skipped={skipped} missing-timestamps={missing_times} reassembled={} fragments-dropped={} fragments-pending={} gtk-installed={} gtk-rejected={}\nOutput: {}",assembler.stats.completed,assembler.stats.dropped,assembler.pending(),keys.gtk_installed,keys.gtk_rejected,path.display());
    Ok(())
}
