//! Reproducible synthetic CPU/cache benchmark; never consumes a real dictionary.
use air_crack::{cache::Cache, engine::TargetSet};
use air_handshake::{PmkidSession, VerificationTarget};
use anyhow::{bail, Context, Result};
use clap::Args;
use rayon::prelude::*;
use serde_json::json;
use std::hint::black_box;
use std::io::Write;
use std::path::PathBuf;
use std::time::{Instant, SystemTime, UNIX_EPOCH};
const SSID: &[u8] = b"aircrack-rs benchmark";
#[derive(Args, Debug)]
pub struct BenchArgs {
    #[arg(long,default_value="256",value_parser=clap::value_parser!(u32).range(1..=65536))]
    candidates: u32,
    #[arg(long,default_value="5",value_parser=clap::value_parser!(u16).range(1..=21))]
    samples: u16,
    #[arg(long,default_value="1",value_parser=clap::value_parser!(u16).range(1..=256))]
    threads: u16,
    /// Save a new JSON report; existing paths are never overwritten
    #[arg(long)]
    json: Option<PathBuf>,
}
struct Temp(PathBuf);
impl Drop for Temp {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}
fn temp() -> Result<Temp> {
    let stamp = SystemTime::now().duration_since(UNIX_EPOCH)?.as_nanos();
    let path = std::env::temp_dir().join(format!("air-benchmark-{}-{stamp}", std::process::id()));
    let mut builder = std::fs::DirBuilder::new();
    #[cfg(unix)]
    {
        use std::os::unix::fs::DirBuilderExt;
        builder.mode(0o700);
    }
    builder.create(&path)?;
    Ok(Temp(path))
}
fn timed<F: FnOnce()>(work: F) -> f64 {
    let start = Instant::now();
    work();
    start.elapsed().as_secs_f64()
}
fn summary(values: &[f64], n: u32) -> serde_json::Value {
    let mut sorted = values.to_vec();
    sorted.sort_by(f64::total_cmp);
    let middle = sorted.len() / 2;
    let median = if sorted.len().is_multiple_of(2) {
        (sorted[middle - 1] + sorted[middle]) / 2.0
    } else {
        sorted[middle]
    };
    json!({"seconds":values,"median_seconds":median,"candidates_per_second":n as f64/median.max(f64::MIN_POSITIVE)})
}
pub fn run(args: BenchArgs) -> Result<()> {
    let pool = rayon::ThreadPoolBuilder::new()
        .num_threads(usize::from(args.threads))
        .build()?;
    let candidates: Vec<_> = (0..args.candidates)
        .map(|n| format!("bench-candidate-{n:08}"))
        .collect();
    for candidate in candidates.iter().take(8) {
        if air_core::pmk(candidate, SSID) != air_core::pmk_reference(candidate, SSID) {
            bail!("PBKDF2 differential check failed");
        }
    }
    let ap = [2, 0, 0, 0, 0, 1];
    let sta = [2, 0, 0, 0, 0, 2];
    let root = air_core::pmk("synthetic answer outside candidate set", SSID);
    let anonce = [1; 32];
    let snonce = [2; 32];
    let mut eapol = vec![0; 99];
    eapol[..5].copy_from_slice(&[2, 3, 0, 95, 2]);
    eapol[5..7].copy_from_slice(&0x010au16.to_be_bytes());
    eapol[17..49].copy_from_slice(&snonce);
    let ptk = air_core::ptk(&root, &ap, &sta, &anonce, &snonce);
    let mic = air_core::mic(&ptk, &eapol);
    let session = air_handshake::HandshakeSession {
        bssid: ap,
        sta,
        anonce: Some(anonce),
        snonce: Some(snonce),
        eapol,
        mic: Some(mic),
        count: 2,
        nonce_source: None,
    };
    let targets = TargetSet::new(
        vec![
            VerificationTarget::Handshake(session),
            VerificationTarget::Pmkid(PmkidSession {
                bssid: ap,
                sta,
                pmkid: air_core::pmkid(&root, &ap, &sta),
            }),
        ],
        SSID.to_vec(),
    )?;
    let mut reference = Vec::new();
    let mut optimized = Vec::new();
    let mut cold = Vec::new();
    let mut warm = Vec::new();
    let mut engine = Vec::new();
    let mut cache_stats = Vec::new();
    let folder = temp()?;
    // Warm dispatched SHA-1 and worker threads before measuring. Alternate
    // baseline/optimized order across samples to reduce order/thermal bias.
    pool.install(|| {
        let out: Vec<_> = candidates
            .par_iter()
            .take(8)
            .map(|p| air_core::pmk(p, SSID))
            .collect();
        black_box(out);
    });
    for sample in 0..args.samples {
        let measure = |baseline: bool| {
            pool.install(|| {
                timed(|| {
                    let output: Vec<_> = candidates
                        .par_iter()
                        .map(|p| {
                            if baseline {
                                air_core::pmk_reference(p, SSID)
                            } else {
                                air_core::pmk(p, SSID)
                            }
                        })
                        .collect();
                    black_box(output);
                })
            })
        };
        if sample % 2 == 0 {
            reference.push(measure(true));
            optimized.push(measure(false));
        } else {
            optimized.push(measure(false));
            reference.push(measure(true));
        }
        engine.push(pool.install(|| {
            timed(|| {
                for batch in candidates.chunks(256) {
                    assert!(targets.crack_batch(batch).is_none());
                }
            })
        }));
        let path = folder.0.join(format!("{sample}.cache"));
        // Capacity covers the maximum benchmark corpus with ample headroom.
        let start = Instant::now();
        let mut cache = Cache::open(&path, 64)?;
        pool.install(|| -> Result<()> {
            for batch in candidates.chunks(256) {
                if targets.crack_batch_cached(batch, &mut cache)?.is_some() {
                    bail!("unexpected synthetic match");
                }
            }
            Ok(())
        })?;
        cold.push(start.elapsed().as_secs_f64());
        let first = cache.stats;
        drop(cache);
        // Reopen so warm measurement demonstrates persistent, cross-run reuse.
        let start = Instant::now();
        let mut cache = Cache::open(&path, 64)?;
        pool.install(|| -> Result<()> {
            for batch in candidates.chunks(256) {
                if targets.crack_batch_cached(batch, &mut cache)?.is_some() {
                    bail!("unexpected synthetic match");
                }
            }
            Ok(())
        })?;
        warm.push(start.elapsed().as_secs_f64());
        let second = cache.stats;
        cache_stats.push(json!({"cold_hits":first.hits,"cold_misses":first.misses,"cold_derived":first.derived,"warm_hits":second.hits,"warm_misses":second.misses,"warm_derived":second.derived,"evictions":first.evictions+second.evictions}));
        drop(cache);
        std::fs::remove_file(&path)?;
    }
    let reference = summary(&reference, args.candidates);
    let optimized = summary(&optimized, args.candidates);
    let report = json!({"schema_version":1,"profile":if cfg!(debug_assertions){"debug"}else{"release"},"os":std::env::consts::OS,"arch":std::env::consts::ARCH,
        "threads":args.threads,"candidates":args.candidates,"samples":args.samples,"synthetic_ssid_hex":hex::encode(SSID),
        "algorithm":"PBKDF2-HMAC-SHA1/4096/32","verification_targets":["WPA2 EAPOL","PMKID"],"reference":reference,"optimized":optimized,
        "pbkdf2_speedup":reference["median_seconds"].as_f64().unwrap()/optimized["median_seconds"].as_f64().unwrap(),
        "dictionary_no_cache":summary(&engine,args.candidates),"dictionary_cache_cold":summary(&cold,args.candidates),"dictionary_cache_warm":summary(&warm,args.candidates),"cache_samples":cache_stats,
        "scope":"synthetic CPU benchmark; disk lookup and MIC verification included in cache modes; warm cache is not PBKDF2 throughput; no upstream speed parity claim"});
    if let Some(path) = args.json {
        let mut options = std::fs::OpenOptions::new();
        options.write(true).create_new(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            options.mode(0o600);
        }
        let mut file = options
            .open(&path)
            .context("cannot create benchmark JSON; existing files are never overwritten")?;
        file.write_all(serde_json::to_string_pretty(&report)?.as_bytes())?;
        file.write_all(b"\n")?;
        file.sync_all()?;
    }
    println!(
        "Synthetic benchmark: {} candidates, {} samples, {} workers ({})",
        args.candidates,
        args.samples,
        args.threads,
        report["profile"].as_str().unwrap()
    );
    for name in [
        "reference",
        "optimized",
        "dictionary_no_cache",
        "dictionary_cache_cold",
        "dictionary_cache_warm",
    ] {
        println!(
            "{name}: {:.1} candidates/s (median {:.6}s)",
            report[name]["candidates_per_second"].as_f64().unwrap(),
            report[name]["median_seconds"].as_f64().unwrap()
        );
    }
    println!(
        "PBKDF2 speedup over generic baseline: {:.3}x",
        report["pbkdf2_speedup"].as_f64().unwrap()
    );
    Ok(())
}
