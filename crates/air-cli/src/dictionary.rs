use air_crack::{engine::TargetSet, wordlist::Wordlist};
use anyhow::{bail, Context};
use clap::Args;
use serde::{Deserialize, Serialize};
use sha1::{Digest, Sha1};
use std::fs::{File, OpenOptions};
use std::io::{BufReader, Read, Write};
use std::path::{Path, PathBuf};
use std::sync::{
    atomic::{AtomicBool, Ordering},
    Arc,
};
use std::time::{Duration, Instant};

#[derive(Args, Debug)]
pub struct Options {
    /// Print completed dictionary lines, rate and elapsed time to stderr
    #[arg(long)]
    pub(crate) progress: bool,
    /// New private JSON snapshot with per-network results, including found candidates
    #[arg(long)]
    pub(crate) results_json: Option<PathBuf>,
    /// Create a new private checkpoint; updated after each completed batch
    #[arg(long, conflicts_with = "resume")]
    pub(crate) session: Option<PathBuf>,
    /// Resume a checkpoint with the same capture, dictionary, SSID and BSSID
    #[arg(long)]
    pub(crate) resume: Option<PathBuf>,
    /// Stop after this many additional dictionary lines (checkpoint retained)
    #[arg(long, value_parser = clap::value_parser!(u64).range(1..))]
    pub(crate) max_candidates: Option<u64>,
    /// Explicit private PMK cache file; contains sensitive key material
    #[arg(long)]
    pub(crate) pmk_cache: Option<PathBuf>,
    /// Maximum cache size in MiB (default 64); existing capacity is retained
    #[arg(long, requires = "pmk_cache", value_parser = clap::value_parser!(u32).range(1..=1024))]
    pub(crate) pmk_cache_mib: Option<u32>,
    /// Rayon worker count; otherwise uses the existing Rayon/environment default
    #[arg(long, value_parser = clap::value_parser!(u16).range(1..=256))]
    pub(crate) threads: Option<u16>,
}
impl Options {
    pub fn validate(&self, wordlist: Option<&Path>) -> anyhow::Result<()> {
        if wordlist.is_none()
            && (self.progress
                || self.session.is_some()
                || self.resume.is_some()
                || self.max_candidates.is_some()
                || self.pmk_cache.is_some()
                || self.threads.is_some()
                || self.results_json.is_some())
        {
            bail!("dictionary options require --wordlist");
        }
        if wordlist == Some(Path::new("-")) && (self.session.is_some() || self.resume.is_some()) {
            bail!("stdin cannot be checkpointed or resumed; use a regular dictionary file");
        }
        Ok(())
    }
}

#[derive(Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
struct Identity {
    capture_sha1: String,
    dictionary_sha1: String,
    ssid: String,
    bssid: [u8; 6],
}
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Checkpoint {
    version: u32,
    identity: Identity,
    completed_lines: u64,
    exhausted: bool,
}

pub(crate) fn private_new(path: &Path) -> std::io::Result<File> {
    let mut options = OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    options.open(path)
}
/// Incremental fingerprint of all resolved records, preserving the record fingerprint format.
pub struct CaptureIdentity(Sha1);
impl CaptureIdentity {
    pub fn new() -> Self {
        let mut digest = Sha1::new();
        digest.update(b"aircrack-rs record snapshot v2");
        Self(digest)
    }
    pub fn update(&mut self, record: &air_capture::PacketRecord) {
        let digest = &mut self.0;
        digest.update(record.original_len.to_le_bytes());
        digest.update([u8::from(record.timestamp.is_some())]);
        let time = record.timestamp.unwrap_or_default();
        digest.update(time.as_secs().to_le_bytes());
        digest.update(time.subsec_nanos().to_le_bytes());
        let packet = &record.packet;
        digest.update(packet.dlt.to_le_bytes());
        digest.update((packet.data.len() as u64).to_le_bytes());
        digest.update(&packet.data);
    }
    pub fn finish(self) -> String {
        hex::encode(self.0.finalize())
    }
}

pub(crate) fn hash(file: &mut File) -> anyhow::Result<String> {
    let mut digest = Sha1::new();
    let mut buffer = [0; 65536];
    loop {
        let n = file.read(&mut buffer)?;
        if n == 0 {
            break;
        }
        digest.update(&buffer[..n]);
    }
    Ok(hex::encode(digest.finalize()))
}
struct Session {
    path: PathBuf,
    lock: PathBuf,
    state: Checkpoint,
}
impl Drop for Session {
    fn drop(&mut self) {
        let _ = std::fs::remove_file(&self.lock);
    }
}
impl Session {
    fn open(path: &Path, resume: bool, identity: Identity) -> anyhow::Result<Self> {
        let mut lock_name = path.as_os_str().to_os_string();
        lock_name.push(".lock");
        let lock = PathBuf::from(lock_name);
        let mut lock_file = private_new(&lock).context("session is locked (after a crashed process, remove its .lock only when it is no longer running)")?;
        if let Err(error) = writeln!(lock_file, "{}", std::process::id()) {
            let _ = std::fs::remove_file(&lock);
            return Err(error.into());
        }
        let result = (|| {
            if resume {
                let meta = std::fs::symlink_metadata(path)?;
                if !meta.is_file() || meta.len() > 16384 {
                    bail!("invalid checkpoint file");
                }
                let mut bytes = Vec::new();
                File::open(path)?.take(16385).read_to_end(&mut bytes)?;
                if bytes.len() > 16384 {
                    bail!("checkpoint size limit exceeded");
                }
                let state: Checkpoint =
                    serde_json::from_slice(&bytes).context("invalid checkpoint")?;
                if state.version != 5 {
                    bail!("unsupported checkpoint version; start a new session");
                }
                if state.identity != identity {
                    bail!("checkpoint input mismatch: capture, dictionary or network changed");
                }
                Ok(state)
            } else {
                let state = Checkpoint {
                    version: 5,
                    identity,
                    completed_lines: 0,
                    exhausted: false,
                };
                let mut file =
                    private_new(path).context("checkpoint already exists or cannot be created")?;
                file.write_all(&serde_json::to_vec(&state)?)?;
                file.sync_all()?;
                Ok(state)
            }
        })();
        match result {
            Ok(state) => Ok(Self {
                path: path.to_owned(),
                lock,
                state,
            }),
            Err(error) => {
                let _ = std::fs::remove_file(lock);
                Err(error)
            }
        }
    }
    fn save(&mut self, completed: u64, exhausted: bool) -> anyhow::Result<()> {
        self.state.completed_lines = completed;
        self.state.exhausted = exhausted;
        let mut name = self.path.as_os_str().to_os_string();
        name.push(format!(".tmp-{}", std::process::id()));
        let temp = PathBuf::from(name);
        let mut file = private_new(&temp).context("cannot create checkpoint temporary file")?;
        let result = (|| {
            file.write_all(&serde_json::to_vec(&self.state)?)?;
            file.sync_all()?;
            std::fs::rename(&temp, &self.path)?;
            Ok(())
        })();
        if result.is_err() {
            let _ = std::fs::remove_file(&temp);
        }
        result
    }
}
pub(crate) struct Stop {
    pub(crate) flag: Arc<AtomicBool>,
    #[cfg(unix)]
    ids: Vec<signal_hook::SigId>,
}
impl Stop {
    pub(crate) fn new(#[allow(unused_variables)] enabled: bool) -> anyhow::Result<Self> {
        let flag = Arc::new(AtomicBool::new(false));
        #[cfg(unix)]
        {
            let ids = if enabled {
                vec![
                    signal_hook::flag::register(signal_hook::consts::SIGINT, flag.clone())?,
                    signal_hook::flag::register(signal_hook::consts::SIGTERM, flag.clone())?,
                ]
            } else {
                Vec::new()
            };
            Ok(Self { flag, ids })
        }
        #[cfg(not(unix))]
        Ok(Self { flag })
    }
}
impl Drop for Stop {
    fn drop(&mut self) {
        #[cfg(unix)]
        for id in &self.ids {
            signal_hook::low_level::unregister(*id);
        }
    }
}

pub fn run(
    targets: &TargetSet,
    capture_identity: String,
    path: &Path,
    ssid: &[u8],
    bssid: [u8; 6],
    options: Options,
) -> anyhow::Result<()> {
    if targets.requires_exported_pmk() {
        eprintln!("SAE/FT-SAE: only exported 64-hex PMK candidates can be verified; passive captures do not support password guessing");
    }
    let stdin = path == Path::new("-");
    let mut session = None;
    let mut words = if stdin {
        Wordlist::from_reader(BufReader::new(std::io::stdin()))
    } else {
        let mut file = File::open(path).context("cannot open wordlist")?;
        if !file.metadata()?.is_file() {
            bail!("wordlist must be a regular file; use --wordlist - for stdin");
        }
        if let Some(session_path) = options.session.as_ref().or(options.resume.as_ref()) {
            use std::io::{Seek, SeekFrom};
            let identity = Identity {
                capture_sha1: capture_identity,
                dictionary_sha1: hash(&mut file)?,
                ssid: hex::encode(ssid),
                bssid,
            };
            file.seek(SeekFrom::Start(0))?;
            session = Some(Session::open(
                session_path,
                options.resume.is_some(),
                identity,
            )?);
        }
        Wordlist::from_reader(BufReader::new(file))
    };
    let mut completed = session.as_ref().map_or(0, |s| s.state.completed_lines);
    for _ in 0..completed {
        words
            .next()
            .context("checkpoint position exceeds dictionary length")??;
    }
    let stop = Stop::new(!stdin)?;
    let mut cache = options
        .pmk_cache
        .as_ref()
        .map(|path| air_crack::cache::Cache::open(path, options.pmk_cache_mib.unwrap_or(64)))
        .transpose()
        .context("cannot open PMK cache")?;
    let pool = options
        .threads
        .map(|threads| {
            rayon::ThreadPoolBuilder::new()
                .num_threads(usize::from(threads))
                .build()
        })
        .transpose()
        .context("cannot create dictionary worker pool")?;
    let started = Instant::now();
    let mut last_report = Instant::now();
    let initial = completed;
    let report = |completed: u64| {
        let seconds = started.elapsed().as_secs_f64();
        eprintln!(
            "[*] progress: {completed} dictionary lines completed; {:.1} lines/s; elapsed {:.1}s",
            (completed - initial) as f64 / seconds.max(0.001),
            seconds
        );
    };
    loop {
        let used = completed - initial;
        if stop.flag.load(Ordering::Relaxed)
            || options.max_candidates.is_some_and(|max| used >= max)
        {
            if options.progress {
                report(completed);
            }
            report_cache(cache.as_ref());
            bail!("verification paused after {completed} dictionary lines; last completed batch checkpointed when --session/--resume is used");
        }
        let size = options
            .max_candidates
            .map_or(256, |max| (max - used).min(256) as usize);
        let batch = words
            .by_ref()
            .take(size)
            .collect::<std::io::Result<Vec<_>>>()
            .context("wordlist: cannot read wordlist")?;
        if batch.is_empty() {
            if let Some(s) = &mut session {
                s.save(completed, true)?;
            }
            if options.progress {
                report(completed);
            }
            report_cache(cache.as_ref());
            if targets.requires_exported_pmk() {
                bail!("no supplied exported PMK matched; SAE passphrases cannot be verified from a passive capture");
            }
            bail!("password not found in wordlist");
        }
        let work = || match cache.as_mut() {
            Some(cache) => targets.crack_batch_cached(&batch, cache),
            None => Ok(targets.crack_batch(&batch)),
        };
        let found = match &pool {
            Some(pool) => pool.install(work),
            None => {
                let mut work = work;
                work()
            }
        }
        .context("PMK cache batch failed; checkpoint not advanced")?;
        if let Some((index, pass)) = found {
            // Keep the previous batch position so a resumed successful run replays
            // the matching batch. No password or candidate is saved on disk.
            if options.progress {
                report(completed + index as u64 + 1);
            }
            report_cache(cache.as_ref());
            println!("[+] found: {pass}");
            return Ok(());
        }
        completed = completed
            .checked_add(batch.len() as u64)
            .context("dictionary line counter overflow")?;
        if let Some(s) = &mut session {
            s.save(completed, false)?;
        }
        if options.progress && last_report.elapsed() >= Duration::from_secs(1) {
            report(completed);
            last_report = Instant::now();
        }
    }
}

pub(crate) fn report_cache(cache: Option<&air_crack::cache::Cache>) {
    if let Some(cache) = cache {
        let s = cache.stats;
        eprintln!(
            "[*] PMK cache: hits={} misses={} derived={} writes={} evictions={} corrupt={}",
            s.hits, s.misses, s.derived, s.writes, s.evictions, s.corrupt
        );
    }
}
