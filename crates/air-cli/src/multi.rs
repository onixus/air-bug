//! Ordered dictionaries, per-BSSID matches, and a shared credential-free checkpoint.
use super::dictionary::{hash, private_new, report_cache, Options, Stop};
use air_crack::{networks::Networks, wordlist::Wordlist};
use anyhow::{bail, Context, Result};
use serde::{Deserialize, Serialize};
use std::{
    fs::File,
    io::{BufReader, Read, Seek, SeekFrom, Write},
    path::{Path, PathBuf},
    sync::atomic::Ordering,
    time::{Duration, Instant},
};
pub fn mac(ap: &[u8; 6]) -> String {
    ap.iter()
        .map(|b| format!("{b:02x}"))
        .collect::<Vec<_>>()
        .join(":")
}
#[derive(Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
struct NetworkId {
    bssid: [u8; 6],
    ssid_hex: String,
}
#[derive(Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
struct Identity {
    captures: Vec<String>,
    dictionaries: Vec<String>,
    networks: Vec<NetworkId>,
}
#[derive(Clone, Copy, Default, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
struct Position {
    dictionary: usize,
    line: u64,
}
#[derive(Clone, Copy, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Found {
    global_line: u64,
    position: Position,
}
#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct State {
    version: u32,
    identity: Identity,
    completed_lines: u64,
    position: Position,
    exhausted: bool,
    found: Vec<Option<Found>>,
}
struct Session {
    path: PathBuf,
    lock: PathBuf,
    state: State,
}
impl Drop for Session {
    fn drop(&mut self) {
        let _ = std::fs::remove_file(&self.lock);
    }
}
impl Session {
    fn open(path: &Path, resume: bool, initial: State) -> Result<Self> {
        let mut name = path.as_os_str().to_os_string();
        name.push(".lock");
        let lock = PathBuf::from(name);
        let mut file=private_new(&lock).context("session is locked (after a crashed process remove its .lock only when it is no longer running)")?;
        let result = (|| {
            writeln!(file, "{}", std::process::id())?;
            let state = if resume {
                let meta = std::fs::symlink_metadata(path)?;
                if !meta.is_file() || meta.len() > 262144 {
                    bail!("invalid multi-network checkpoint file");
                }
                let mut bytes = Vec::new();
                File::open(path)?.take(262145).read_to_end(&mut bytes)?;
                if bytes.len() > 262144 {
                    bail!("checkpoint size limit exceeded");
                }
                let state: State = serde_json::from_slice(&bytes).context(
                    "invalid multi-network checkpoint; use a new session when upgrading from v5",
                )?;
                if state.version != 6 {
                    bail!("unsupported multi-network checkpoint version; start a new session");
                }
                if state.identity != initial.identity {
                    bail!("checkpoint input mismatch: capture order/content, dictionary order/content or networks changed");
                }
                if state.found.len() != initial.found.len()
                    || state.position.dictionary > initial.identity.dictionaries.len()
                {
                    bail!("invalid checkpoint network/cursor state");
                }
                for found in state.found.iter().flatten() {
                    if found.global_line == 0
                        || found.global_line > state.completed_lines
                        || found.position.dictionary >= initial.identity.dictionaries.len()
                        || found.position.line == 0
                    {
                        bail!("invalid checkpoint match position");
                    }
                }
                state
            } else {
                let mut file =
                    private_new(path).context("checkpoint already exists or cannot be created")?;
                file.write_all(&serde_json::to_vec(&initial)?)?;
                file.sync_all()?;
                initial
            };
            Ok(state)
        })();
        match result {
            Ok(state) => Ok(Self {
                path: path.into(),
                lock,
                state,
            }),
            Err(error) => {
                let _ = std::fs::remove_file(lock);
                Err(error)
            }
        }
    }
    fn save(&mut self, state: &State) -> Result<()> {
        let mut name = self.path.as_os_str().to_os_string();
        name.push(format!(".tmp-{}", std::process::id()));
        let temp = PathBuf::from(name);
        let mut file = private_new(&temp).context("cannot create checkpoint temporary file")?;
        let result = (|| {
            file.write_all(&serde_json::to_vec(state)?)?;
            file.sync_all()?;
            drop(file);
            std::fs::rename(&temp, &self.path)?;
            Ok(())
        })();
        if result.is_err() {
            let _ = std::fs::remove_file(&temp);
        } else {
            self.state = state.clone();
        }
        result
    }
}
struct Dictionaries {
    files: Vec<Option<File>>,
    active: Option<Wordlist>,
    index: usize,
    line: u64,
    stdin: bool,
}
impl Dictionaries {
    fn new(files: Vec<Option<File>>, stdin: bool) -> Self {
        Self {
            files,
            active: None,
            index: 0,
            line: 0,
            stdin,
        }
    }
    fn position(&self) -> Position {
        Position {
            dictionary: self.index,
            line: self.line,
        }
    }
    fn next(&mut self) -> Result<Option<String>> {
        loop {
            if self.index >= self.files.len() {
                return Ok(None);
            }
            if self.active.is_none() {
                self.active = Some(if self.stdin {
                    Wordlist::from_reader(BufReader::new(std::io::stdin()))
                } else {
                    Wordlist::from_reader(BufReader::new(self.files[self.index].take().unwrap()))
                });
            }
            match self.active.as_mut().unwrap().next() {
                Some(word) => {
                    let word = word.context("wordlist: cannot read wordlist")?;
                    self.line = self
                        .line
                        .checked_add(1)
                        .context("dictionary line counter overflow")?;
                    return Ok(Some(word));
                }
                None => {
                    self.active = None;
                    self.index += 1;
                    self.line = 0;
                }
            }
        }
    }
}
struct Results {
    path: PathBuf,
    file: Option<File>,
    complete: bool,
}
impl Results {
    fn reserve(path: &Path) -> Result<Self> {
        Ok(Self {
            path: path.into(),
            file: Some(
                private_new(path)
                    .context("cannot create results JSON; existing paths are never overwritten")?,
            ),
            complete: false,
        })
    }
    fn finish(
        &mut self,
        networks: &Networks,
        paths: &[PathBuf],
        state: &State,
        candidates: &[Option<String>],
        status: &str,
    ) -> Result<()> {
        let rows:Vec<_>=networks.networks().iter().enumerate().map(|(index,net)|{
            let found=state.found[index];
            serde_json::json!({"bssid":mac(&net.bssid),"ssid_hex":hex::encode(&net.ssid),"status":if found.is_some(){"found"}else if state.exhausted{"not_found"}else{"pending"},
                "requires_exported_pmk":net.targets.requires_exported_pmk(),"candidate":candidates[index],
                "found_at":found.map(|f|serde_json::json!({"global_line":f.global_line,"dictionary_index":f.position.dictionary,"dictionary":paths[f.position.dictionary].to_string_lossy(),"line":f.position.line}))})
        }).collect();
        let value = serde_json::json!({"schema_version":1,"status":status,"completed_lines":state.completed_lines,"position":state.position,"networks":rows});
        let mut file = self.file.take().unwrap();
        file.write_all(&serde_json::to_vec_pretty(&value)?)?;
        file.write_all(b"\n")?;
        file.sync_all()?;
        drop(file);
        self.complete = true;
        Ok(())
    }
}
impl Drop for Results {
    fn drop(&mut self) {
        drop(self.file.take());
        if !self.complete {
            let _ = std::fs::remove_file(&self.path);
        }
    }
}
fn print_found(networks: &Networks, index: usize, candidate: &str) {
    println!(
        "[+] found: {candidate} [bssid={} ssid_hex={}]",
        mac(&networks.networks()[index].bssid),
        hex::encode(&networks.networks()[index].ssid)
    );
}
fn finish(
    networks: &Networks,
    paths: &[PathBuf],
    state: &State,
    candidates: &[Option<String>],
    status: &str,
    results: &mut Option<Results>,
) -> Result<()> {
    if let Some(results) = results {
        results.finish(networks, paths, state, candidates, status)?;
    }
    for (index, net) in networks.networks().iter().enumerate() {
        println!(
            "[*] result: bssid={} ssid_hex={} status={}",
            mac(&net.bssid),
            hex::encode(&net.ssid),
            if state.found[index].is_some() {
                "found"
            } else if state.exhausted {
                "not_found"
            } else {
                "pending"
            }
        );
    }
    Ok(())
}
pub fn run(
    networks: &Networks,
    captures: Vec<String>,
    paths: &[PathBuf],
    options: Options,
) -> Result<()> {
    let stdin = paths[0] == Path::new("-");
    let checkpoint = options.session.as_ref().or(options.resume.as_ref());
    let mut files = Vec::new();
    let mut hashes = Vec::new();
    for path in paths {
        if stdin {
            files.push(None);
            continue;
        }
        if !std::fs::metadata(path)
            .context("cannot open wordlist")?
            .is_file()
        {
            bail!("wordlist must be a regular file; use --wordlist - for stdin");
        }
        let mut file = File::open(path).context("cannot open wordlist")?;
        if !file.metadata()?.is_file() {
            bail!("wordlist must be a regular file; use --wordlist - for stdin");
        }
        if checkpoint.is_some() {
            hashes.push(hash(&mut file)?);
            file.seek(SeekFrom::Start(0))?;
        }
        files.push(Some(file));
    }
    let identity = Identity {
        captures,
        dictionaries: hashes,
        networks: networks
            .networks()
            .iter()
            .map(|net| NetworkId {
                bssid: net.bssid,
                ssid_hex: hex::encode(&net.ssid),
            })
            .collect(),
    };
    let initial = State {
        version: 6,
        identity,
        completed_lines: 0,
        position: Position::default(),
        exhausted: false,
        found: vec![None; networks.networks().len()],
    };
    let mut results = options
        .results_json
        .as_deref()
        .map(Results::reserve)
        .transpose()?;
    let mut session = checkpoint
        .map(|path| Session::open(path, options.resume.is_some(), initial.clone()))
        .transpose()?;
    let mut state = session.as_ref().map_or(initial, |s| s.state.clone());
    let mut words = Dictionaries::new(files, stdin);
    let stop = Stop::new(!stdin)?;
    let mut cache = options
        .pmk_cache
        .as_ref()
        .map(|path| air_crack::cache::Cache::open(path, options.pmk_cache_mib.unwrap_or(64)))
        .transpose()
        .context("cannot open PMK cache")?;
    let pool = options
        .threads
        .map(|n| {
            rayon::ThreadPoolBuilder::new()
                .num_threads(usize::from(n))
                .build()
        })
        .transpose()?;
    let mut candidates = vec![None; networks.networks().len()];
    // Replay only source positions of stored matches. No credentials live in the
    // checkpoint; same-SSID matches at a position share one derivation again.
    for number in 1..=state.completed_lines {
        if stop.flag.load(Ordering::Relaxed) {
            bail!("verification paused while restoring checkpoint; checkpoint unchanged");
        }
        let word = words
            .next()?
            .context("checkpoint position exceeds dictionary length")?;
        let due: Vec<_> = state
            .found
            .iter()
            .map(|found| found.is_some_and(|f| f.global_line == number))
            .collect();
        if due.iter().any(|&v| v) {
            let solved: Vec<_> = due.iter().map(|&v| !v).collect();
            let work =
                || networks.crack_batch(std::slice::from_ref(&word), &solved, cache.as_mut());
            let verified = match &pool {
                Some(pool) => pool.install(work),
                None => {
                    let mut work = work;
                    work()
                }
            }?;
            for index in 0..due.len() {
                if due[index] {
                    if verified[index] != Some(0)
                        || state.found[index].unwrap().position != words.position()
                    {
                        bail!(
                            "checkpoint stored match cannot be verified at its dictionary position"
                        );
                    }
                    candidates[index] = Some(word.clone());
                }
            }
        }
    }
    if state.exhausted && words.next()?.is_some() {
        bail!("checkpoint exhausted state does not match dictionaries");
    }
    if state.position != words.position() {
        bail!("checkpoint dictionary cursor mismatch");
    }
    for (index, candidate) in candidates.iter().enumerate() {
        if let Some(candidate) = candidate {
            print_found(networks, index, candidate);
        }
    }
    if networks
        .networks()
        .iter()
        .any(|n| n.targets.requires_exported_pmk())
    {
        eprintln!("SAE/FT-SAE targets accept only exported 64-hex PMK candidates; passive captures do not support password guessing");
    }
    let start = Instant::now();
    let initial = state.completed_lines;
    let mut last_report = Instant::now();
    let report = |state: &State| {
        let elapsed = start.elapsed().as_secs_f64();
        eprintln!("[*] progress: {} dictionary lines completed; {:.1} lines/s; elapsed {:.1}s; matched {}/{} networks",state.completed_lines,(state.completed_lines-initial)as f64/elapsed.max(0.001),elapsed,state.found.iter().flatten().count(),state.found.len());
    };
    loop {
        if state.found.iter().all(Option::is_some) {
            if options.progress {
                report(&state);
            }
            report_cache(cache.as_ref());
            finish(
                networks,
                paths,
                &state,
                &candidates,
                "complete",
                &mut results,
            )?;
            return Ok(());
        }
        if state.exhausted {
            if options.progress {
                report(&state);
            }
            report_cache(cache.as_ref());
            finish(
                networks,
                paths,
                &state,
                &candidates,
                "exhausted",
                &mut results,
            )?;
            bail!(
                "password not found in wordlists for all networks; matched {}/{}",
                state.found.iter().flatten().count(),
                state.found.len()
            );
        }
        let used = state.completed_lines - initial;
        if stop.flag.load(Ordering::Relaxed)
            || options.max_candidates.is_some_and(|max| used >= max)
        {
            if options.progress {
                report(&state);
            }
            report_cache(cache.as_ref());
            finish(networks, paths, &state, &candidates, "paused", &mut results)?;
            bail!("verification paused after {} dictionary lines; completed batch and network matches checkpointed when --session/--resume is used",state.completed_lines);
        }
        let size = options
            .max_candidates
            .map_or(256, |max| (max - used).min(256) as usize);
        let mut batch = Vec::new();
        let mut positions = Vec::new();
        for _ in 0..size {
            match words.next()? {
                Some(word) => {
                    batch.push(word);
                    positions.push(words.position());
                }
                None => break,
            }
        }
        if batch.is_empty() {
            state.exhausted = true;
            state.position = words.position();
            if let Some(session) = &mut session {
                session.save(&state)?;
            }
            continue;
        }
        let solved: Vec<_> = state.found.iter().map(Option::is_some).collect();
        let work = || networks.crack_batch(&batch, &solved, cache.as_mut());
        let found = match &pool {
            Some(pool) => pool.install(work),
            None => {
                let mut work = work;
                work()
            }
        }
        .context("PMK cache/multi-network batch failed; checkpoint not advanced")?;
        let batch_end = state
            .completed_lines
            .checked_add(batch.len() as u64)
            .context("dictionary line counter overflow")?;
        for (index, first) in found.iter().enumerate() {
            if let Some(first) = first {
                state.found[index] = Some(Found {
                    global_line: state.completed_lines + *first as u64 + 1,
                    position: positions[*first],
                });
                candidates[index] = Some(batch[*first].clone());
            }
        }
        state.completed_lines = batch_end;
        state.position = *positions.last().unwrap();
        if let Some(session) = &mut session {
            session.save(&state)?;
        }
        for (index, first) in found.iter().enumerate() {
            if first.is_some() {
                print_found(networks, index, candidates[index].as_ref().unwrap());
            }
        }
        if options.progress && last_report.elapsed() >= Duration::from_secs(1) {
            report(&state);
            last_report = Instant::now();
        }
    }
}
