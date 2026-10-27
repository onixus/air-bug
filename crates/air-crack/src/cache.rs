//! Opt-in, bounded, private PMK table. Four-way set associative buckets give a
//! fixed disk budget and bounded I/O; no index proportional to file size in RAM.
//! Cache contents are trusted local key material, never an interchange format.
use fs2::FileExt;
use sha2::{Digest, Sha256};
use std::fs::{File, OpenOptions};
use std::io::{self, Read, Seek, SeekFrom, Write};
use std::path::Path;
const HEADER: usize = 64;
const SLOT: usize = 128;
const WAYS: usize = 4;
const BUCKET: usize = SLOT * WAYS;
const MAGIC: &[u8; 16] = b"AIR-PMK-CACHE-v1";
#[derive(Default, Clone, Copy, Debug)]
pub struct Stats {
    pub hits: u64,
    pub misses: u64,
    pub derived: u64,
    pub writes: u64,
    pub evictions: u64,
    pub corrupt: u64,
}
pub struct Cache {
    file: File,
    buckets: u32,
    dirty: bool,
    pub stats: Stats,
}
fn invalid(message: &str) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, message)
}
fn header(buckets: u32) -> [u8; HEADER] {
    let mut out = [0; HEADER];
    out[..16].copy_from_slice(MAGIC);
    for (chunk, value) in
        out[16..32]
            .as_chunks_mut::<4>()
            .0
            .iter_mut()
            .zip([1, buckets, SLOT as u32, 4096])
    {
        chunk.copy_from_slice(&value.to_le_bytes());
    }
    let digest = Sha256::digest(&out[..32]);
    out[32..].copy_from_slice(&digest);
    out
}
fn checksum(key: &[u8], pmk: &[u8]) -> [u8; 32] {
    let mut hash = Sha256::new();
    hash.update(b"WPA PMK cache entry v1");
    hash.update(key);
    hash.update(pmk);
    hash.finalize().into()
}
pub fn key(ssid: &[u8], passphrase: &str) -> [u8; 32] {
    let mut hash = Sha256::new();
    hash.update(b"PBKDF2-HMAC-SHA1/4096/32 v1");
    hash.update((ssid.len() as u64).to_le_bytes());
    hash.update(ssid);
    hash.update((passphrase.len() as u64).to_le_bytes());
    hash.update(passphrase.as_bytes());
    hash.finalize().into()
}
fn valid(slot: &[u8]) -> bool {
    slot[96..].iter().all(|&byte| byte == 0) && slot[64..96] == checksum(&slot[..32], &slot[32..64])
}
impl Cache {
    /// `mib` is the maximum file size, including the versioned header. Existing
    /// files retain their capacity; a lower opening budget rejects larger files.
    pub fn open(path: &Path, mib: u32) -> io::Result<Self> {
        if !(1..=1024).contains(&mib) {
            return Err(invalid("PMK cache budget must be 1..1024 MiB"));
        }
        let budget = u64::from(mib) * 1024 * 1024;
        let mut options = OpenOptions::new();
        options.read(true).write(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            options
                .mode(0o600)
                .custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK);
        }
        let (mut file, created) = match options.create_new(true).open(path) {
            Ok(file) => (file, true),
            Err(error) if error.kind() == io::ErrorKind::AlreadyExists => {
                options.create_new(false);
                (options.open(path)?, false)
            }
            Err(error) => return Err(error),
        };
        if !file.metadata()?.is_file() {
            return Err(invalid("PMK cache must be a regular file"));
        }
        #[cfg(unix)]
        {
            use std::os::unix::fs::MetadataExt;
            let meta = file.metadata()?;
            // SAFETY: geteuid takes no pointers or arguments.
            if meta.mode() & 0o077 != 0 || meta.uid() != unsafe { libc::geteuid() } {
                return Err(io::Error::new(
                    io::ErrorKind::PermissionDenied,
                    "PMK cache must be owned by this user with private permissions (0600)",
                ));
            }
        }
        file.try_lock_exclusive().map_err(|_| {
            io::Error::new(
                io::ErrorKind::WouldBlock,
                "PMK cache is locked by another process",
            )
        })?;
        let buckets = if created {
            let buckets = ((budget - HEADER as u64) / BUCKET as u64) as u32;
            // A sparse fixed-size table; unwritten slots are empty zero bytes.
            file.set_len(HEADER as u64 + u64::from(buckets) * BUCKET as u64)?;
            file.write_all(&header(buckets))?;
            file.sync_all()?;
            buckets
        } else {
            let len = file.metadata()?.len();
            if len > budget || len < HEADER as u64 {
                return Err(invalid("PMK cache length exceeds budget or is invalid"));
            }
            let mut bytes = [0; HEADER];
            file.read_exact(&mut bytes)?;
            let buckets = u32::from_le_bytes(bytes[20..24].try_into().unwrap());
            if buckets == 0
                || bytes != header(buckets)
                || len != HEADER as u64 + u64::from(buckets) * BUCKET as u64
            {
                return Err(invalid("unsupported or corrupt PMK cache header/length"));
            }
            buckets
        };
        Ok(Self {
            file,
            buckets,
            dirty: false,
            stats: Stats::default(),
        })
    }
    fn bucket(&mut self, key: &[u8; 32]) -> io::Result<([u8; BUCKET], u64)> {
        let index = u64::from_le_bytes(key[..8].try_into().unwrap()) % u64::from(self.buckets);
        let offset = HEADER as u64 + index * BUCKET as u64;
        let mut bytes = [0; BUCKET];
        self.file.seek(SeekFrom::Start(offset))?;
        self.file.read_exact(&mut bytes)?;
        Ok((bytes, offset))
    }
    pub fn get(&mut self, key: &[u8; 32]) -> io::Result<Option<[u8; 32]>> {
        let (bucket, _) = self.bucket(key)?;
        for slot in bucket.as_chunks::<SLOT>().0.iter() {
            if slot.iter().all(|&byte| byte == 0) {
                continue;
            }
            if &slot[..32] == key {
                if valid(slot) {
                    self.stats.hits += 1;
                    return Ok(Some(slot[32..64].try_into().unwrap()));
                }
                self.stats.corrupt += 1;
            }
        }
        self.stats.misses += 1;
        Ok(None)
    }
    pub fn put(&mut self, key: &[u8; 32], pmk: &[u8; 32]) -> io::Result<()> {
        let (bucket, offset) = self.bucket(key)?;
        let slot = bucket
            .as_chunks::<SLOT>()
            .0
            .iter()
            .position(|slot| &slot[..32] == key)
            .or_else(|| {
                bucket
                    .as_chunks::<SLOT>()
                    .0
                    .iter()
                    .position(|slot| slot.iter().all(|&b| b == 0) || !valid(slot))
            });
        let index = slot
            .unwrap_or_else(|| u64::from_le_bytes(key[8..16].try_into().unwrap()) as usize % WAYS);
        if slot.is_none() {
            self.stats.evictions += 1;
        }
        let mut bytes = [0; SLOT];
        bytes[..32].copy_from_slice(key);
        bytes[32..64].copy_from_slice(pmk);
        bytes[64..96].copy_from_slice(&checksum(key, pmk));
        self.file
            .seek(SeekFrom::Start(offset + (index * SLOT) as u64))?;
        self.file.write_all(&bytes)?;
        self.stats.writes += 1;
        self.dirty = true;
        Ok(())
    }
    /// Commit each completed batch before advancing a dictionary checkpoint.
    pub fn flush(&mut self) -> io::Result<()> {
        if self.dirty {
            self.file.sync_data()?;
            self.dirty = false;
        }
        Ok(())
    }
    pub fn capacity(&self) -> u64 {
        u64::from(self.buckets) * WAYS as u64
    }
}
