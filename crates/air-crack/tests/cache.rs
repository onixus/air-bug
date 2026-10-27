use air_crack::cache::{key, Cache};
use std::io::{Read, Seek, SeekFrom, Write};
use std::path::PathBuf;
use std::sync::atomic::{AtomicUsize, Ordering};
struct Temp(PathBuf);
impl Temp {
    fn new() -> Self {
        static NEXT: AtomicUsize = AtomicUsize::new(0);
        let path = std::env::temp_dir().join(format!(
            "pmk-cache-{}-{}",
            std::process::id(),
            NEXT.fetch_add(1, Ordering::Relaxed)
        ));
        std::fs::create_dir(&path).unwrap();
        Self(path)
    }
    fn path(&self) -> PathBuf {
        self.0.join("pmk.cache")
    }
}
impl Drop for Temp {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}
#[test]
fn persistent_private_cache_binds_octet_ssid_and_candidate_and_excludes_other_writers() {
    let tmp = Temp::new();
    let a = key(b"one\0network", "test password");
    let b = key(b"one", "test password");
    assert_ne!(a, b);
    assert_ne!(a, key(b"one\0network", "another password"));
    let mut cache = Cache::open(&tmp.path(), 1).unwrap();
    assert!(Cache::open(&tmp.path(), 1).is_err());
    cache.put(&a, &[7; 32]).unwrap();
    cache.flush().unwrap();
    drop(cache);
    let mut cache = Cache::open(&tmp.path(), 1).unwrap();
    assert_eq!(cache.get(&a).unwrap(), Some([7; 32]));
    assert_eq!(cache.get(&b).unwrap(), None);
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        assert_eq!(
            std::fs::metadata(tmp.path()).unwrap().permissions().mode() & 0o777,
            0o600
        );
    }
}
#[test]
fn collisions_evict_without_false_hits_or_growing_the_file() {
    let tmp = Temp::new();
    let mut cache = Cache::open(&tmp.path(), 1).unwrap();
    let size = std::fs::metadata(tmp.path()).unwrap().len();
    for n in 1..=5 {
        let mut key = [0; 32];
        key[8] = n;
        cache.put(&key, &[n; 32]).unwrap();
    }
    let mut last = [0; 32];
    last[8] = 5;
    assert_eq!(cache.get(&last).unwrap(), Some([5; 32]));
    assert_eq!(cache.stats.evictions, 1);
    let mut missing = [0; 32];
    missing[8] = 99;
    assert_eq!(cache.get(&missing).unwrap(), None);
    assert_eq!(std::fs::metadata(tmp.path()).unwrap().len(), size);
    assert!(size <= 1024 * 1024);
}
#[test]
fn torn_entries_are_misses_but_bad_headers_and_truncation_are_errors() {
    let tmp = Temp::new();
    let k = key(b"Test Network", "test password");
    let mut cache = Cache::open(&tmp.path(), 1).unwrap();
    cache.put(&k, &[9; 32]).unwrap();
    cache.flush().unwrap();
    drop(cache);
    let mut file = std::fs::OpenOptions::new()
        .read(true)
        .write(true)
        .open(tmp.path())
        .unwrap();
    let mut head = [0; 64];
    file.read_exact(&mut head).unwrap();
    let buckets = u32::from_le_bytes(head[20..24].try_into().unwrap());
    let pos = 64 + (u64::from_le_bytes(k[..8].try_into().unwrap()) % u64::from(buckets)) * 512 + 32;
    file.seek(SeekFrom::Start(pos)).unwrap();
    file.write_all(&[99]).unwrap();
    drop(file);
    let mut cache = Cache::open(&tmp.path(), 1).unwrap();
    assert_eq!(cache.get(&k).unwrap(), None);
    assert_eq!(cache.stats.corrupt, 1);
    cache.put(&k, &[9; 32]).unwrap();
    cache.flush().unwrap();
    assert_eq!(cache.get(&k).unwrap(), Some([9; 32]));
    drop(cache);
    let before = std::fs::read(tmp.path()).unwrap();
    let mut bad = before.clone();
    bad[0] ^= 1;
    std::fs::write(tmp.path(), &bad).unwrap();
    assert!(Cache::open(&tmp.path(), 1).is_err());
    assert_eq!(std::fs::read(tmp.path()).unwrap(), bad);
    std::fs::write(tmp.path(), &before[..before.len() - 1]).unwrap();
    assert!(Cache::open(&tmp.path(), 1).is_err());
}
#[cfg(unix)]
#[test]
fn existing_symlinks_and_public_permissions_are_rejected() {
    use std::os::unix::fs::{symlink, PermissionsExt};
    let tmp = Temp::new();
    let cache = Cache::open(&tmp.path(), 1).unwrap();
    drop(cache);
    let link = tmp.0.join("link");
    symlink(tmp.path(), &link).unwrap();
    assert!(Cache::open(&link, 1).is_err());
    std::fs::set_permissions(tmp.path(), std::fs::Permissions::from_mode(0o644)).unwrap();
    assert!(Cache::open(&tmp.path(), 1).is_err());
}

#[test]
fn precomputed_raw_candidate_must_equal_the_supplied_pmk() {
    let root = [7; 32];
    let ap = [2, 0, 0, 0, 0, 1];
    let sta = [2, 0, 0, 0, 0, 2];
    let targets = air_crack::engine::TargetSet::new(
        vec![air_handshake::VerificationTarget::Pmkid(
            air_handshake::PmkidSession {
                bssid: ap,
                sta,
                pmkid: air_core::pmkid(&root, &ap, &sta),
            },
        )],
        b"Test Network".to_vec(),
    )
    .unwrap();
    let correct = "07".repeat(32);
    let wrong = "08".repeat(32);
    assert!(targets.verify_precomputed(&correct, &root));
    assert!(!targets.verify_precomputed(&wrong, &root));
    assert!(!targets.verify_precomputed(&"x".repeat(64), &root));
}
