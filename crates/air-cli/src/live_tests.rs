use super::*;
use std::sync::atomic::AtomicUsize;

struct Session(PathBuf);
impl Session {
    fn new() -> Self {
        static NEXT: AtomicUsize = AtomicUsize::new(0);
        let path = std::env::temp_dir().join(format!(
            "air-shadow-unit-{}-{}",
            std::process::id(),
            NEXT.fetch_add(1, Ordering::Relaxed)
        ));
        create_session(&path).unwrap();
        Self(path)
    }
    fn args(&self) -> CaptureArgs {
        CaptureArgs {
            iface: "en0".into(),
            output: self.0.join("out.pcap"),
            bssid: [2, 0, 0, 0, 0, 1],
            monitor: false,
            duration: 1,
            max_packets: 10,
        }
    }
}
impl Drop for Session {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}
#[test]
fn worker_records_success_and_prevents_reuse() {
    let session = Session::new();
    worker(session.args(), session.0.clone(), |_, _| Ok(())).unwrap();
    assert!(state(&session.0).unwrap().starts_with("completed:"));
    assert!(worker(session.args(), session.0.clone(), |_, _| panic!(
        "must not run twice"
    ))
    .is_err());
    shadow(Shadow::Stop {
        session: session.0.clone(),
    })
    .unwrap();
}
#[test]
fn worker_records_backend_failure() {
    let session = Session::new();
    assert!(worker(session.args(), session.0.clone(), |_, _| bail!(
        "permission denied test"
    ))
    .is_err());
    assert!(state(&session.0)
        .unwrap()
        .contains("failed: permission denied test"));
    assert!(shadow(Shadow::Status {
        session: session.0.clone()
    })
    .is_err());
}
#[test]
fn worker_observes_stop_request_and_heartbeat() {
    let session = Session::new();
    worker(session.args(), session.0.clone(), |_, stop| {
        assert!(!stop());
        assert!(state(&session.0).unwrap().starts_with("active worker"));
        private_file(&session.0.join("STOP"))?;
        assert!(stop());
        Ok(())
    })
    .unwrap();
    assert!(state(&session.0).unwrap().starts_with("completed:"));
}
#[test]
fn stale_session_is_never_reported_running() {
    let session = Session::new();
    assert!(state(&session.0).is_err());
    private_file(&session.0.join("heartbeat"))
        .unwrap()
        .set_modified(SystemTime::UNIX_EPOCH)
        .unwrap();
    assert!(state(&session.0)
        .unwrap_err()
        .to_string()
        .contains("stale session"));
}
#[cfg(unix)]
#[test]
fn private_permissions_and_session_symlink_rejection() {
    use std::os::unix::fs::{symlink, PermissionsExt};
    let session = Session::new();
    assert_eq!(
        fs::metadata(&session.0).unwrap().permissions().mode() & 0o777,
        0o700
    );
    let f = private_file(&session.0.join("private")).unwrap();
    assert_eq!(f.metadata().unwrap().permissions().mode() & 0o777, 0o600);
    let link = session.0.join("link");
    symlink(&session.0, &link).unwrap();
    assert!(verify_session(&link).is_err());
}

// Test-only subprocess fixture: no production environment override or radio.
#[cfg(unix)]
#[test]
fn worker_process_helper() {
    use std::io::Write;
    let Some(path) = std::env::var_os("AIR_TEST_WORKER_SESSION") else {
        return;
    };
    let session = Session(PathBuf::from(path));
    install_signals().unwrap();
    worker(session.args(), session.0.clone(), |opts, stop| {
        let mut file = private_file(&opts.output)?;
        let mut header = vec![0xd4, 0xc3, 0xb2, 0xa1, 2, 0, 4, 0];
        for value in [0u32, 0, 65535, 105] {
            header.extend(value.to_le_bytes());
        }
        file.write_all(&header)?;
        drop(file);
        private_file(&session.0.join("ready"))?;
        let deadline = Instant::now() + Duration::from_secs(10);
        while !stop() {
            if Instant::now() > deadline {
                bail!("fixture did not receive stop");
            }
            std::thread::sleep(Duration::from_millis(20));
        }
        Ok(())
    })
    .unwrap();
    // Parent owns cleanup; preserve result and pcap for its assertions.
    std::mem::forget(session);
}

#[cfg(unix)]
#[test]
fn separate_worker_finalizes_after_stop_and_unix_signals() {
    use std::os::unix::process::CommandExt;
    struct Child(std::process::Child);
    impl Drop for Child {
        fn drop(&mut self) {
            let _ = self.0.kill();
            let _ = self.0.wait();
        }
    }
    for signal in [None, Some("-INT"), Some("-TERM"), Some("-HUP")] {
        let session = Session::new();
        let mut child = Child(
            Command::new(std::env::current_exe().unwrap())
                .args([
                    "--exact",
                    "live::tests::worker_process_helper",
                    "--nocapture",
                ])
                .env("AIR_TEST_WORKER_SESSION", &session.0)
                .stdin(Stdio::null())
                .stdout(Stdio::null())
                .stderr(Stdio::null())
                .process_group(0)
                .spawn()
                .unwrap(),
        );
        let deadline = Instant::now() + Duration::from_secs(5);
        while !session.0.join("ready").exists() {
            assert!(Instant::now() < deadline, "worker did not initialize");
            assert!(
                child.0.try_wait().unwrap().is_none(),
                "worker exited prematurely"
            );
            std::thread::sleep(Duration::from_millis(20));
        }
        if let Some(signal) = signal {
            assert!(Command::new("/bin/kill")
                .args([signal, &child.0.id().to_string()])
                .status()
                .unwrap()
                .success());
        } else {
            shadow(Shadow::Stop {
                session: session.0.clone(),
            })
            .unwrap();
        }
        let deadline = Instant::now() + Duration::from_secs(5);
        loop {
            if let Some(status) = child.0.try_wait().unwrap() {
                assert!(status.success());
                break;
            }
            assert!(Instant::now() < deadline, "worker failed to finalize");
            std::thread::sleep(Duration::from_millis(20));
        }
        assert!(state(&session.0).unwrap().starts_with("completed:"));
        assert!(air_capture::read_pcap(session.0.join("out.pcap"))
            .unwrap()
            .is_empty());
    }
}
