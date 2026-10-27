# Passive live/shadow capture validation

Validated locally on macOS 26.7.1 ARM64 with Rust/Cargo 1.98.1.

## Implemented

- `interfaces`: system tcpdump interface enumeration.
- `live` / `airodump`: explicit foreground capture, exact MAC scope, new private pcap, packet/time limits.
- `shadow start/status/stop`: explicitly launched background worker with private session, heartbeat, stop request, result and diagnostic log; no persistence or stealth.
- SIGINT/SIGTERM/SIGHUP request orderly completion. Child capture runs in its own process group; shutdown interrupts, waits, then force-reaps an unresponsive child and reports failure.
- Monitor mode is explicit, uses DS-aware BSSID filtering, excludes WDS, and may disconnect local Wi-Fi. Default non-monitor mode captures only EAPOL Ethernet packets to/from the supplied MAC; Ethernet cannot prove BSSID identity.
- No injection, deauth, active discovery, channel hopping, automatic sudo or permission changes.

## Verification results

All commands succeeded after fixing strict Clippy warnings:

```sh
cargo fmt --all -- --check
cargo clippy --workspace --all-targets --locked -- -D warnings
cargo test --workspace --locked
cargo test --release --workspace --locked
cargo build --release --workspace --locked
```

55 tests passed in each debug/release profile (including the inert subprocess helper entry). Coverage includes:

- Existing capture parsing, cryptographic vectors and offline CLI fixtures.
- Capture parameter validation, narrow filters, nonoverwrite and symlink refusal.
- Fake tcpdump duration/cancellation, graceful termination, forced termination and reaping.
- Real system tcpdump filtering on synthetic offline 802.11 packets (`-r` only), including other networks with matching non-BSSID addresses.
- Private session permissions, backend failure propagation, heartbeat staleness, duplicate-worker refusal.
- Separate test worker process finalization and valid pcap after STOP, SIGINT, SIGTERM and SIGHUP; no radio devices opened.

Ten additional checks against the built ARM64 release artifact passed: version, live/airodump help, shadow start/status/stop help, interface listing, offline fixture verification, existing-output preservation, and rejection of invalid background options before session/output creation.

## Real-Mac limitation (not a successful radio test)

`/usr/sbin/tcpdump -i en0 -L` was first denied by the session sandbox. An approved retry outside the sandbox reached macOS and failed with:

```text
tcpdump: en0: You don't have permission to capture on that device
((cannot open BPF device) /dev/bpf0: Permission denied)
```

Interface enumeration succeeds, but real radio capture/monitor compatibility has not been qualified. No capture of surrounding networks was performed. An administrator must provide appropriate capture privileges before a real authorized-BSSID test. See the README for commands and adapter/monitor cautions.

A zero-packet valid pcap means capture completed, not that a handshake was observed. Capture does not force client reconnection. Disk rotation is absent. SIGKILL, supervisor crashes and machine suspension can defeat cleanup or timing; use `shadow stop` and conservative limits. Linux/Windows were not tested locally (Windows live capture is unsupported).
