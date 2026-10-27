# aircrack-rs

Experimental Rust workspace for passive live capture and offline Wi-Fi analysis.
The verification path is **pcap/pcapng → WPA/WPA2-PSK M1/M2, M2/M3, M3/M4 or PMKID → passphrase/PSK
verification**, using HMAC-MD5 (descriptor v1), HMAC-SHA1 (descriptor v2) or AES-CMAC
(descriptor v3 with PSK-SHA256 AKM).
`airdecap` decrypts CCMP-128/TKIP/WEP40/WEP104 data, including authenticated
GTK multicast/broadcast, or strips open Wi-Fi captures. Capture and inspect
only networks you are authorized to audit.

## Project status

Status checked on **2026-10-27**: 191 Rust tests, rustfmt and strict Clippy passed;
release CLI and CoreWLAN helper built. Passive survey is implemented. The macOS
hardware diagnosis isolated blocked shutdown signals and the need for an
unassociated adapter; see the [hardware report](docs/MACOS_SURVEY_VALIDATION.ru.md). See the [PMKID/M2-M3 implementation and differential test report](docs/PMKID_M2M3_VALIDATION.ru.md). See the [earlier baseline assessment and comparison
with upstream aircrack-ng 1.7](docs/PROJECT_STATUS_2026-10-27.ru.md) for functional
gaps, evidence and acceptance limits. This is a subset implementation, not a
drop-in replacement for the upstream suite.

## Android · Apex

An offline Android 8.0+ app (arm64-v8a + x86_64) reuses the Rust verification
pipeline through a bounded JNI adapter. Dark/light/system Apex UI, private SAF
imports and local dictionary verification; no live capture or Internet permission.
See the [Android build, usage and verification notes](<android/README.md>).

```sh
bash android/build-android.sh
```

## Build and checks

Use a current stable Rust toolchain with rustfmt and Clippy; local checks used
Rust/Cargo 1.98.1. Offline analysis needs no native libpcap, root privileges or radio.
Live capture uses the system tcpdump and requires OS capture permissions.

```sh
cargo build --workspace --locked
cargo test --workspace --locked
cargo fmt --all -- --check
cargo clippy --workspace --all-targets --locked -- -D warnings
```

## Ordinary Wi-Fi overview on macOS (keeps the connection)

Use **`scan`** to list access points, channels, bands, RSSI and noise through the
ordinary CoreWLAN API. The Security column shows advertised Open/WEP/WPA/WPA2/
WPA3/OWE modes, including mixed modes; unavailable metadata is Unknown. The
current access point is marked `* Connected` with a success background, matched
by BSSID (never by SSID). If macOS hides the current BSSID, no row is guessed. It works with the Wi-Fi interface still associated. It does
not open BPF, request monitor mode, tune channels, disconnect, or change Wi-Fi power.
No administrator privileges are required. OS scans may briefly affect latency;
association is checked before/after each scan and refresh stops if it changes.

Build the CLI and its separate scan companion:

```sh
cargo build -p air-cli --release --locked
sh tools/build-wifi-scan-macos.sh
./target/release/aircrack scan --iface en0
./target/release/aircrack scan --iface en0 --tui --interval 15
./target/release/aircrack scan --iface en0 --tui --ssid "home"
./target/release/aircrack scan --iface en0 --cached
```

`scan --tui` opens an interactive table; `--watch` also selects it when stdin and
stdout are terminals. Rows update in place, strongest signal first. All actions are available without letter keys: Tab opens an actions menu,
arrows select an action, Enter runs it, Esc closes it. F1 shows help; F2 cycles
APEX themes; F3 edits the SSID filter; F4 cycles signal/SSID/channel/security
sorting; F5 refreshes once; F6 reverses sorting; F7 cycles all/2.4/5/6 GHz;
F8 jumps to the current AP and clears filters; F9 or Space pauses/resumes;
F10 exits. On a Mac, function keys may require Fn; the Tab menu is an alternative.
While editing, SSID input accepts any language, Enter applies, Esc cancels,
Delete clears. Old letter shortcuts remain optional aliases.

F11 opens signal history for the selected BSSID; F12 opens channel distribution.
Both are also at the end of the Tab actions menu (scroll with arrows).
History keeps 60 successful snapshots with elapsed-time and dBm axes. Missing
observations make gaps; unavailable BSSIDs are never tracked by SSID. The graph
stays pinned to its BSSID if the AP disappears or rows reorder. Cached scans may
repeat old measurements; the horizontal axis is snapshot time, not measurement
age. History is in memory only and resets when scan restarts.

Channel bars count all returned AP rows in the latest snapshot, independently
of table filters, with separate 2.4/5/6 GHz groups and unknown metadata labelled
`?`. This is not channel utilization or interference measurement. Arrows scroll
the chart; Esc returns to the table. In both charts F2 switches APEX theme,
F5 refreshes and F9/Space pauses. The scan backend is unchanged.

Arrows, PgUp/PgDn, Home and End select an AP; Enter opens full details including
BSSID, security, signal, noise and SNR. Selection follows the BSSID across
refreshes when available. The selected row has a `>` marker and underline;
the connected AP retains its separate `* Connected` status. Pausing cancels the
in-flight helper; F5 can refresh once while paused without resuming automation. `--ssid NAME`
sets the initial filter (also available in plain output). Unknown signals sort last.

The scan table uses [APEX tokens](https://github.com/onixus/unified-platform/issues/117)
from the vendored 0.1.0 Rust palette subset in `air-tui/src/apex_tokens.rs`.
`--theme dark|light|system` selects its theme; `t` cycles themes in place.
System mode uses the terminal's `COLORFGBG` background hint, falling back to dark
when absent. Theme changes last for this session. Fonts and cell dimensions are
controlled by the terminal; browser CSS, localStorage and pixel-based focus rings
do not apply. The filter border uses focus-ring and the current-network status
uses text plus a marker and success-subtle background, not color alone.

Scanning runs in one background worker, so input remains responsive; quitting
cancels and reaps the helper. Failed refreshes retain the previous snapshot with
an error and update age. `--plain --watch` retains append-only text output;
redirected `--watch` output is also plain. The interval is a delay after each
completed scan (minimum 5 seconds). `--cached` reads the OS cache without requesting a scan; cache age is
unknown and clearly labelled. Empty results are not proof that no networks exist.
This is AP discovery, not packet capture or a client/station inventory. An ordinary
OS scan can transmit probe requests; it is not advertised as passive monitoring.

Security validation on this Mac identified WPA2, WPA/WPA2 and WPA2/WPA3;
with location consent, exactly one scanned BSSID matched the current association.
Interactive terminal validation also exercised APEX dark/light theme switching,
the Security column and clean terminal restoration. Re-signing the helper can
require location consent again before the current BSSID is available.

Interactive terminal validation on this Mac (2026-10-27): a real ordinary scan,
SSID filter, signal-order toggle and exit completed successfully. Alternate-screen
and terminal settings were restored; `en0` stayed associated on channel 44 and
the following HTTPS request returned 200.

macOS may withhold SSID/BSSID until Location Services consent is granted. Missing
identifiers are labelled explicitly and are not merged into a fictitious single
AP. Channels and signal may still be available. To explicitly request consent:

```sh
./target/release/aircrack scan --iface en0 --request-location
```

The bundled `Air Wi-Fi Scan.app` has a Location Services purpose string and requests
consent only with this option; it does not request location coordinates or upload
results. The consent dialog can take up to 45 seconds. Denial/global Location
Services disablement produces an explicit error; ordinary restricted scanning
continues to be available without this flag. Rebuilding the ad-hoc-signed companion
can require renewed consent. `sudo` does not replace privacy consent.

Hardware validation on this Mac (2026-10-27): ordinary scanning returned **18 APs**
with channels and signals, while `en0` remained associated on channel 44 and an
HTTPS request returned 200. SSID/BSSID were redacted by macOS during that test.
Location consent was subsequently validated: `--request-location` succeeded,
then separate ordinary scan/cache launches exposed BSSIDs without another request.
The last ordinary scan returned 25 APs, 25 BSSIDs and 20 SSIDs; five SSIDs were not
provided by macOS. Cache returned 37 APs/BSSIDs and 20 SSIDs. Connection stayed on
channel 44 and HTTPS returned 200. A helper initialization bug discovered during
this check was fixed: every invocation now establishes the existing authorization
context, while only `--request-location` may ask for new consent.
No monitor capture, disassociation, channel change or power cycle was performed.
The scan helper is a separate executable with none of those control APIs.

## Passive AP/client survey

`survey` is the live dashboard: AP BSSID/SSID/channel/signal/security, beacon and
packet counters, and client MAC/last observed BSSID/signal/probe SSID. It reads
management and data headers, including protected/QoS/null data, without decrypting
payloads. Omit `--bssid` to observe all networks on the selected channel, or supply
an exact BSSID to narrow the capture. This is passive reception, not active scanning.

Build the CLI with `cargo build -p air-cli --release --locked`. On Linux, install
`iw` and use an **already configured monitor interface** (for example `mon0`).
The program checks the interface type and the adapter/regulatory channel list;
it does not create interfaces, disconnect clients, or change interface mode.
On macOS, build the small CoreWLAN helper **beside the CLI executable**:

```sh
swiftc tools/air-channel-macos.swift -framework CoreWLAN -o target/release/air-channel-macos
```

On macOS, survey refuses an associated or unknown-mode interface **before opening
capture**, to protect the current Wi-Fi connection. Use a dedicated, unassociated
adapter; the program never disconnects Wi-Fi automatically. CoreWLAN refuses
channel changes while associated. Capture rights and channel-control rights must already be available.
Neither platform automatically invokes sudo. Use a dedicated adapter where possible.

```sh
./target/release/aircrack survey --iface mon0 --list-channels
./target/release/aircrack survey --iface mon0 --output survey.pcap --channel 6
./target/release/aircrack survey --iface mon0 --output hopping.pcap \
  --channels 1,6,11 --dwell-ms 1000 --duration 300
# On macOS substitute the actual Wi-Fi interface, e.g. en0.
# Offline inventory, without opening a radio:
./target/release/aircrack survey --read tests/fixtures/wpa2-radiotap.pcap
```

Controls: **Left/Right** selects the previous/next channel and holds it;
**Space** toggles hopping; **Tab** selects the AP/client table; **Up/Down** scrolls;
**q/Esc/Ctrl-C** stops. An explicit `--channels` list is also the manual cycle;
otherwise manual selection cycles the adapter's available channels. Without channel
options, capture initially holds the existing channel. `--plain` prints periodic
text snapshots for noninteractive use. `--read` always prints one offline snapshot.

### Enterprise audit and roaming diagnostics

`survey` also observes outer 802.1X/EAP metadata, advertised Enterprise AKMs and
802.11k/v/FT capabilities, plus a bounded management-event journal with
reassociation status, disconnect reasons and FT authentication algorithm.
Plain output, TUI and JSON/CSV exports include these diagnostics automatically.
No identities or EAP payloads are retained in audit fields/exports; saved PCAPs
still contain original packets. EAP counts aggregate across peers per BSSID;
management observations do not prove completed roaming or outage duration.
See [Enterprise and roaming scope, usage and validation](docs/ENTERPRISE_ROAMING.ru.md).
[Native Fedora 43 validation](docs/FEDORA_ENTERPRISE_ROAMING_VALIDATION.ru.md):
218 Rust tests and 16 roaming/fragment cases passed, as did fmt, strict Clippy
and release build. The VM exposed only virtual Ethernet; real radio/Enterprise
roaming remains unverified.

### Captured handshake / PMKID indicator

The AP table's **Evidence** column shows `HS`, `FT`, `PMKID`, `HS+PMKID` or `-`.
The status line counts AP rows carrying each evidence type. `HS` means a
structurally supported descriptor-v1/v2/v3 WPA/WPA2 M1/M2, M2/M3 or usable M3/M4 pair was captured;
PMKID means a supported M1 KDE or PSK association/reassociation PMKID was seen.
These flags **do not verify the MIC, PMKID or password**. A malformed capture can
contain syntactically plausible evidence. Use the offline verification command
with the saved PCAP and the correct SSID to test candidate passwords.

Pair matching shares the offline verifier's EAPOL parser, endpoints, direction
and replay-counter rules; it works with reordered packets. No full handshake
frames or secrets are retained by the indicator. A cache of up to **256 pending
message summaries**, expiring after **120 seconds of processing time**, bounds
memory and matching work. `pending-evicted` reports capacity evictions; a missing
indicator is not proof that no handshake occurred. Offline replay also uses
processing time, not capture timestamps. Evidence sticks to the AP row until
that row expires or is evicted; counts describe the current table, not a permanent
session archive. Unsupported descriptor versions do not produce indicators.

### Export survey results

```sh
# Final snapshot after a live survey finishes or is stopped normally
./target/release/aircrack survey --iface mon0 --output survey.pcap \
  --channel 6 --export-json survey.json --export-csv survey.csv

# Export an existing capture without opening any radio
./target/release/aircrack survey --read tests/fixtures/wpa2-radiotap.pcap \
  --export-json snapshot.json --export-csv snapshot.csv
```

Both flags are optional and may be combined. Exports are final snapshots, not
periodic logs; they contain the current bounded AP/client tables after filtering
and expiry. Existing output paths (including symlinks) are never overwritten.
New export files are reserved before capture, use mode 0600 on Unix, and are
filled only after successful capture/parser finalization and channel restoration.
On ordinary failure, reserved export files are removed; a process crash can leave
empty/partial files. `--list-channels` cannot be combined with export flags.
The PCAP remains the input for offline password verification; exports contain
metadata and evidence flags, not EAPOL payloads, nonces, MICs or passwords.

JSON uses `schema_version: 1`, separate `access_points` and `clients` arrays,
summary counters and elapsed processing time. APs include separate
`handshake_m1m2`, `handshake_m2m3` and `pmkid` booleans; unknown numeric metadata
is `null`. `ssid_hex` / `probe_ssid_hex` preserve bytes exactly, while display
strings escape control and non-ASCII bytes. `age_seconds` is processing-time age;
client `last_bssid` is an observation, not confirmation of current association.

CSV has one header and a `kind` column (`ap` / `client`) with matching metadata
columns; fields that do not apply or were not observed are empty. Text is quoted,
quotes are doubled and formula-like text gets a leading apostrophe for spreadsheet
imports; raw SSID hex is preserved separately. Negative numeric RSSI is kept
numeric. JSON includes pending-cache eviction/coverage diagnostics; CSV is a
flat table and should be accompanied by JSON when those diagnostics matter.

Current boundaries:

- Tuning covers **2.4/5 GHz, 20 MHz**, using only adapter-supported channels. No
  6 GHz tuning, bandwidth selection, active scan, injection, or multi-adapter capture.
  Channel changes use `iw ... set freq` on Linux and CoreWLAN on macOS. The original
  primary channel is restored on orderly exit/error when known; original bandwidth
  and Wi-Fi association are not restored. A missing original channel is reported.
- A `?` means metadata was not observed. Client signal is measured only from client
  transmissions; AP signal only from AP transmissions. Last BSSID is an observation,
  not a current-association assertion. Counters include retransmissions. Security
  labels describe advertisements: `RSN`, `RSN/SAE`, `WPA`, `Privacy` or `Open`;
  `Privacy` alone does not establish that the AP uses WEP.
- Stale rows expire after 120 seconds (`--stale-seconds`), each table is capped at
  4096 rows, and oldest rows are evicted at the cap. SSID control/non-ASCII bytes
  are escaped before terminal output. WDS/mesh, control frames and management
  reassembly are not implemented. Survey does not infer hidden SSIDs from clients.
- The live reader processes bounded chunks and incomplete file writes. The output
  is classic PCAP with 4096-byte snapshots; both `<output>` and `<output>.log` are
  exclusively created with mode 0600. Existing files are never overwritten.
  Defaults: 300 seconds and 100000 packets. No disk rotation. A failed capture can
  leave partial files; diagnostics are retained outside the alternate terminal.
- Offline survey accepts raw 802.11/Radiotap PCAP and PCAPng;
  Ethernet is not supported by this survey reader. The existing offline
  verification command still supports pcapng. Offline ages reflect processing time.
- Synthetic parser, CLI, UI rendering and subprocess/channel tests are automated.
  Synthetic tests do not qualify real hardware; see the separate hardware report.

### macOS hardware check — 2026-10-27

On this Mac, associated `en0` received Ethernet packets but no Radiotap packets,
including with direct unfiltered tcpdump. After temporary disassociation, direct
tcpdump received **1202 packets**, and CoreWLAN confirmed channels **1 and 6**.
The test interrupted connectivity; Wi-Fi subsequently reconnected on channel 44
and an HTTPS request succeeded. No further disconnections are part of validation.

The implementation now rejects survey on an associated Mac adapter before device
opening, resets inherited blocked shutdown signals, verifies channel readback,
and reports zero-packet surveys as unverified/error rather than success. The
production helper never disassociates or toggles Wi-Fi power. Full evidence,
limits and test details: [macOS validation report](docs/MACOS_SURVEY_VALIDATION.ru.md).

## Passive live and shadow capture

Build with `cargo build --release --workspace --locked`, then:

```sh
./target/release/aircrack interfaces
# Replace the example MAC with the exact BSSID authorized for your test.
./target/release/aircrack live --iface en0 --bssid 02:00:00:00:00:01 \
  --output authorized.pcap --duration 60 --max-packets 10000

./target/release/aircrack shadow start --iface en0 --bssid 02:00:00:00:00:01 \
  --output background.pcap --session ./capture-session --duration 300
./target/release/aircrack shadow status --session ./capture-session
./target/release/aircrack shadow stop --session ./capture-session
```

`airodump` is an alias of `live`; `--write` aliases `--output`. These live/shadow commands have no
channel-switching option; use `survey` for the AP/client dashboard and tuning. Each output and session directory must be **new**;
outputs are exclusively created with mode 0600, sessions with mode 0700 on Unix.
Shadow is an explicit background worker, not stealth, persistence or auto-start.
It has a heartbeat, diagnostic log and stop request; stale status fails instead
of claiming that capture is running. INT/TERM/HUP request orderly finalization.
Use `shadow stop`, not `kill -9`; forcibly killing the supervisor can defeat its
cleanup/time watchdog. Capture stops after the packet or duration limit
(1..86400 seconds, default 60; default 10000 packets), plus shutdown overhead.
There is no disk rotation; choose conservative limits and protect capture files.

By default tcpdump runs non-promiscuously and captures only EAPOL Ethernet
packets to/from the supplied MAC. Ethernet has **no BSSID field**: this is an
endpoint filter, not proof of wireless association. Beacons/SSIDs are unavailable
and offline verification may need `--essid`. Drivers may not expose EAPOL at all.
For actual infrastructure BSSID filtering and 802.11 frames, explicitly add
`--monitor`; DS-aware filters select the AP's BSSID; WDS additionally matches the selected radio
address in RA/TA, never a bridged DA/SA. Monitor mode
**can disconnect Wi-Fi**, does not select/hop channels, and depends on adapter,
driver, OS permissions and link type. A dedicated capture adapter is preferable.
No mode transmits probes, deauth or injected packets. Passive capture cannot
force a handshake; a valid zero-packet pcap is successful capture, not proof of
handshake availability. Verification remains a separate `aircrack` command.

The backend uses fixed `/usr/sbin/tcpdump` on macOS and `/usr/bin/tcpdump` on
Linux. Windows live capture is unsupported; offline analysis remains available.
It never runs sudo or changes BPF permissions automatically. On the tested Mac,
interface enumeration worked but opening `en0` failed with `/dev/bpf0: Permission
denied`; real radio capture has **not** been qualified. An administrator must
provide appropriate capture rights (or explicitly run the audited binary with
suitable privileges). Never publish private captures or logs.

## Verify a capture

```sh
cargo run -p air-cli -- aircrack --capture capture.pcap --wordlist wordlist.txt
```

The SSID is read from beacon/probe-response information elements. For hidden SSIDs,
Ethernet captures, or captures without beacons, specify `--essid MySSID`. For
multiple networks, all supported BSSIDs are considered by default; repeat
`--bssid` to select a subset. Conflicting advertised SSIDs for one BSSID require
`--essid` or `--ssid-map`; an explicit SSID must match one of the
observed non-hidden SSIDs for the selected BSSID. SSID bytes from captures
are preserved, including non-UTF-8 values. The CLI's `--essid` accepts UTF-8 text.
Without `--wordlist`, the command reports supported handshake and PMKID targets separately.

Supported capture encapsulations:

- Raw 802.11 (DLT 105), including QoS data headers.
- Radiotap (DLT 127), including TSFT alignment, FCS presence and data padding.
- Ethernet EAPOL (DLT 1, EtherType 0x888e, without VLAN tags).
- pcapng enhanced/simple packet blocks, multiple interfaces and sections.

A complete M1/M2 pair must have matching BSSID, station and replay counter.
M2/M3 pairs use the same endpoints and require M3 replay = M2 replay + 1,
without wraparound; the engine verifies M2 MIC using M3 ANonce.
PMKID targets are extracted from M1 PMKID KDEs or PSK-only association/reassociation
RSN PMKID lists. PMKID uses HMAC-SHA1 over `PMK Name || AP || STA`, without a
terminating NUL or sorting MACs. Beacon PMKID lists and unsupported AKMs are not
association targets.
Retransmissions are deduplicated; packet input order is immaterial. Malformed or
unrelated packets are skipped. Invalid capture containers and unknown link types
produce errors. Only complete pairs are passed to the verification engine.
EAPOL's declared length excludes capture padding/FCS from MIC computation; the
MIC field is zeroed and compared in constant time against the captured MIC.

Passphrase dictionaries are UTF-8 text with one candidate per line. Candidates
must be 8–63 printable ASCII bytes (spaces are preserved). CRLF is supported.
A dictionary line is limited to 64 KiB excluding LF; overlong lines and invalid
UTF-8 fail explicitly. An exactly 64-character hexadecimal candidate is interpreted
as a raw 32-byte PSK/PMK, bypassing PBKDF2; other 64-character strings are invalid.
Passphrase rules above apply to non-hex candidates. Dictionaries are read in batches of
256 candidates, without an unbounded PMK cache or a global lock around PBKDF2.
All selected BSSIDs share one ordered dictionary pass. Targets are grouped by
exact SSID bytes; one PMK per unique candidate/SSID in a bounded batch serves all
BSSIDs in that group. Each BSSID retains its own first matching position, even
when equal SSIDs use different passwords. Matching any target verifies only its
own BSSID. JNI also shares PMK derivation
while keeping sequential mobile candidate processing.
Read/encoding errors are reported rather than silently truncating the dictionary.
Capture input is streamed and retained evidence is bounded. A match prints
`[+] found:`; multi-network output includes BSSID and SSID hex. Missing context,
input errors, exhausted unmatched networks and paused runs return nonzero.
Complete verification of all selected networks returns zero. Successful password output contains the recovered
passphrase, so treat that output as sensitive.

### Resource limits, progress, checkpoints and stdin

CLI `aircrack`, `airdecap` and `wpaclean` read regular PCAP/PCAPng files through
`CaptureReader`, one record at a time. Their default input work budgets are
**4096 MiB / 10000000 packets**; `--max-capture-mib` can raise the byte budget
up to 1048576 MiB and `--max-packets` can raise the packet budget up to u32::MAX.
Memory use does not grow with total capture size. The parser uses a fixed
8,000,000-byte buffer and caps PCAPng sections at **256 interfaces**.

Verification retains only unique EAPOL/association/FT evidence and distinct
SSID advertisements: at most **1024 relevant records**, **1024 SSID advertisements**
and **4 MiB of retained payload**, plus bounded fragment assembly. Extraction
allows at most **1024 targets** before pair expansion. New evidence exceeding a
budget fails the whole operation; unrelated data and exact duplicates are discarded.
For `aircrack`, BSSID selection is applied before bounded SSID discovery;
BSSID/SSID selection then precedes the relevant-record evidence budget.
SSID discovery itself retains at most 1024 distinct advertisements. `wpaclean`
retains its existing whole-capture evidence policy. `--max-records` and `--max-targets` lower extraction ceilings
on `aircrack`; `wpaclean` exposes `--max-records` and uses 1024 targets.

These are work and retained-state bounds, not an OS-enforced RSS or wall-time
sandbox. Compatibility `read_pcap*` collectors still return a Vec and retain their
64 MiB / 100000-packet defaults. JNI uses the streaming reader while retaining its
stricter file/packet/evidence limits. Live survey keeps its incremental reader;
offline `survey --read` now also accepts PCAPng with 4096 MiB / 10000000-packet budgets.

```sh
# New checkpoint, progress to stderr; checkpoint path must not already exist
./target/release/aircrack aircrack --capture capture.pcap \
  --wordlist words.txt --progress --session audit.session

# Continue with the same inputs and network selection
./target/release/aircrack aircrack --capture capture.pcap \
  --wordlist words.txt --progress --resume audit.session

# Read candidates from a pipe (no checkpoint/resume for stdin)
cat words.txt | ./target/release/aircrack aircrack \
  --capture capture.pcap --wordlist - --progress
```

`--progress` reports committed dictionary lines, lines/second and elapsed time at
batch boundaries and on completion; it does not display candidate strings.
Counts include skipped invalid-length/non-printable candidates, and are not a
PBKDF2 benchmark. On resume, the completed count is cumulative and speed/elapsed
refer to the current run. There is no percentage or ETA because the dictionary
is not pre-counted. In the legacy single-network mode, a successful report
includes the matching line; checkpoints retain the preceding batch so the matching batch is replayable without saving
the recovered password.

The compatible single-capture/single-dictionary/single-network mode uses
checkpoint version **5**. Multi-input/network mode or `--results-json` uses the
common version **6**, described below. Version-1/2/3/4 checkpoints are rejected:
older engines may have skipped newly supported M3/M4 or WDS targets, or complete fragment chains.
Start a new session after upgrading rather than resuming that prefix.

Checkpoints contain versioned JSON, completed line count, selected SSID/BSSID,
a SHA-1 fingerprint of link types, original/captured lengths, packet order/data
and resolved timestamps, plus the dictionary content fingerprint. Fragment expiry
depends on timestamps, so timestamp edits also invalidate resume. Fingerprints
detect changed inputs; they do not authenticate an untrusted checkpoint.
Keep inputs unchanged throughout a run. Dictionary hashing uses bounded memory
and reads the complete file before a checkpointed run; resume then reads/skips
completed lines without PBKDF2 (it does not seek directly to a byte offset).

Checkpoints use exclusive creation, mode 0600 on Unix, a `.lock` file to prevent
concurrent use, and same-directory temporary files plus atomic rename after each
fully verified batch. SIGINT/SIGTERM on Unix finish the current batch and exit
with a nonzero paused status; `--max-candidates N` provides a deterministic pause
after N additional lines on any platform. Without checkpoint options no state is
saved. A crash/forced termination may repeat the unfinished batch; a stale lock
must be removed manually only after confirming the old process has stopped.
Windows graceful signal handling and power-loss durability are not claimed.
stdin uses ordinary OS signal handling and cannot be resumed. I/O errors remain
fatal and the last committed checkpoint is retained. Checkpoint/resume/stdin
options are desktop CLI features; the Android UI has no new controls for them.

## Multiple captures, dictionaries and networks

```sh
./target/release/aircrack aircrack \
  --capture first.pcap second.pcapng \
  --wordlist common.txt extra.txt \
  --session campaign.session --max-candidates 100000 \
  --results-json paused-results.json --threads 4 --pmk-cache network.pmk-cache

# Same ordered inputs and effective network selection; use a new result path
./target/release/aircrack aircrack \
  --capture first.pcap second.pcapng \
  --wordlist common.txt extra.txt \
  --resume campaign.session --results-json final-results.json \
  --threads 4 --pmk-cache network.pmk-cache
```

`--capture` and `--wordlist` accept space-separated values or repeated flags.
Limits are **64 capture files, 64 dictionaries and 256 BSSIDs**. Capture byte and
packet work budgets are **global across the input list**. Two streaming capture
passes discover SSID context, then collect selected evidence, checking per-file
record fingerprints for changes. M1/M2/M3/M4 can be distributed across input
files. Fragment chains reset between files, avoiding cross-file clock/sequence
mixing. Capture order/content remains part of checkpoint identity, even though
handshake extraction does not depend on input order.

Dictionaries form one ordered sequence. Empty files contribute no candidates;
a final line without LF is a complete candidate and never concatenates with the
next file. CRLF and invalid-line/I/O checks remain unchanged. Same-SSID BSSIDs
share candidate derivation but are verified independently: finding one password
does not mark every BSSID with that SSID as solved. Solved BSSIDs are skipped in
later batches, and whole SSID groups are skipped once all their networks match.
SAE/FT-SAE provenance and cache rules remain in force across mixed groups.

Without a filter, all structurally supported networks are selected. Repeat
`--bssid` for an explicit subset. `--essid` selects an advertised SSID and can
supply a missing UTF-8 salt. All selected targets must have an unambiguous SSID
before dictionary processing. For hidden, non-UTF-8 or conflicting names,
provide `--ssid-map map.json` containing up to 256 entries / 64 KiB:

```json
[{"bssid":"02:00:00:00:00:01","ssid_hex":"54657374204e6574776f726b"}]
```

Mappings explicitly override advertised context for that BSSID; they do not add
targets or bypass cryptographic verification. Duplicate/invalid entries fail.
No SSID or missing nonce is guessed. Captures are still parsed fully to validate
containers and fingerprints; selection limits retained evidence, not input work.

Common checkpoint **v6** binds the ordered resolved-capture fingerprints,
ordered complete dictionary-content hashes and effective BSSID/SSID identities.
It saves the global completed-line count, dictionary cursor and each network's
first-match source position. **Passwords and PMKs are not stored in checkpoints.**
Resume rereads the prefix, retrieves matching lines and cryptographically verifies
them again, sharing derivation by SSID; it then continues unresolved networks.
File indices are zero-based, lines are one-based. A batch can span dictionary
boundaries, and checkpoint updates commit all network matches atomically after
the batch/cache work succeeds. `--max-candidates` counts additional global
candidate lines, not a separate allowance for each SSID. Reading/hashing input
and restoring committed matches are outside that new-line count.

The normal single-input invocation retains the established v5 checkpoint and
successful-batch replay behavior. V5 checkpoints cannot be promoted into a v6
campaign; start a new session when adding inputs/networks or requesting JSON.
Resume requires the same ordered input contents and effective selection; cache
path, worker count and result-output path may change. Input path renames with
identical contents are accepted. Existing `.lock` handling and private atomic
checkpoint writes remain in force. The common checkpoint is capped at 256 KiB.

Each BSSID gets a text result. `--results-json NEW_PATH` writes a private 0600
snapshot with overall `complete`, `paused` or `exhausted` status, and per-network
`found`, `pending` or `not_found`, SSID hex, candidate and dictionary source
position. **Result JSON includes recovered candidates and is sensitive.**
Existing paths, symlinks and inputs are never overwritten; normal I/O/validation
failures remove the reserved result file. An intentional pause or dictionary
exhaustion writes its explicitly marked partial snapshot and exits nonzero.
Previously committed matches survive resume. Results are ordered by BSSID.

A sole stdin dictionary works with multiple networks, but cannot be combined
with other dictionaries or checkpoint/resume. Android/JNI retain their existing
single-capture workflow; this campaign interface is a desktop CLI feature.

## Dictionary speed, benchmark and persistent PMK cache

[Local release measurements and validation](docs/DICTIONARY_PERFORMANCE_2026-10-27.ru.md):
about **1.4× PBKDF2 speedup** on this Mac, with cold/warm cache costs reported separately.

```sh
cargo build --release --workspace --locked
# Synthetic workload, fixed candidates, identical worker count, repeated medians
./target/release/aircrack benchmark --candidates 1024 --samples 7 --threads 1 \
  --json benchmark.json

# Opt-in cache; reusing the file on a later run avoids repeated PBKDF2 work
./target/release/aircrack aircrack --capture evidence.cap --wordlist words.txt \
  --threads 4 --pmk-cache ./network.pmk-cache --pmk-cache-mib 64 --progress
```

The benchmark separates generic RustCrypto PBKDF2, specialized WPA PBKDF2,
the dictionary engine without cache, a cold persistent cache and a reopened warm
cache. Candidates and SSID are synthetic; dictionary modes verify both WPA2
EAPOL and PMKID targets. All modes process the same number of candidates and use
the requested Rayon worker count. Baseline/optimized order alternates across
samples after warm-up; JSON retains individual durations and medians. Cold/warm
cache timing includes opening the cache, lookups, verification and any writes/
synchronization. **Warm-cache checks/s are not PBKDF2 derivations/s.**
Debug builds are labeled in the report; use release for performance comparisons.
CI checks benchmark execution and correctness, not a timing threshold.

WPA PBKDF2-HMAC-SHA1 still uses exactly 4096 rounds and outputs 32 bytes. The
specialization precompresses HMAC pads, fixes the repeated 20-byte message
padding, and interleaves the two independent PBKDF2 output-block chains. SHA-1
compression and hardware dispatch remain RustCrypto's implementation; no custom
SHA-1 round implementation or CPU-specific unsafe intrinsics are added. Generic
PBKDF2 remains available as the benchmark/differential baseline and for inputs
outside WPA's short password/salt shape. Dictionary MIC verification derives
only the 16-byte KCK; full PTKs remain in the decryption path.

`--threads 1..256` bounds a dedicated dictionary worker pool. Without it, existing
Rayon/environment defaults apply. Each candidate's PMK is still shared across all
targets for the selected SSID; `find_first` preserves dictionary order. Cache
lookup/write work happens outside parallel derivation, with no global lock around
PBKDF2. The 256-line batch bound remains in force; duplicate passphrases within
a cached batch share one derivation. A cached batch prepares the entire batch,
so cache statistics can include candidates after an early matching line.

The cache is disabled unless `--pmk-cache PATH` is given. `--pmk-cache-mib` is a
1..1024 MiB file budget (default 64), including a 64-byte versioned header and
four-way buckets of 128-byte slots. The sparse file never grows past its fixed
capacity; full buckets evict a deterministic slot. Existing files keep their
capacity and must fit the requested opening budget. There is no in-memory index
proportional to cache size and no full-file scan on startup. Different captures
or BSSIDs can reuse entries for the same exact SSID octets and passphrase.

Entries bind SHA-256 of algorithm/version, exact SSID and candidate to a PMK and
checksum. No plaintext passwords, SSIDs or dictionary positions are stored.
**PMKs are sensitive key material, and candidate hashes do not protect weak
passwords.** This is a trusted local cache, not an import format or encrypted
vault. Unix opens reject symlinks, other owners and group/other permissions;
new files use mode 0600. Other platforms rely on filesystem ACLs. An OS file lock
allows one process at a time and releases on close/crash; lock contention is an
explicit error. The recommended `.pmk-cache` extension is ignored by Git.

Torn/corrupt entries become misses and are recomputed. Invalid headers, wrong
file sizes, locking failures and I/O errors fail the run, rather than silently
reporting password-not-found or overwriting another format. Checksums detect
accidental corruption, not deliberate modification by someone with write access.
A failed/crashed initialization can leave an invalid file requiring explicit
removal/recreation. New entries are synchronized before advancing the batch's
checkpoint. Checkpoint **v5** remains unchanged: cache location and worker count
do not change verification semantics. Resume and stdin work with the cache;
stdin still cannot be checkpointed. Raw 64-hex PMKs bypass the cache, and SAE/
FT-SAE passphrases never become valid candidates through cached PBKDF2 output.
JNI benefits from the shared PBKDF2/KCK optimization but does not persist PMKs.

## Reproducible end-to-end example

```sh
cargo run -p air-cli -- aircrack \
  --capture tests/fixtures/wpa2-radiotap.pcap \
  --wordlist tests/fixtures/words.txt
```

Expected: `[+] found: correct horse battery`.

The checked-in synthetic fixtures use locally assigned addresses and a public
test passphrase. They are generated by `tests/fixtures/generate.py` using Python's
`hashlib`, `hmac` and `struct`, independently of the Rust code. Python is only
needed to regenerate fixtures; tests read the saved files directly. The tests
exercise all supported encapsulations through the library and actual CLI,
including wrong passwords/SSIDs, modified MICs, incomplete/mismatched sessions,
multiple networks, malformed inputs, and wordlist errors. Core tests include a
known WPA PMK vector and independently generated PMK/PTK/MIC vectors.

## Decrypt or strip a capture (`airdecap`)

```sh
# WPA2 CCMP-128 unicast data, using a known password and its SSID
./target/release/aircrack airdecap --input capture.pcap \
  --output decrypted.pcap --essid 'MySSID' --pass 'known-password'

# A raw 32-byte PMK (64 hex characters) needs no SSID
./target/release/aircrack airdecap --input capture.pcap --pmk HEX_PMK

# WEP40 (10 hex characters) or WEP104 (26 hex characters)
./target/release/aircrack airdecap --input legacy.pcap --wep-key HEX_WEP_KEY

# Strip 802.11 headers from an open-network capture
./target/release/aircrack airdecap --input open.pcap --bssid 02:00:00:00:00:01
```

Input accepts classic PCAP or pcapng raw 802.11/Radiotap; output is a new classic
nanosecond-resolution PCAP, default `<input stem>-dec.cap`, with Ethernet frames.
`--keep-wireless` / `-l` retains raw 802.11 instead (DLT 105), clearing Protected
on decoded data and removing Radiotap, padding, FCS and cipher headers/trailers.
`--bssid` optionally limits the network. `--pass`, `--pmk` and `--wep-key` are
mutually exclusive; `--pass` requires an explicit SSID. Both a normal passphrase
and raw 64-hex PSK are accepted by `--pass`. Avoid putting real credentials in
shared shell history/logs; decrypted captures contain plaintext network traffic.

CCMP/TKIP need an authenticated M1/M2, M2/M3, usable M3/M4 or supported FT reassociation in the same
capture. The handshake MIC is checked before deriving temporal keys; each CCMP
packet's 8-byte authentication tag must then verify. A PMKID alone cannot derive
a temporal key. Pairwise traffic uses key ID zero; multicast/broadcast From-DS traffic uses
GTKs recovered from authenticated M3 or group-rekey G1 messages. No extra flags
are needed to enable TKIP, GTK or descriptor v3. Mesh and aggregated/null data remain excluded; WDS is supported as described below; unicast fragment reassembly is described below.

TKIP derives a 64-byte SHA1 PTK with directional Michael keys. Each complete
MSDU must pass both CRC32 ICV and Michael MIC (including destination/source MACs
and QoS priority); a valid ICV alone is insufficient. A multicast MSDU sent
To-DS still uses its STA/AP pairwise key, since its receiver is the AP.

GTK recovery validates EAPOL MIC before decrypting Key Data: RSN messages use
RFC3394 AES key unwrap (v2/v3) or RC4-drop256 (v1), and WPA1 G1 uses the raw GTK
with its Key Information index. RSN GTK KDE lengths/control fields/padding are
validated. Keys are bound to AP and Key ID, retaining historical keys for rekeys
and same-ID reuse within the capture. GTK length selects CCMP-128 (16 bytes) or
TKIP (32 bytes) and must agree with the negotiated group cipher when known.
M3 must match the authenticated pairwise ANonce/replay epoch; group G1 must be
MIC-valid for that peer's PTK. Counters `gtk-installed` / `gtk-rejected` report
key recovery without disclosing key material.

Descriptor v3 supports **RSN type 2, negotiated PSK-SHA256 AKM 00:0f:ac:06 and
CCMP-128**: SHA256 KDF-384 derives KCK/KEK/TK, AES-CMAC authenticates EAPOL, and
CCMP verifies each data tag. An explicit, structurally valid M2 RSN IE is required;
missing/ambiguous AKM, legacy AKM2 with v3 and enterprise AKMs are rejected
rather than guessed from the descriptor version. FT and SAE use their separate
key derivation paths below. Descriptor v1/v2 keep the legacy
SHA1 PTK derivation. PMKID verification remains the existing SHA1/PSK AKM2 path;
PSK-SHA256 PMKID remains unsupported.

WEP uses the supplied key plus each packet IV and checks CRC32 ICV before output.
It does not discover WEP keys. Open data requires no credential. Ethernet conversion
accepts RFC1042/bridge-tunnel SNAP; non-SNAP payloads require `--keep-wireless`.
EAPOL/management packets, malformed/truncated frames and unsupported traffic are
omitted. Rejected protected frames are counted separately. No decoded data yields
a nonzero exit and no output file; mixed captures may yield a partial decoded
subset, with counters showing omissions. Captured retransmissions are preserved.

The streaming offline reader applies the configurable input work budgets above;
handshake extraction uses 1024 records/targets and temporal keys are capped at
64 authenticated pairwise key records per AP/client. GTKs are capped at 64
per AP/Key ID and 1024 total; encrypted Key Data is limited to 4096 bytes. The first streaming pass collects bounded key evidence; the second decrypts and
writes packets immediately, so data appearing before its handshake can also be decoded.
Both passes fingerprint all resolved records; a changed capture causes an error and
removal of the partial output. Output is exclusively
created with mode 0600 on Unix; existing files/symlinks and the input are never
overwritten. A normal write failure removes the newly created partial output;
a crash can leave it behind. Credential values are not included in error messages.

Timestamps are preserved, including pcapng decimal/binary `if_tsresol` and signed
`if_tsoffset`; pcapng Simple Packet Blocks have no timestamp and are written as
zero with `missing-timestamps` reported. Timestamps beyond classic PCAP's 32-bit
seconds range are rejected instead of wrapping. Packet input and decrypted output
are streamed; only bounded evidence, key sets and fragment chains are retained.

`tests/fixtures/generate_decap.py` builds independent public WPA1/CCMP/WEP fixtures
using Python stdlib plus the OpenSSL AES block primitive. Runtime decryption uses
RustCrypto (`aes`/`ccm`/`rc4`/`md-5`) and CRC32; it does not execute OpenSSL or
upstream airdecap. The generator is only needed to regenerate fixtures.

`tests/interop/compare_airdecap_ng.py` compares output packet bytes and timestamps
against an existing upstream 1.7 binary. The local macOS comparison ran **23 cases** (including M3/M4 and WDS):
ten output packet/timestamp results matched, including TKIP both directions and
ICV-negative cases. Explicit differences cover padded Radiotap, GTK/v3 coverage,
and the bad-Michael fixture: Rust rejects it while upstream 1.7 emits a packet.
These expected differences are recorded instead of being hidden as parity.
The bottle binary was relocated in `/tmp`, dependency paths updated to locally
installed libraries, and ad-hoc signed; no algorithm source was changed. This is
synthetic correctness evidence, not a performance or real-network qualification.
Upstream baseline: [airdecap-ng documentation](https://www.aircrack-ng.org/doku.php?id=airdecap-ng);
CCM reference: [RFC 3610](https://www.rfc-editor.org/rfc/rfc3610).

## FT personal roaming, SAE keys and fragment assembly

```sh
# FT-PSK: verify a dictionary against a signed reassociation with full FT context
./target/release/aircrack aircrack --capture roaming.pcap --essid MySSID \
  --wordlist words.txt

# FT-PSK data/GTK decryption; the same credentials select the FT hierarchy
./target/release/aircrack airdecap --input roaming.pcap --essid MySSID \
  --pass known-password --output roaming-dec.cap

# SAE: use an exported 32-byte PMK from your own authorized client/AP
./target/release/aircrack airdecap --input sae.pcap --pmk HEX_PMK \
  --output sae-dec.cap

# FT-SAE also requires the SSID for the FT-R0 hierarchy
./target/release/aircrack airdecap --input ft-sae.pcap --essid MySSID \
  --pmk HEX_ROOT_PMK --output ft-sae-dec.cap
```

**FT-PSK (AKM4) / FT-SAE (AKM9), CCMP-128:** signed reassociation requests
(transaction 5) and successful responses (transaction 6) provide RSN, Mobility
Domain and FT IEs. Captured context must include MDID, R0KH-ID, R1KH-ID, both
nonces and exactly one PMKR1Name. SHA256 FT-R0 → FT-R1 → FT-PTK derivation
checks PMKR1Name and the AES-CMAC FTIE MIC, binding STA/AP, transaction and signed
IEs. Response GTK subelements are unwrapped only after MIC verification.
The SSID and root XXKey/PMK are inputs; `--pmk` does not mean PMK-R0 or PMK-R1.
FT-PSK can verify normal passphrase candidates; FT-SAE can verify only exported
PMKs. This path requires complete key-holder context in a supported reassociation
IE set; it does not guess a missing R1KH-ID from the AP MAC. FT-EAP/SHA384, RIC,
RSNXE-extended FT MIC layouts, IGTK/BIGTK, and authentication/action-only FT captures
without a supported reassociation are outside this implementation.

**SAE (AKM8), CCMP-128, 32-byte PMK:** the post-SAE EAPOL exchange uses
AKM-defined descriptor version 0, SHA256 PTK derivation and AES-CMAC MIC. `airdecap`
can authenticate that handshake, recover GTK and decrypt data with an exported
PMK. It does not run the SAE PAKE, validate commit/confirm exchanges, derive the
SAE PMK from a password, or claim passive offline SAE password recovery. SAE/FT-SAE
passphrase candidates are rejected even if a contrived PMK happens to equal their
PBKDF2 output. The offline verifier accepts supplied 64-hex PMK candidate lines and
prints an explicit PMK requirement for SAE; JNI reports this limitation instead
of treating an ordinary password dictionary as a meaningful SAE password check.
GCMP/CCMP-256 and extended-PMK/SHA384 SAE AKMs are not supported.

**Fragment assembly:** plaintext management/data fragments are reconstructed before
SSID/EAPOL/FT parsing in CLI, JNI and survey. `decode_packet` / `parse_dot11` remain
stateless and deliberately reject fragments; embedding callers use `FrameDecoder`.
`airdecap` authenticates each encrypted MPDU first, then assembles a unicast MSDU;
CCMP tags and WEP/TKIP ICV are checked per fragment, TKIP Michael after assembly.
Receiver/transmitter, sequence, TID, remaining header fields, actual key fingerprint,
Protected state and Key ID must match, and encrypted PN/TSC values must be consecutive.
Conflicting duplicates or mismatched keys poison the chain; missing fragments never
produce partial output. Identical retries are deduplicated inside a pending chain.
Completed MSDU retransmissions may still appear as separate observations.

Limits are 256 chains, 16 fragments per chain, 65535 bytes per assembled frame,
4 MiB retained fragment/header bytes plus bounded metadata, and a two-second
capture-time window. Missing offline timestamps use zero logical time for
deterministic decoding; time expiry cannot be enforced on those records, but the
chain/byte caps still apply. Survey uses processing time. Output uses
fragment zero's timestamp and a normalized header with fragment/More-Fragments bits
cleared. Multicast-receiver fragmentation, A-MSDU, null data, mesh and protected
management decryption remain unsupported. Counters `reassembled`, `fragments-dropped`
and `fragments-pending` expose incomplete coverage. Offline capture timestamps and
original lengths are bound into version-5 checkpoint identities.

Survey adds an `FT` evidence marker and `FT` AP counter for structurally complete
FT records, including reconstructed management frames; this does not verify their
MIC or password. JSON AP rows add `ft`; CSV appends an `ft` column while retaining
existing columns. Reassembly and key lookup limits still apply to exported data.

`generate_roaming_fragments.py` independently generates public FT/SAE-PMK and
fragment vectors using Python stdlib/OpenSSL. `validate_roaming_fragments.py`
checks release packet bytes/timestamps and negative plaintext-output cases; CI runs
it alongside the existing upstream comparisons. These tests do not qualify real
radios, devices or complete SAE/FT interoperability. Key/MIC references:
[hostap common key hierarchy](https://raw.githubusercontent.com/vanhoefm/hostap-wpa3/master/src/common/wpa_common.c),
[hostap FT validation](https://raw.githubusercontent.com/vanhoefm/hostap-wpa3/master/src/rsn_supp/wpa_ft.c).

## M3/M4 and four-address WDS

`aircrack`, JNI, `wpaclean` and the survey `HS` indicator recognize M3/M4 with
matching radio endpoints, descriptor type/version and **equal replay counters**.
The M4 MIC is verified using M3 ANonce and a real captured SNonce. A standalone
M3/M4 pair needs a nonzero M4 SNonce and legacy descriptor v1/v2. A normal M4 with
zero nonce needs M2 from the preceding replay counter; the M2 MIC may be bad,
because M4 is the MIC target and M2 supplies nonce/negotiation context. No nonce
is guessed. The M4 classification requires Pairwise/MIC/Secure and no Key Data;
ambiguous WPA1 M2/M4 without Secure is not newly classified as M4.

Descriptor v0/v3 M4 targets additionally require M2's explicit supported AKM/cipher
profile. SAE still accepts exported PMKs only, even if a supplied PMK happens to
coincide with PBKDF2(password). M3/M4-derived PTKs also work in `airdecap`.
Survey JSON adds `handshake_m3m4`; CSV appends it after `ft`, keeping previous
column positions. Indicators remain structural, not MIC authentication.

Four-address WDS uses **RA/TA for the radio link**, **DA=Address3 / SA=Address4**
for Ethernet and Michael, and QoS control at offset 30 (plus optional HT control).
WDS EAPOL identifies the authenticator with ACK and derives PTKs from the radio
peers. Ordinary WDS data has no BSSID: `airdecap` tries only authenticated keys
for that exact RA/TA pair, in both authenticator orientations. It does not scan
unrelated keys or use bridged hosts as PTK peers. `--bssid` on WDS data matches a
radio endpoint; key collection still applies the authenticated AP selection.

CCMP AAD includes Address4 and QoS TID. TKIP uses the directional Michael key
and bridged DA/SA; WEP and open frames use the same address mapping. Logical
multicast DA with unicast RA uses the link PTK. WDS multicast RA/GTK selection is
not inferred. Clear/encrypted unicast WDS fragments retain the same size/time/
key/PN limits, with Address4 bound to the chain. Radiotap padding is computed
from the complete 30/32/36-byte header. Raw output preserves Address4.
Survey does not invent AP/client relationships for ordinary WDS data; supported
WDS EAPOL can provide verification evidence. Mesh, A-MSDU and protected management
remain outside this WDS implementation. Validation uses synthetic offline captures,
not device/radio interoperability qualification.

## Clean verification captures (`wpaclean`)

```sh
./target/release/aircrack wpaclean --input large.pcapng --output evidence.cap
./target/release/aircrack wpaclean -i large.pcap -o selected.cap --bssid 02:00:00:00:00:01
./target/release/aircrack aircrack --capture evidence.cap --wordlist words.txt
```

The cleaner scans the entire input and retains one matching M1/M2, M2/M3 or usable M3/M4 pair
per supported verification target, FT personal reassociation evidence, legacy
PMKID evidence, and distinct SSID advertisements for the retained networks.
It removes unrelated data, duplicate evidence and incomplete exchanges. Conflicting
SSID advertisements remain visible rather than silently choosing a password salt.
Without credentials this is a **structural** check; a retained MIC is not proof
of a valid handshake. SAE/FT-SAE targets still require exported PMKs.

Output is a new mode-0600 **nanosecond PCAP with raw 802.11 DLT 105**.
Radiotap padding/FCS are removed and clear fragments are reassembled, with the
fragment-zero timestamp. Ethernet EAPOL uses the existing synthetic infrastructure
header normalization; it does not provide radio metadata or an SSID. Unknown
PCAPng SPB timestamps become zero and are counted in `missing-timestamps`.
The output preserves supported verification targets, not a forensic byte-for-byte
capture or all data/GTK rekey exchanges needed for decryption.

Acceptance tests cover captures beyond the old 64 MiB / 100000-packet limits,
normalized link types and fragments, retained FT/SAE-PMK/PMKID targets, BSSID
selection, conflicting SSIDs, bad MICs, idempotence and exclusive output.
`tests/interop/validate_streaming.py` reproduces large-file checks and records
observed peak RSS where `wait4` is available. On this Mac, synthetic 68 MiB and
273 MiB inputs each cleaned to 408 bytes, with about 10.5 MiB peak RSS; this is
an observation for that workload, not an enforced process-memory ceiling.

Malformed containers, exceeded budgets, no usable targets, or an unrepresentable
output timestamp fail without publishing a successful partial capture. Existing
files, symlinks and the input are never overwritten. Normal failures remove the
new output; a crash can leave a partial file. This CLI uses `-i/-o` options and is
not a drop-in replacement for upstream wpaclean's positional interface.

## Current boundaries

WEP key recovery, SAE PAKE/password recovery, FT-EAP/SHA384,
aggregated data, mesh, Prism and injection are not implemented. M3/M4 and WDS
support has the explicit nonce, negotiation and radio-peer limits described above.
`airmon`, `aireplay`, `airbase`, `packetforge` and `ivstools` return explicit unsupported-operation errors. `tui` remains the legacy UI demo; the working passive dashboard is `survey`.

## Workspace

- `air-core`: PMK/PTK/MIC primitives.
- `air-frames`: 802.11 headers and SSID information elements.
- `air-capture`: pcap/pcapng normalization plus streaming survey metadata and bounded AP/client inventory.
- `air-handshake`: FT personal reassociation and WPA/WPA2/SAE descriptor v0/v1/v2/v3 M1/M2, M2/M3 and M3/M4 sessions; M1 KDE and association RSN PMKID targets.
- `air-crack`: parallel candidate verification and streaming dictionaries.
- `air-platform`: bounded tcpdump runner, survey filters, passive channel control and child cleanup.
- `air-cli`: live/shadow capture management, capture inspection and dictionary verification.
- `air-tui`: survey dashboard plus the legacy UI demonstration.
- `air-jni`: bounded offline Android adapter, progress and cancellation.

See [implemented architecture and resource limits](ARCHITECTURE.md),
[audit findings](docs/AUDIT.md), [development checks](CONTRIBUTING.md), and
[security boundaries](SECURITY.md). CI defines format, strict Clippy, tests and
release builds on Linux/macOS/Windows; hosted results have not been verified here.

## Differential tests against upstream 1.7

The checked-in [comparison script](tests/interop/compare_aircrack_ng.py) requires
an existing aircrack-ng **1.7** executable and a built Rust release binary:

```sh
cargo build -p air-cli --release --locked
python3 tests/interop/compare_aircrack_ng.py \
  --upstream /path/to/aircrack-ng --rust target/release/aircrack \
  --report target/interop.json
```

The script runs only public synthetic captures, with a 30-second subprocess limit.
It distinguishes found, not-found, no supported target and execution errors.
All 20 common cases agreed locally (including WPA1/WPA2 M3/M4 and PSK-SHA256 v3 M1/M2 and M2/M3). Four additional association/reassociation RSN
cases record a deliberate capability difference: Rust verifies those records,
while upstream 1.7's PCAP path reports no EAPOL data. These are correctness tests,
not a speed benchmark or a claim of full upstream compatibility.

The advanced fixtures (`generate_advanced.py`) independently build TKIP/Michael,
AES-wrapped/RC4 GTK deliveries, rekeys and PSK-SHA256 v3 captures using Python
stdlib/OpenSSL. Rust vectors include RFC4493 CMAC and RFC3394 unwrap known answers.
Protocol references: [hostap key derivation/MIC rules](https://raw.githubusercontent.com/vanhoefm/hostap-wpa3/master/src/common/wpa_common.c),
[Linux TKIP implementation as a wire-format reference](https://raw.githubusercontent.com/torvalds/linux/master/net/mac80211/tkip.c).
TKIP's substitution table is generated algebraically; the runtime does not invoke
an upstream program. No real-network, reassembly, anti-replay or device qualification
is implied by these offline synthetic tests.


### Passive security audit and capture diagnostics

`survey --read capture.pcapng --export-json audit.json --export-csv audit.csv`
uses the same audit as live survey. It reports the last valid unfragmented
beacon or probe response for each BSSID: advertised RSN/WPA group and pairwise
cipher selectors, AKMs, RSN capabilities and PMF state, group-management cipher,
and RSNXE bytes/SAE flags. Unknown selectors retain their wire identifiers.
The audit flags observed legacy ciphers/WPA, transition mode, PMF settings and
other inconsistencies; these are observations of unauthenticated advertisements,
not proof of negotiated security or vulnerabilities. Omitted fields remain
unknown. A later malformed advertisement marks the current audit unknown; JSON
retains the earlier `last_valid` with its source and record number. A changed
advertisement is flagged, but does not by itself prove an attack.

JSON `capture_quality` describes all input records, before BSSID filtering:
truncated records, invalid record lengths, Radiotap errors and driver-reported
bad FCS, presence/absence/unknown FCS metadata, missing timestamps and timestamp
regressions. Truncated and bad-FCS records are not used for inventory or audit.
Per-AP diagnostics count retry-bit and fragmented data frames, supported EAPOL
message types, unparsed EAPOL-Key messages, zero-nonce M4, and disagreements
between advertised and capture channels when both are known. Counts are per
BSSID and may describe different clients and exchanges; retry counts do not
measure loss, and FCS flags are driver reports rather than checksum validation.
`HS`, `FT` and `PMKID` are structural evidence only; neither a password nor a
MIC is verified by survey. FCS, channel and timestamp metadata may be absent;
no observation is treated as proof a frame or network property does not exist.
The JSON changes are additive to schema version 1; CSV keeps existing columns in
place and appends the audit and per-AP counters. JSON contains the full details.


The audit also exports `current_assessment` for a valid latest advertisement,
with an advertised mode and findings containing stable IDs, severity,
observed evidence and practical recommendations. When the latest advertisement
is malformed, `current_assessment` is null; the older `last_valid` is retained
only for context. CSV appends the advertised mode, finding IDs and recommendations.
The same advice is printed in plain mode. A lack of findings is not a security
certification: only advertised fields in the captured frame are examined.

SAE+PSK transition mode is identified as a compatibility tradeoff; optional PMF
in that mode is not classified as a configuration error. An SAE or OWE
advertisement without PMF capability is flagged for review, and optional PMF
outside SAE+PSK transition prompts a compatibility-aware recommendation. OWE
provides opportunistic encryption, not AP authentication. The OWE transition
vendor element exposes an *advertised* peer BSSID and SSID in hexadecimal; the
survey does not confirm the peer's existence, link the two BSSes, or assume that
clients select the encrypted BSS. Unknown selectors and omitted fields are
reported as unknown, not as failures or passes. Rules are informed by
[RFC 8110](https://www.rfc-editor.org/rfc/rfc8110), the
[hostapd configuration](https://chromium.googlesource.com/chromiumos/third_party/hostap/+/d43eb71da79f5d92931ed5cde5c62b6ccc17d04b/hostapd/hostapd.conf),
and the [wpa_supplicant SAE/PMF configuration notes](https://github.com/greearb/hostap-ct/blob/master/wpa_supplicant/wpa_supplicant.conf).


### 6 GHz and Reduced Neighbor Reports

Offline survey identifies 2.4/5/6 GHz from the received Radiotap frequency,
including 5935 MHz (6 GHz channel 2). Direct observations in JSON carry frame
kind, input record index, optional capture time and observed radio. An advertised
channel without a known band is not assigned a band. Channel numbers overlap;
use the band and MHz together.

RNR (IE 201) entries are exported separately as `rnr_neighbors` in JSON and
`rnr` rows in CSV. Each entry records its reporting BSSID, record and timestamp,
operating class, advertised channel and any BSSID/short SSID fields present in a
recognized TBTT layout. A reported neighbor is not proof of its reachability,
SSID, security, or identity; `directly_observed` reports whether a direct frame
for that BSSID exists in the current inventory. The advertised operating-class
channel can denote a wider-channel center. Unknown types are not interpreted;
malformed elements increment `malformed_rnr_elements` without contributing
partial neighbor records. Neighbor inventory is bounded, expires with survey
rows, and reports evictions. BSSID filtering selects the reporting AP; its RNR
may contain other BSSIDs.

On Linux with an existing monitor interface, `--list-channels` includes
adapter-reported frequencies. `--frequency 5955` holds an exact frequency;
`--frequencies 5955,5975` hops only among reported, enabled frequencies.
Existing `--channel`/`--channels` remain 2.4/5 GHz only. Frequency tuning is
not yet available through the macOS CoreWLAN helper. Driver, adapter and
regulatory restrictions still apply; live 6 GHz tuning has not been hardware
validated in this project. Parsing follows the Linux
[802.11 RNR structures](https://github.com/torvalds/linux/blob/master/include/linux/ieee80211.h)
and [RNR iteration](https://github.com/torvalds/linux/blob/master/net/wireless/scan.c).
