# Security boundaries

This experimental project is for authorized passive capture and offline Wi-Fi analysis. It has not received a formal security or cryptographic audit.

- Capture/process only networks you are authorized to inspect. Offline analysis requires no elevated privileges; live capture requires tcpdump and OS capture permissions. The program never escalates itself or changes BPF permissions.
- Live/shadow require an exact nonzero unicast MAC, duration and packet limits. Monitor filtering is DS-aware BSSID filtering; default non-monitor mode filters EAPOL Ethernet endpoints, which cannot establish BSSID identity. The separate `survey` command intentionally supports broad passive AP/client discovery and channel hopping; injection and deauth are not implemented.
- Monitor mode is explicit and may disrupt this machine's Wi-Fi connection. Use a dedicated adapter. Zero packets/absent handshake do not prove a network is secure.
- Capture files use exclusive creation (0600); session directories use 0700 on Unix. No disk rotation is implemented. Shadow exposes start/status/stop and never installs persistence. Use stop for finalization; SIGKILL, process crashes, machine suspension or loss of the supervisor can defeat graceful cleanup and timing. There is no absolute orphan-proof guarantee.
- Survey uses bounded streaming and capped/expiring tables; terminal SSID bytes are escaped. Its capture/log files are private and exclusively created. The offline verification path loads captures and decoded frames into memory; handshake candidates are not resource-bounded. Untrusted large/pathological captures can exhaust memory or CPU. Do not expose the CLI as a public upload service without external isolation and limits.
- Wordlists are streamed with a 64 KiB per-line limit. Read/encoding/length failures are fatal.
- Found passphrases are printed to stdout. Treat output and shell/CI logs as sensitive. Secret zeroization is not guaranteed.
- Unsupported legacy commands fail without injection or interface changes. Live/shadow/airodump are passive capture operations and must only be launched intentionally.
- On macOS, `survey` refuses associated/unknown interface mode before capture. It never disassociates or toggles Wi-Fi power; use a dedicated unassociated adapter. Zero-packet surveys report failure to verify reception.
- `survey` is the operational passive dashboard; the legacy `tui` command remains a preview. Survey checks adapter-supported 2.4/5 GHz channels, never actively scans or forcibly disassociates, and attempts to restore the original primary channel when known. It does not restore bandwidth or association.

When reporting a vulnerability, include the affected version/toolchain, minimal sanitized reproducer, expected behavior and observed error. Do not attach private captures, real passwords or identifying network information to a public issue. No dedicated private reporting channel has been configured in this repository; arrange a private channel with its maintainer before sharing sensitive details.

## Ordinary macOS discovery

`scan` uses a separate CoreWLAN companion to perform an ordinary OS scan or read
its cache. It never opens a capture device or invokes channel/association/power
controls. It can operate while associated; OS scans may send probe requests and
cause brief latency. The optional `--request-location` invokes native consent
only on explicit request. No coordinates are requested and no results are uploaded.
Identifiers restricted by macOS remain restricted; no elevated-privilege workaround
is attempted. All network strings are escaped before terminal output. Scan results
and stdout still contain identifying network data when permission is available.
