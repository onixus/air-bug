# CLI machine contract (schema version 1)

`aircrack aircrack`, `aircrack airdecap` and `aircrack survey` use the following stable process
exit codes, with or without diagnostic output:

| Code | `exit_category` | Meaning |
| --- | --- | --- |
| 0 | `success` | Inspection, verification or decoding completed |
| 2 | `password_not_found` | Verification exhausted the supplied dictionaries |
| 3 | `no_supported_target` | No supported verification target, authenticated handshake for the supplied key, or decodable data |
| 4 | `bad_container` | Malformed, truncated or unsupported capture/container/link type |
| 5 | `privilege_or_device` | Cannot access an input, output or device |
| 6 | `partial` | Verification paused by candidate limit or handled SIGINT/SIGTERM |
| 64 | `usage` | Invalid arguments/configuration or wordlist input, or diagnostic path cannot be reserved |
| 70 | `internal` | Unexpected operation failure or diagnostic write failure |

Request a summary file with `--diagnostic-json PATH` (alias `--json PATH`):

```sh
aircrack aircrack --capture authorized.pcap --wordlist words.txt --json verify.json
aircrack airdecap --input authorized-open.pcap --output decoded.pcap --json decode.json
aircrack survey --read authorized.pcap --plain --json survey.json
```

The diagnostic is a separate file; existing human stdout/stderr and explicit
credential-bearing `--results-json` output retain their behavior. Diagnostics
never include passwords, PMKs, WEP keys, candidates, input paths or raw error
chains. `error` contains a generic category-specific explanation on failure and
`null` on success. Detailed errors remain on stderr.

Fields are `schema_version` (integer 1), `command` (`aircrack`, `airdecap` or `survey`),
`kind` (`aircrack_diagnostic`, `airdecap_diagnostic` or `survey_diagnostic`), `exit_category`, `exit_code`, `counts` and `error`. Consumers should
reject unknown schema major versions and allow additive fields. Help/version
requests retain clap's normal behavior and do not create diagnostics.

`aircrack` counts: `packets`, `parsed_frames`, `skipped_frames`, `networks`,
`handshake_sessions`, `pmkid_targets`. These describe discovered evidence, not
recovered credentials. `airdecap` counts: `data_frames`, `decrypted`, `rejected`,
`skipped`, `missing_timestamps`, `gtk_installed`, `gtk_rejected`. A successful
open-traffic decode can have `decrypted: 0`.

Counts reflect completed observation phases, including dictionary exhaustion
and a completed decode pass that yielded no output. Counts unavailable before
those phases complete are zero; argument parsing failures have `counts: {}`.
A failed decode never commits its partial PCAP output.

The summary path is reserved before work, using exclusive creation and mode
0600 on Unix. Existing files (including input/output collisions and symlinks)
are never overwritten. Reservation failure returns 64 without starting work;
no diagnostic can be written to that path. A final write/sync failure returns
70; consumers must reject incomplete JSON. Abrupt process termination is not
guaranteed to produce a summary.

`aircrack` also includes a top-level `verification` field, without credentials:

| Value | Meaning |
| --- | --- |
| `found` | All selected networks were successfully verified |
| `not_found` | Dictionaries exhausted before all selected networks were verified |
| `not_attempted` | Inspection only, or failure before verification began (including argument parsing) |
| `partial` | Verification started but did not finish (pause, interruption or execution failure) |

For multiple networks, `not_found` and `partial` may include some matches;
they do not assert that no network matched. Use explicit `--results-json` for
per-network results; that file contains credentials and requires separate handling.
A pause preserves completed checkpoints when `--session`/`--resume` is used.
Cache failures are execution failures (`internal`, 70), never usage errors.
Missing capture files remain `privilege_or_device` (5); missing or unreadable
wordlists and invalid dictionary encoding are bad input (`usage`, 64).
Resource/capture limits currently use `usage` (64).

Survey supports both `--diagnostic-json` and `--json`, including on argument
errors when a destination can be recovered. It uses the same redaction,
reservation and final-write rules as the offline commands. Export collisions
(`--export-json`, `--export-csv`) return `privilege_or_device` (5), preserving
the existing file. Its `counts` fields are `access_points`, `clients`, `packets`,
`handshakes` (APs with any supported handshake evidence), and `pmkid` (APs with
PMKID evidence). Survey success includes offline inspection or channel listing;
it does not imply credential verification. Survey failures currently have zero
counts; clap argument failures have an empty counts object. There is no
`verification` field for survey or airdecap.

On Windows diagnostics inherit directory ACLs; use a private output directory.
Other subcommands are outside this contract and may return 1 or clap's 2.
