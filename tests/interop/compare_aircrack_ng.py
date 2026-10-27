#!/usr/bin/env python3
"""Offline differential test against aircrack-ng 1.7; public synthetic inputs only.

No downloads, installations, radio devices or shell commands are performed here.
A subprocess error/timeout is NOT classified as a password mismatch.
"""
import argparse
import hashlib
import json
import os
from pathlib import Path
import platform
import re
import subprocess
import sys

ROOT = Path(__file__).resolve().parents[2]
FIXTURES = ROOT / 'tests/fixtures'
PASSWORD = 'correct horse battery'


def digest(path):
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()


def main():
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument('--upstream', required=True, type=Path)
    ap.add_argument('--rust', required=True, type=Path)
    ap.add_argument('--upstream-library-path', type=Path, help='optional directory for a relocated macOS bottle')
    ap.add_argument('--report', type=Path, required=True)
    args = ap.parse_args()
    upstream, rust = args.upstream.resolve(strict=True), args.rust.resolve(strict=True)
    env = dict(os.environ, LC_ALL='C')
    if args.upstream_library_path:
        env['DYLD_LIBRARY_PATH'] = str(args.upstream_library_path.resolve(strict=True))
    try:
        version = subprocess.run([str(upstream), '--help'], env=env, text=True,
                                 stdout=subprocess.PIPE, stderr=subprocess.STDOUT, timeout=15)
    except (OSError, subprocess.TimeoutExpired) as error:
        raise SystemExit(f'Cannot execute original aircrack-ng: {error}') from error
    if version.returncode != 0 or not re.search(r'Aircrack-ng 1\.7(?:\s|$)', version.stdout):
        raise SystemExit(f'Expected working upstream 1.7, got:\n{version.stdout}')
    cases = []
    for stem in ['wpa2-m1m2-compat', 'wpa2-m2m3', 'wpa2-pmkid', 'wpa1-m1m2', 'wpa1-m2m3', 'wpa2-v3', 'wpa2-v3-m2m3', 'wpa2-m3m4', 'wpa1-m3m4']:
        for words, expected in [('words.txt', 'found'), ('wrong-words.txt', 'not_found')]:
            cases.append((stem + '.pcap', words, expected, expected))
    for stem in ['wpa2-m2m3-bad-mic', 'wpa2-pmkid-bad-id']:
        cases.append((stem + '.pcap', 'words.txt', 'not_found', 'not_found'))
    # Upstream 1.7's PCAP PMKID extractor reads M1 KDEs, not assoc RSN lists.
    # Keep these differences explicit instead of pretending unsupported == no match.
    for stem in ['wpa2-pmkid-assoc', 'wpa2-pmkid-reassoc']:
        for words, expected in [('words.txt', 'found'), ('wrong-words.txt', 'not_found')]:
            cases.append((stem + '.pcap', words, expected, 'no_target'))
    rows = []
    failures = []
    for capture, words, rust_expected, upstream_expected in cases:
        base = ['-q', '-a', '2', '-p', '1', '-b', '02:00:00:00:00:01', '-e', 'Test Network',
                '-w', str(FIXTURES / words), str(FIXTURES / capture)]
        commands = {
            'upstream': [str(upstream), *base],
            'rust': [str(rust), 'aircrack', '--capture', str(FIXTURES / capture),
                     '--essid', 'Test Network', '--bssid', '02:00:00:00:00:01',
                     '--wordlist', str(FIXTURES / words)],
        }
        row = {'capture': capture, 'capture_sha256': digest(FIXTURES / capture),
               'wordlist': words, 'wordlist_sha256': digest(FIXTURES / words)}
        for impl, command in commands.items():
            try:
                result = subprocess.run(command, env=env, text=True, stdout=subprocess.PIPE,
                                        stderr=subprocess.STDOUT, timeout=30)
                output, code = result.stdout, result.returncode
                if impl == 'upstream' and capture in ('wpa2-v3.pcap', 'wpa2-v3-m2m3.pcap') and code == 1 and 'OMAC1 is only supported when OpenSSL (or similar) supports CMAC.' in output:
                    status = 'unsupported'
                elif code == 0 and (f'KEY FOUND! [ {PASSWORD} ]' in output if impl == 'upstream'
                                  else f'[+] found: {PASSWORD}' in output):
                    status = 'found'
                elif code == 1 and ('KEY NOT FOUND' in output if impl == 'upstream'
                                    else 'password not found in wordlist' in output):
                    status = 'not_found'
                elif code == 1 and ('Packets contained no EAPOL data' in output if impl == 'upstream'
                                    else 'no complete WPA2' in output):
                    status = 'no_target'
                else:
                    status = 'error'
            except (OSError, subprocess.TimeoutExpired) as error:
                output, code, status = str(error), None, 'error'
            expected = upstream_expected if impl == 'upstream' else rust_expected
            # Some upstream 1.7 builds explicitly report they lack CMAC. Keep
            # the diagnostic visible; do not call it a password mismatch.
            if impl == 'upstream' and status == 'unsupported':
                expected = 'unsupported'
            row[impl] = {'status': status, 'expected': expected, 'exit_code': code,
                         'output': re.sub(r'\x1b\[[0-9;]*[A-Za-z]', '', output),
                         'command': command}
            if status != expected:
                failures.append(f'{capture} / {words} / {impl}: {status}, expected {expected}')
        row['same_result'] = row['rust']['status'] == row['upstream']['status']
        rows.append(row)
        print(f'{capture:32} {words:16} rust={row["rust"]["status"]:9} upstream={row["upstream"]["status"]}')
    report = {'schema_version': 1, 'platform': platform.platform(),
              'upstream_version': '1.7', 'upstream_sha256': digest(upstream),
              'rust_sha256': digest(rust), 'cases': rows, 'failures': failures,
              'scope': 'synthetic correctness only; no performance or radio acceptance'}
    args.report.parent.mkdir(parents=True, exist_ok=True)
    args.report.write_text(json.dumps(report, indent=2) + '\n')
    if failures:
        print('\n'.join(failures), file=sys.stderr)
        return 1
    print(f'PASS: {len(rows)} cases; {sum(row["same_result"] for row in rows)} equal results; expected unsupported cases recorded.')
    return 0


if __name__ == '__main__':
    sys.exit(main())
