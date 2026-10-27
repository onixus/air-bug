#!/usr/bin/env python3
"""Public synthetic large-capture acceptance and observed RSS (where available)."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import struct
import subprocess
import sys
import tempfile


def run(command):
    process = subprocess.Popen(command, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    rss = None
    if hasattr(os, "wait4"):
        _, status, usage = os.wait4(process.pid, 0)
        process.returncode = os.waitstatus_to_exitcode(status)
        rss = usage.ru_maxrss * (1 if sys.platform == "darwin" else 1024)
        stdout = process.stdout.read().decode(errors="replace")
        stderr = process.stderr.read().decode(errors="replace")
        process.stdout.close()
        process.stderr.close()
    else:
        stdout, stderr = process.communicate()
        stdout, stderr = stdout.decode(errors="replace"), stderr.decode(errors="replace")
    if process.returncode:
        raise RuntimeError(f"{command[1]} failed: {stderr}")
    return stdout, rss


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--rust", required=True)
    parser.add_argument("--report", required=True)
    args = parser.parse_args()
    binary = str(Path(args.rust).resolve())
    fixtures = Path(__file__).resolve().parents[1] / "fixtures"
    source = (fixtures / "wpa2-raw.pcap").read_bytes()
    noise = bytearray(700)
    struct.pack_into("<H", noise, 0, 0x0208)
    for offset, suffix in [(4, 2), (10, 1), (16, 3)]:
        noise[offset:offset + 6] = bytes([2, 0, 0, 0, 0, suffix])
    record = struct.pack("<IIII", 0, 0, 700, 700) + noise
    results = []
    with tempfile.TemporaryDirectory(prefix="air-streaming-") as folder:
        for count in [100001, 400004]:
            path = Path(folder) / f"{count}.cap"
            output = Path(folder) / f"{count}-clean.cap"
            with path.open("wb") as file:
                file.write(source[:24])
                batch = record * 1024
                for _ in range(count // 1024):
                    file.write(batch)
                file.write(record * (count % 1024))
                file.write(source[24:])
            summary, rss = run([binary, "wpaclean", "-i", str(path), "-o", str(output)])
            verified, _ = run([binary, "aircrack", "--capture", str(output),
                               "--wordlist", str(fixtures / "words.txt")])
            size = output.stat().st_size
            ok = size < 1024 and "into 3 records; targets=1" in summary and "[+] found:" in verified
            results.append({"input_bytes": path.stat().st_size, "noise_packets": count,
                            "output_bytes": size, "observed_peak_rss_bytes": rss, "ok": ok})
            print(f"{count} noise packets: {'PASS' if ok else 'FAIL'}; output={size} RSS={rss}")
    failures = [case for case in results if not case["ok"]]
    report = {"schema_version": 1, "rust_sha256": hashlib.sha256(Path(binary).read_bytes()).hexdigest(),
              "scope": "synthetic capture size scaling; RSS observed, not an enforced budget or speed benchmark",
              "cases": results, "failures": failures}
    Path(args.report).write_text(json.dumps(report, indent=2) + "\n")
    return bool(failures)


if __name__ == "__main__":
    sys.exit(main())
