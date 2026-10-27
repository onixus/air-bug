#!/usr/bin/env bash
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cargo build --manifest-path "$ROOT/Cargo.toml" -p air-jni --release --locked
mkdir -p "$ROOT/android/build/host-jni"
javac -d "$ROOT/android/build/host-jni" "$ROOT/android/app/src/main/java/dev/onixus/aircrack/NativeBridge.java" "$ROOT/android/tests/HostJniSmoke.java"
java -Djava.library.path="${CARGO_TARGET_DIR:-$ROOT/target}/release" -cp "$ROOT/android/build/host-jni" dev.onixus.aircrack.HostJniSmoke "$ROOT"
