#!/usr/bin/env bash
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
export ANDROID_HOME="${ANDROID_HOME:-${ANDROID_SDK_ROOT:-$HOME/Library/Android/sdk}}"
NDK="${ANDROID_NDK_HOME:-$ANDROID_HOME/ndk/28.2.13676358}"
case "$(uname -s)" in Darwin) HOST=darwin-x86_64;; Linux) HOST=linux-x86_64;; *) echo 'Use macOS or Linux with Android NDK' >&2; exit 1;; esac
BIN="$NDK/toolchains/llvm/prebuilt/$HOST/bin"
[[ -x "$BIN/aarch64-linux-android26-clang" ]] || { echo "NDK not found: $NDK" >&2; exit 1; }
export CARGO_TARGET_AARCH64_LINUX_ANDROID_LINKER="$BIN/aarch64-linux-android26-clang"
export CARGO_TARGET_X86_64_LINUX_ANDROID_LINKER="$BIN/x86_64-linux-android26-clang"
cargo build --manifest-path "$ROOT/Cargo.toml" -p air-jni --release --locked --target aarch64-linux-android --target x86_64-linux-android
for pair in 'aarch64-linux-android arm64-v8a' 'x86_64-linux-android x86_64'; do
    read -r target abi <<< "$pair"
    mkdir -p "$ROOT/android/app/src/main/jniLibs/$abi"
    cp "${CARGO_TARGET_DIR:-$ROOT/target}/$target/release/libair_jni.so" "$ROOT/android/app/src/main/jniLibs/$abi/"
done
"$ROOT/android/gradlew" -p "$ROOT/android" --no-daemon assembleDebug lintDebug "$@"
