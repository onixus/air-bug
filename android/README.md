# Aircrack Android · Apex

Native Android 8.0+ (API 26) shell around the existing Rust offline pipeline. Universal APK: **arm64-v8a + x86_64**. No 32-bit ARM support.

## Build

Requires Java 17+, Rust with Android targets, Android SDK platform 36, NDK 28.2.13676358, and network access on the **build machine** for Gradle/Cargo dependencies. The application has **no network permission**.

```sh
rustup target add aarch64-linux-android x86_64-linux-android
export JAVA_HOME=/path/to/jdk17
export ANDROID_HOME=/path/to/Android/sdk
export ANDROID_NDK_HOME="$ANDROID_HOME/ndk/28.2.13676358"
bash android/build-android.sh
adb install -r android/app/build/outputs/apk/debug/app-debug.apk
```

The output is a **debug-signed testing APK**, not a Play Store release. A production release requires a private signing key and device acceptance testing; no release key is committed. Native ELF segments are 16 KiB-aligned (NDK r28 / current Rust), and AGP handles APK alignment.

The pinned [Gradle wrapper](<gradle/wrapper/gradle-wrapper.properties>) is included. The [build script](<build-android.sh>) compiles Rust in release mode for both ABIs, copies the libraries and runs `assembleDebug lintDebug`; desktop protocol implementations are not forked or modified. Run the script after changing Rust: invoking Gradle alone does **not** rebuild JNI libraries.

## Use

1. Import a PCAP/PCAPNG through Android's document picker, or load the synthetic training example.
2. Confirm written owner authorization or engagement scope for every network in the capture. The app states this in its footer and never prompts interactively; keeping the scope is the operator's responsibility.
3. Without a dictionary, analyze the capture. The report lists BSSIDs, SSIDs and supported M1/M2, M2/M3 and PMKID records.
4. Tap a network to select its BSSID; enter SSID explicitly if missing or ambiguous. Original SSID bytes are preserved internally; lossy display text is never silently reused for verification.
5. Optionally import a UTF-8 wordlist, then verify. A matched passphrase is hidden until explicitly revealed.

The bundled training capture and wordlist are public synthetic fixtures, not real credentials. All processing occurs locally. There is no live/monitor capture, root requirement, injection, deauthentication, WEP or WPA3 verification.

### Safety boundaries

- Copies are bounded during SAF streaming: capture **4 MiB**, dictionary **16 MiB**. Only app-private cache paths reach JNI; no external filesystem permissions or persisted URI grants.
- Adapter rejects more than **32,768 packets** or **128 combined supported EAPOL/PMKID records (M1 carrying a PMKID counts in both categories)**, the latter **before** handshake extraction can form a Cartesian product. The container parser still reads the bounded capture as a whole; this is not a general-purpose sandbox for hostile input.
- One process-wide worker serializes I/O and native jobs. `control(0)` executes on that worker immediately before `run`, so an old Activity cannot have its cancellation reset by a new concurrent job. Each Activity owns unique cache files; queued cleanup occurs after I/O. Abandoned-process files are removed on the next process start.
- Cancellation is polled between packets, dictionary entries and PBKDF2 calls; an in-progress PBKDF2/container read is not forcibly interrupted. Leaving the foreground requests cancellation.
- Both JNI exports catch Rust unwinding panics. OOM/OS process termination is not recoverable through `catch_unwind`.
- No logs of capture data/passphrases, no backup, no Internet permission, no clipboard copying. `FLAG_SECURE` blocks screenshots/recents. Passphrase strings cannot be reliably zeroized in the Java heap; don't use a compromised/rooted device for sensitive audits.

## Apex #117 mapping

Source: [Apex design-system requirements](https://github.com/onixus/unified-platform/issues/117).

- Native Java Views, not a web wrapper. [ApexTokens](<app/src/main/java/dev/onixus/aircrack/ApexTokens.java>) is the single literal color table pending an upstream native token package.
- Dark/light/system preference `apex.theme`, resolved before the Activity content is constructed. Native system bars/insets; mobile header 56dp, 4dp spacing grid, radius 12dp, 48dp touch controls. Desktop sidebar is not rendered on mobile.
- Local Inter and JetBrains Mono; 24/18/14/13/12/11sp type scale. Overlines are uppercase mono; no text below 11sp. Lucide-derived stroke icons use 20/24dp.
- One sky accent and one primary action. Status = icon + word + subtle surface. Focus/pressed ring 2dp. No custom motion, hence nothing to disable under reduced-motion settings. No export feature in this MVP.
- [Apex check](<tests/check_apex.py>) rejects literal component colors and verifies WCAG ratios for rendered token pairs: text ≥4.5:1, control/focus ≥3:1. Status tints use 6% rather than 8%: amber text on the light 8% tint measured 4.498:1 and failed the threshold.
- Inter/JetBrains Mono are OFL; bundled notices are alongside the fonts. Lucide/Feather licenses are bundled in [Lucide notice](<app/src/main/assets/Lucide-LICENSE.txt>). Font sources: [Inter](https://github.com/google/fonts/tree/main/ofl/inter), [JetBrains Mono](https://github.com/google/fonts/tree/main/ofl/jetbrainsmono); icons adapted from [Lucide](https://github.com/lucide-icons/lucide).

## Verification

```sh
cargo test --workspace --locked
cargo fmt --all -- --check
cargo clippy --workspace --all-targets --locked -- -D warnings
python3 android/tests/check_apex.py
bash android/test-host-jni.sh
bash android/build-android.sh assembleDebugAndroidTest
# Requires a connected API 26+ arm64/x86_64 device or emulator:
./android/gradlew -p android connectedDebugAndroidTest
```

[Host JNI smoke](<tests/HostJniSmoke.java>) calls the real exported JNI functions on a desktop JVM: inspection, known-answer passphrase, no match, errors, cancellation and progress. It is **not** a substitute for ART/device tests.

[Native device test](<app/src/androidTest/java/dev/onixus/aircrack/NativeSmokeTest.java>) covers the packaged JNI pipeline and malformed dictionaries. [UI test](<app/src/androidTest/java/dev/onixus/aircrack/ApexUiTest.java>) exercises both themes, synthetic import and verification with the passphrase hidden. It temporarily clears `FLAG_SECURE` **only in instrumentation code** to save synthetic screenshots; production retains the protection. Screenshots are exported to `/data/local/tmp/apex-{dark,light}{,-result}.png` for CI collection.

The [CI job](<../.github/workflows/ci.yml>) builds both ABIs, runs Apex/host-JNI checks, and schedules API 35 x86_64 instrumentation plus screenshot artifacts. This configuration has not been executed remotely during this session.

### Local verification limitation

Rust workspace tests, rustfmt, strict Clippy, host JNI smoke, Apex contrast/literal checks, APK assembly and Android lint passed. Instrumentation tests compiled. On this host, Android Emulator 37.2.12 / Android 37 ARM64 could not boot: it reported `hvf is not enabled on this aarch64 host` and repeated `qemu_mprotect__osdep: mprotect failed: Permission denied`, then crashed. Thus **device UI/ART execution and actual screenshots are not locally verified**. Do not treat compiled tests as executed tests or the debug APK as production-certified.

The shared Rust/JNI pipeline now also accepts descriptor-v2 M2/M3 and SHA1 PMKID records (M1 KDE or PSK association/reassociation RSN). The JSON `sessions` field remains the total verification-target count for compatibility; `handshakes` and `pmkids` report separate counts. Host JNI smoke covers both new paths. Rebuild the Android APK after updating Rust; previously built APKs do not gain these features automatically.

## Rebuilt APK 0.1.1 (2026-10-27)

The PMKID/M2-M3 sources have now been rebuilt for arm64-v8a and x86_64. VersionCode is 2. The installable debug APK, SHA256, packaged-library checks, lint results and emulator limitation are recorded in the [APK verification report](../docs/ANDROID_APK_0.1.1_VALIDATION.ru.md). Host JNI and 62 Rust tests passed; device instrumentation compiled but could not execute because the test emulator remained offline.

### Real-device verification of APK 0.1.1

The rebuilt APK was subsequently installed and tested on Xiaomi 2211133G (fuxi), Android 16 / API 36, arm64-v8a. All **3 NativeSmokeTest instrumentation tests passed**, including four M2/M3 and PMKID fixtures, known-answer verification, wrong SSID, malformed dictionary, no-match and cancellation checks. The APK pulled back from the phone has the same SHA256 as the delivered artifact. The app launches successfully; the auxiliary test package was removed. This supersedes the earlier lack of ART/native-device evidence, while the separate UI instrumentation suite remains unexecuted. See the [device results](../docs/ANDROID_APK_0.1.1_VALIDATION.ru.md#последующая-проверка-на-реальном-телефоне).

### UI themes verified on the physical phone

Both `ApexUiTest` flows subsequently passed on Xiaomi/Android 16. Four screenshots (initial/result in dark/light) and the final log are linked in the [APK verification report](../docs/ANDROID_APK_0.1.1_VALIDATION.ru.md#ui-проверка-тем-на-телефоне). The screenshot harness now waits for layout and verifies the full result card is visible. A visual issue remains: dark status-bar clock/icons on the dark screenshot have poor contrast; application content and hidden-secret behavior pass. The production APK was not changed during this UI test run.

The shared engine additionally supports WPA/WPA2 key descriptor v1/v2 verification
(HMAC-MD5/SHA1) and raw 64-hex PSK candidates, with one PMK derivation shared
across targets. Host JNI smoke includes WPA1 M1/M2 and M2/M3 fixtures. `airdecap`
is a desktop CLI feature; there is no Android decryption UI. Rebuild the APK to
package the updated native library; host JVM checks do not qualify ART/device behavior.

Descriptor v3 verification is now supported for explicit RSN PSK-SHA256 AKM6 /
CCMP-128 M2 negotiation, including M2/M3-only captures. Host JNI fixtures cover
both v3 pairings. TKIP/GTK capture decryption remains a desktop `airdecap` feature;
this change does not add an Android decryption UI or qualify physical devices.

The native verifier also supports signed FT-PSK reassociations, exported SAE /
FT-SAE PMK candidates and bounded cleartext fragment assembly. It does not attempt
passive SAE password recovery; an ordinary SAE password dictionary returns an
explicit exported-PMK requirement. Ciphertext fragment/FT/SAE traffic decryption
is a desktop airdecap feature. Rebuild the APK to package changed JNI; host checks
are not ART/device acceptance.

The JNI offline verifier now consumes `CaptureReader` incrementally and retains
only bounded verification evidence and SSID context. Existing Android file,
packet, record and target limits remain in force; this does not enable live radio
capture or change APK/device qualification.

M3/M4 verification and WDS EAPOL use the shared Rust path. A zero M4 nonce
requires captured M2 context; descriptor v0/v3 requires explicit negotiation.
Host JNI smoke includes M3/M4, M2-context and WDS fixtures; this does not qualify
Android radio capture or actual devices.

The shared core now specializes WPA PBKDF2 and derives only KCK for dictionary
MIC verification. JNI keeps the same capture/wordlist limits, cancellation and
candidate rules; it does not create a persistent PMK cache.
