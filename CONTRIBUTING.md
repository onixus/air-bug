# Development

Use a current stable Rust toolchain with `rustfmt` and `clippy`. The local validation environment uses Rust/Cargo 1.98.1; an older MSRV has not been qualified. No native libpcap or radio interface is needed.

From the workspace root:

```sh
cargo fmt --all -- --check
cargo clippy --workspace --all-targets --locked -- -D warnings
cargo test --workspace --locked
cargo build --release --workspace --locked
```

Keep Cargo.lock in version control: this workspace ships an application. Dependency updates must be deliberate and tested. CI defines these checks on Linux, macOS and Windows; local success on one OS does not qualify the others.

For parser changes, add regression tests for malformed and truncated input, and retain fail-closed behavior for unsupported formats. For crypto changes, use independent known-answer vectors, not only values produced by the implementation under test. Do not claim support for a suite simply because a placeholder command exists.

Synthetic fixture generation uses only Python's standard library:

```sh
python3 tests/fixtures/generate.py
cargo test --workspace --locked
```

Review regenerated fixture changes before committing. Never commit real credentials, private captures, local target artifacts or recovered password logs. Tests must remain offline: capture lifecycle tests use private fake executables, and BSSID-filter tests run system tcpdump only with synthetic `-r` files. No CI test should open a radio or require BPF permissions. Live/shadow runtime requires an administrator-provisioned capture environment; injection remains outside scope.

The initial repository had no commits and all sources were untracked. Establish the initial commit after reviewing the files; no automated commit or repository reset is performed by the cleanup.
