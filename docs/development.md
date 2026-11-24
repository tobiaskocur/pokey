# Development

CI runs these on every pull request that touches the code. Run them locally first.

Rust core (`core/`):

```sh
cd core
cargo fmt --all --check
cargo clippy --workspace --all-targets --locked -- -D warnings
cargo test --workspace --locked
```

Rules (from the repo root, after `cargo build --release -p pokey-rulec` in `core/`):

```sh
R=core/target/release/pokey-rulec
$R lint --rules rules --deny-warnings
$R test --rules rules --benign rules/benign --max-ms 50 --max-fuel-pct 50
```

Swift (`macos/`): `make test` on Linux or macOS; `make build` and
`make xcode XCODEBUILD_FLAGS="CODE_SIGNING_ALLOWED=NO"` on macOS.
