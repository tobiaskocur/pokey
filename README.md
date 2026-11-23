# macos-edr-agent

Open-source defensive file-monitoring agent for macOS. An Endpoint Security
system extension watches files as they are written, a sandboxed and
unprivileged inspector process checks them against signed rules (YARA-X plus a
small bounded format-schema language for images), and the user is told when a
file is flagged (notify-only; nothing is blocked yet). Design and accepted risks:
[docs/architecture.md](docs/architecture.md).

Status: the Rust core, the rule pipeline and the platform-independent Swift
logic are built and tested on Linux. **The macOS targets (sensor, inspector,
netd, ui, host app) have not been compiled yet**; the first compile happens in
`macos-ci` on a macOS runner or on a Mac.

## Layout

| Path | What |
| --- | --- |
| `core/edr-core` | Signed rule bundles, schema language (parser, IR, fuel-bounded VM), scan engine over YARA-X |
| `core/edr-ffi` | C ABI used by Swift (`include/edr_core.h`) |
| `core/edr-rulec` | Rule CLI: lint, test, compile, keys, certificates, sign, verify, scan |
| `core/fuzz` | cargo-fuzz targets (interpreter, compiler, bundle verifier) |
| `rules/` | Policy, YARA rules, schemas, fixtures (`fixtures/gen.py`) and `tests.json` |
| `macos/Sources/EDRCore`, `EDRRules` | Pure Swift logic and the rules wrapper (tested on Linux too) |
| `macos/Sources/edr-sensor` | System extension: ES client, candidate pipeline, SQLite journal, inspector pool, XPC server, rule activation |
| `macos/Sources/edr-inspector` | Per-scan helper: drops to `_edrinspect`, rlimits, `sandbox_init`, staged scan |
| `macos/Sources/edr-netd` | Daemon as `_edrnet`: fetches rule bundles, uploads telemetry |
| `macos/Sources/edr-ui` | Per-user agent: notifications and alert acknowledgement |
| `macos/Sources/EDRHost` | Host app: activates the system extension, registers netd and ui |
| `macos/project.yml`, `macos/Config` | XcodeGen project, identity, Info.plists, entitlements, launchd templates |

## Build and test

Rust 1.93.1 (pinned in CI):

```sh
cd core
cargo fmt --all --check
cargo clippy --workspace --all-targets --locked -- -D warnings
cargo test --workspace --locked
cargo +nightly fuzz run interp_ir -- -max_total_time=120   # optional
```

Rules:

```sh
R=core/target/release/edr-rulec
cargo build --release -p edr-rulec --manifest-path core/Cargo.toml
$R lint --rules rules --deny-warnings
$R test --rules rules --benign rules/benign --max-ms 50 --max-fuel-pct 50
```

Swift logic (macOS or Linux with Swift 6.2):

```sh
cd macos && make test
```

App bundle (macOS, Xcode 16+, [XcodeGen](https://github.com/yonaskolb/XcodeGen)):

```sh
cd macos && make xcode XCODEBUILD_FLAGS="DEVELOPMENT_TEAM=..."
```

## Deployment identity

Nothing in the repository is a real identity. Before building for a fleet:

1. Copy your values into `macos/Config/Identity.local.xcconfig` (not
   committed): `EDR_TEAM_ID`, `EDR_BUNDLE_PREFIX`, `EDR_ROOT_THRESHOLD`,
   `EDR_RULES_URL`, `EDR_TELEMETRY_URL`, `EDR_TELEMETRY_WHEREFROMS`, and the
   provisioning profiles carrying the Endpoint Security and system extension
   entitlements (`EDR_SENSOR_PROFILE`, `EDR_HOST_PROFILE`).
2. Put the offline root public keys in `macos/Config/trust-roots.txt` (hex,
   one per line). The sensor refuses to start with fewer keys than the
   threshold.
3. All XPC peers are pinned by code-signing requirement built from the team ID
   and bundle prefix; the values are read from Info.plist at runtime.

## Install flow

1. The installer package runs `macos/scripts/create-users.sh` as root to create
   the hidden `_edrnet` and `_edrinspect` accounts.
2. The user (or MDM) opens the host app, which submits the
   `OSSystemExtensionRequest` and registers `netd` (LaunchDaemon) and `ui`
   (LaunchAgent) with `SMAppService`. The launchd plists are rendered at build
   time by `macos/scripts/render-launchd.sh`.
3. MDM must approve the system extension and grant Full Disk Access to the
   sensor; without MDM the user approves both in System Settings.

## Rule release

1. Keys: roots are created offline with `edr-rulec keygen`; the release key
   lives in a KMS/HSM. `cert-new` + one `cert-sign` per root produce the
   release certificate (k-of-n).
2. `rules-ci` checks every rule change against the current engine and the
   previous engine release (`engine-v*` tag).
3. `release-rules` (manual) compiles an unsigned bundle, then a job in the
   protected `rules-release` environment signs it via `RULES_SIGNER_CMD`
   (reads the message on stdin, prints the Ed25519 signature), verifies it
   against `trust-roots.txt` with self-tests and publishes a GitHub release.
4. `edr-netd` fetches the bundle; the sensor verifies signatures, expiry and
   version rollback, runs the self-tests in an inspector, activates it and
   rolls back if the health gate fails.

## Not covered yet

- No macOS compile or on-device test has run yet (see Status).
- No installer package (`.pkg`) or notarization pipeline; `create-users.sh`
  is the postinstall piece only.
- No server for telemetry ingestion; netd only POSTs JSON to
  `EDR_TELEMETRY_URL`.
- Files without the quarantine xattr (curl, git, extractors) are never
  scanned.
- No blocking: `AUTH_OPEN` deny lists and tamper resistance
  (`AUTH_SIGNAL`/`AUTH_UNLINK`) are later work.
