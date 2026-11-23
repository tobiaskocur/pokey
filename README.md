# Pokey

A macOS agent that scans files downloaded from the internet in a sandboxed process against signed YARA-X and file-format rules.

[![core](https://github.com/tobiaskocur/pokey/actions/workflows/core-ci.yml/badge.svg)](https://github.com/tobiaskocur/pokey/actions/workflows/core-ci.yml)
[![rules](https://github.com/tobiaskocur/pokey/actions/workflows/rules-ci.yml/badge.svg)](https://github.com/tobiaskocur/pokey/actions/workflows/rules-ci.yml)
[![macos](https://github.com/tobiaskocur/pokey/actions/workflows/macos-ci.yml/badge.svg)](https://github.com/tobiaskocur/pokey/actions/workflows/macos-ci.yml)

![pokey-rulec: certify a release key, test, compile, sign, verify and scan](docs/assets/rule-pipeline.gif)

Status: early. Every target builds and the tests pass in CI on Linux and macOS, but nothing has run on a real Mac with the Endpoint Security entitlement yet. Details and known gaps: [docs/deploying.md](docs/deploying.md#status).

## Components

| Process | Runs as | Does |
| --- | --- | --- |
| `pokey-sensor` | root, system extension | Filters Endpoint Security file events down to quarantined files, hashes them, hands them to an inspector, keeps verdicts. Never parses file contents. |
| `pokey-inspector` | `_pokeyinspect`, one process per file | Runs YARA-X, format schemas and an ImageIO decode in a sandbox with no network and no writes. |
| `pokey-netd` | `_pokeynet` | Downloads signed rule bundles, uploads telemetry. |
| `pokey-ui` | logged-in user | Shows alerts as notifications. |

The rule compiler and the scan engine are Rust (`core/`); the macOS processes are Swift (`macos/`).

## Building

Requires Rust 1.93.1 and Swift 6. The macOS targets need Xcode 16 and [XcodeGen](https://github.com/yonaskolb/XcodeGen).

Rust core and rule compiler (Linux or macOS):

```sh
cd core
cargo test --workspace --locked
cargo build --release -p pokey-rulec
```

Swift logic tests (Linux or macOS):

```sh
cd macos
make test
```

macOS targets and an unsigned app bundle:

```sh
cd macos
make build
make xcode XCODEBUILD_FLAGS="CODE_SIGNING_ALLOWED=NO"
```

Signing with your own team ID and Endpoint Security entitlement is described in [docs/deploying.md](docs/deploying.md).

## Usage

`pokey-rulec` lints, tests, compiles, signs and runs the rules in [`rules/`](rules):

```sh
# from the repo root
R=core/target/release/pokey-rulec
$R lint --rules rules --deny-warnings
$R test --rules rules --benign rules/benign --max-ms 50 --max-fuel-pct 50
$R compile --rules rules --version 1 --channel canary --expires-days 7 --out unsigned.bundle
$R scan --rules rules path/to/file.png
```

Run `pokey-rulec` with no arguments to list the key, certificate, signing and verification commands. The GIF above is [docs/demo/demo.sh](docs/demo/demo.sh).

## Documentation

- [Architecture](docs/architecture.md): processes, IPC, data flow, source layout
- [Security model](docs/security-model.md)
- [Rule pipeline](docs/rule-pipeline.md): CI checks, signing, rule updates
- [Development](docs/development.md): checks CI runs, to run before a pull request
- [Deploying](docs/deploying.md): identity, entitlements, rule releases, current status
