# Rule pipeline

Rules live in [`rules/`](../rules): YARA-X signatures, format schemas (PNG,
TIFF, ISO-BMFF/HEIC/AVIF), a policy file mapping outcomes to severity, fixtures
with expected outcomes and a benign corpus that must scan clean.

| Step | Where | What it checks |
| --- | --- | --- |
| Lint and compile | `rules` workflow, every PR | Rules compile on the current engine and on the previous engine release (`engine-v*` tag), which deployed sensors may still run |
| Fixtures | same | Each fixture produces its expected outcome and rule |
| False-positive gate | same | Every file in `rules/benign` scans `CLEAN` |
| Budgets | same | Per-file scan time and interpreter fuel stay under limits |
| Fuzzing | `core` workflow | Schema interpreter, compiler and bundle verifier under libFuzzer |
| Sign and publish | `release-rules`, manual only | Signs in the `rules-release` environment through a KMS/HSM signer command, verifies against the pinned roots, publishes a release |

`pokey-rulec` does all of it locally:

```sh
cargo build --release -p pokey-rulec --manifest-path core/Cargo.toml
R=core/target/release/pokey-rulec
$R lint --rules rules --deny-warnings
$R test --rules rules --benign rules/benign --max-ms 50 --max-fuel-pct 50
$R compile --rules rules --version 1 --channel canary --expires-days 7 --out unsigned.bundle
$R scan --rules rules path/to/file.png
```

Run `pokey-rulec` without arguments for key, certificate, signing and
verification commands.

Bundle format and activation on the sensor: [architecture.md](architecture.md#rule-pipeline).
