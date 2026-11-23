# Contributing

## Before a pull request

Run the checks in [docs/development.md](docs/development.md). CI runs the same ones.

## Pull requests

Pull requests are squash-merged. The pull request title becomes the commit message on `main` and the changelog entry, so it must follow [Conventional Commits](https://www.conventionalcommits.org/):

```
feat(sensor): skip files on network volumes
fix(rulec): reject empty schema files
```

| Type | Changelog section |
| --- | --- |
| `feat` | Added |
| `fix` | Fixed |
| `security` | Security |
| `perf`, `refactor`, `deps` | Changed |
| `revert` | Removed |
| `docs`, `test`, `build`, `ci`, `chore` | not listed |

A breaking change gets `!` after the type (`feat!: ...`). Before 1.0 it bumps the minor version, after 1.0 the major one. The `lint` workflow checks the title.

Rule changes (`rules/`) go through the same process. They are released separately, see below.

## Versions

The app version lives in two files that always match: `version` in `core/Cargo.toml` and `MARKETING_VERSION` in `macos/Config/Version.xcconfig`. Do not edit them by hand; the release pull request changes both. The `core` workflow fails if they differ.

Rule bundles have their own integer version (`pokey-rulec compile --version`), independent of the app version.

## Releasing the app

1. Every push to `main` makes [release-please](https://github.com/googleapis/release-please) open or update a pull request titled `chore: release X.Y.Z`. It bumps both version files and adds the changelog entry. A second job updates `Cargo.lock` on that branch.
2. Pull requests opened by GitHub Actions do not start other workflows. Close and reopen the release pull request once so CI runs on it.
3. Squash-merge it. That tags `vX.Y.Z`, publishes the GitHub release and attaches the binaries, `SHA256SUMS`, the SBOM and the provenance attestation.

To build every release asset without publishing anything, run the `release` workflow by hand (Actions → release → Run workflow). The assets are kept as the `release-dry-run` workflow artifact.

After the first release, remove `"release-as": "0.1.0"` from `release-please-config.json`; otherwise every release stays at 0.1.0.

### Signing and notarization

The `notarize-rulec` job signs and notarizes the macOS `pokey-rulec` with a Developer ID. It is skipped unless the repository variable `APPLE_SIGNING` is `enabled`. It runs in the `release` environment and needs:

| Kind | Name |
| --- | --- |
| variable | `APPLE_SIGNING` = `enabled`, `APPLE_TEAM_ID` |
| secret | `APPLE_DEVELOPER_ID_P12_B64`, `APPLE_DEVELOPER_ID_P12_PASSWORD` (Developer ID Application certificate) |
| secret | `APPLE_NOTARY_KEY_P8_B64`, `APPLE_NOTARY_KEY_ID`, `APPLE_NOTARY_ISSUER_ID` (App Store Connect API key) |

The app bundle is not signed in CI: it needs an Endpoint Security entitlement and provisioning profiles for the deployer's own team ([docs/deploying.md](docs/deploying.md)).

## Releasing rules

Rule bundles are compiled and signed by the `release-rules` workflow, described in [docs/rule-pipeline.md](docs/rule-pipeline.md).

## Branch protection

[`.github/rulesets/main.json`](.github/rulesets/main.json) protects `main`: no deletion or force push, linear history, changes only through squash-merged pull requests, and the always-running `lint` checks must pass. (`core`, `rules` and `macos` run only when their paths change, so they cannot be required.) GitHub enforces rulesets on private repositories only on paid plans. Apply it with:

```sh
gh api -X POST repos/tobiaskocur/pokey/rulesets --input .github/rulesets/main.json
```

## License

By contributing you agree that your contribution is licensed under [Apache-2.0](LICENSE).
