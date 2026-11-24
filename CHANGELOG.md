# Changelog

All notable changes to Pokey are listed here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/) and the project uses
[Semantic Versioning](https://semver.org/). Entries are written by
release-please from the conventional commit titles merged into `main`.

Rule bundles have their own monotonic version (`rules-N` releases) and are not
listed here.

## [0.1.0](https://github.com/tobiaskocur/pokey/compare/v0.1.0...v0.1.0) (2026-11-24)


### ⚠ BREAKING CHANGES

* rename to Pokey, license Apache-2.0, add release pipeline ([#3](https://github.com/tobiaskocur/pokey/issues/3))

### Added

* rename to Pokey, license Apache-2.0, add release pipeline ([#3](https://github.com/tobiaskocur/pokey/issues/3)) ([0c7c26c](https://github.com/tobiaskocur/pokey/commit/0c7c26c0125f19deb7a50211fc6e90375f2fbd6a))


### Changed

* bump ed25519-dalek to 3.0 in core and fuzz ([#10](https://github.com/tobiaskocur/pokey/issues/10)) ([de60e9d](https://github.com/tobiaskocur/pokey/commit/de60e9dd0ef21342a224e599bf7f391acbecb5d6))
* bump sha2 to 0.11 in core and fuzz ([#9](https://github.com/tobiaskocur/pokey/issues/9)) ([f5b4867](https://github.com/tobiaskocur/pokey/commit/f5b4867287eb41ac0a5fb94a4339bed38d6365b8))

## [0.0.0] - unreleased

Pokey was developed as `macos-edr-agent` and renamed before its first release.
No release was published under the old name. If you built from an old
checkout: crates, binaries and bundle identifiers moved from `edr-*` to
`pokey-*`, the bundle magic changed to `PKYBNDL1`, and the service users are
now `_pokeynet` and `_pokeyinspect`, so rule bundles and installs from before
the rename have to be rebuilt.
