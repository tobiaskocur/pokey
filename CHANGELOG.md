# Changelog

All notable changes to Pokey are listed here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/) and the project uses
[Semantic Versioning](https://semver.org/). Entries are written by
release-please from the conventional commit titles merged into `main`.

Rule bundles have their own monotonic version (`rules-N` releases) and are not
listed here.

## [0.0.0] - unreleased

Pokey was developed as `macos-edr-agent` and renamed before its first release.
No release was published under the old name. If you built from an old
checkout: crates, binaries and bundle identifiers moved from `edr-*` to
`pokey-*`, the bundle magic changed to `PKYBNDL1`, and the service users are
now `_pokeynet` and `_pokeyinspect`, so rule bundles and installs from before
the rename have to be rebuilt.
