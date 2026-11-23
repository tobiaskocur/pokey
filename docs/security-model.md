# Security model

- One root process, no parsing in it. The sensor's only untrusted inputs
  are inspector replies (strict, size-bounded schema), bundle bytes from netd
  (signatures checked over raw bytes before anything is parsed) and allowlisted
  ui commands.
- Pinned peers. Every XPC connection is pinned to a code-signing
  requirement built from the team ID and bundle prefix. An inspector must also
  be the sensor's own child and present a one-time nonce passed over a pipe.
- Bounded rules. Structural checks are written in a small schema language,
  compiled to IR in CI and run by a fuel-limited interpreter with
  bounds-checked reads. A schema cannot loop forever or read outside the file.
- Signed, monotonic rule updates. A bundle needs a signature from a release
  key whose certificate is signed by k of n offline roots. The sensor rejects
  older versions, expired bundles and bundles needing a newer engine, runs the
  bundle's self-tests in a fresh inspector before switching, and rolls back to
  the last known-good bundle if the health gate fails.
- Telemetry carries hashes and metadata. Download URLs are off unless the
  deployment turns them on.

The design and its accepted risks are in [architecture.md](architecture.md).
