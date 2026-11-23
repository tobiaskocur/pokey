# Security model

## What it is for

The agent watches files that arrive from the internet (anything carrying the
`com.apple.quarantine` flag), checks them in a throwaway sandboxed process
against signed rules, and tells the user when a file looks wrong, for example a
PNG with a Mach-O binary appended to its end or an image whose structure would
trip up a decoder.

Image and document parsers are a common way into a Mac. Many endpoint tools
either trust the OS decoder or parse untrusted bytes inside a privileged
process. Here the only root process never reads file contents. Parsing happens
in a short-lived process that has dropped root, has no network, cannot write
files and is killed if it runs too long or uses too much memory.

## Properties

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
