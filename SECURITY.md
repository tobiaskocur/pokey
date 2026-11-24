# Security policy

Pokey is early software and has not been audited. Do not rely on it as your only protection.

## Reporting a vulnerability

Report it privately through [GitHub security advisories](https://github.com/tobiaskocur/pokey/security/advisories/new). Do not open a public issue.

Include what you found, how to reproduce it and which version or commit you tested. You will get an answer within 7 days. Once a fix is released, the advisory is published with credit unless you ask otherwise.

## Supported versions

Only the latest release gets security fixes.

## Scope

In scope: the sensor, inspector, netd and UI processes, the XPC protocol between them, rule bundle signing and verification, the schema interpreter and `pokey-rulec`.

Out of scope: detection gaps (a malicious file the shipped rules do not catch), and attacks that already need root or a signed system extension. Detection gaps are welcome as ordinary issues or rule pull requests.

The threat model is in [docs/security-model.md](docs/security-model.md).
