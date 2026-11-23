# Deploying

Nothing in the repository is a real identity. To build for your own fleet:

1. Put your values in `macos/Config/Identity.local.xcconfig` (not committed):
   team ID, bundle prefix, root threshold, rules and telemetry URLs, and the
   provisioning profiles that carry the Endpoint Security and system extension
   entitlements. Apple grants the Endpoint Security entitlement per developer
   team on request.
2. Put your offline root public keys in `macos/Config/trust-roots.txt`.
3. The installer runs `macos/scripts/create-users.sh` to create the
   `_edrnet` and `_edrinspect` accounts. The host app then activates the system
   extension and registers netd and ui. MDM (or the user) approves the system
   extension and grants the sensor Full Disk Access.
4. For rule releases, configure the `rules-release` environment with the
   signer command (`RULES_SIGNER_CMD`, reads the message on stdin and prints the
   Ed25519 signature), the release certificate and the root threshold, and
   protect it with required reviewers.

GitHub's free plan for private repositories does not offer required reviewers on environments; there the `rules-release` environment is limited to the `main` branch and the workflow stops before signing when `RULES_SIGNER_CMD` or `RULES_RELEASE_CERT_B64` is not set.

## Status

| Area | State |
| --- | --- |
| Rust core, rule tool, fuzz targets | Tested in CI (Linux) |
| Swift logic (EDRCore, EDRRules) | Tested in CI on Linux and macOS |
| macOS targets and app bundle | Compile in CI on macOS (unsigned) |
| Endpoint Security events, system extension activation | Not tested: needs the ES entitlement and a signed, notarized build on a real Mac |
| Inspector sandbox, ImageIO stage, watchdog kills | Not tested on a device |
| Installer package, notarization | Not built yet |
| Telemetry server | Not part of this repository; netd POSTs JSON |
| Rule signing job | Prepared, never run; needs a signer and protected environment |

Known gaps by design: files without the quarantine flag (from `curl`, `git`,
archive tools) are not scanned; the agent alerts and does not block
(`AUTH_OPEN` deny lists and tamper resistance are planned).
