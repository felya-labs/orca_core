# FELYA fork policy

This repository is the minimal FELYA patch carrier for the official
[`orcahand/orca_core`](https://github.com/orcahand/orca_core) project.
The official repository remains the upstream provenance source.

## Repository roles

Configure fresh checkouts with these remotes:

```text
origin    https://github.com/felya-labs/orca_core.git
upstream  https://github.com/orcahand/orca_core.git
```

The initial FELYA baseline is the complete upstream commit
`c783006ee65432bd0155708cedc685d074448c65`, published upstream as `v0.4.1`.
The tag is informational; integrations select full commit IDs and retained
artifact digests.

## Change policy

- Start an upstream sync from one reviewed, immutable upstream commit.
- Keep every downstream change in a small pull request and classify it as a
  general upstream candidate or a narrowly scoped FELYA integration hook.
- Do not rewrite validated history or move a published FELYA release tag.
- Remove a downstream patch only after its upstream replacement passes the
  same automated and hardware gates.
- Keep PATON sessions, leases, gestures, UI behavior, and manufacturer-neutral
  safety policy outside this repository.

## Prohibited data

Do not commit or package:

- serial or USB device paths;
- individual motor scans or operator-selected ports;
- per-hand motor directions, neutral positions, measured ranges, tension, or
  calibration output;
- local current limits, credentials, secrets, or generated hardware logs;
- unreviewed experimental gesture or hardware scripts.

Individual device and calibration data belongs in local Hephaistos records.

## Publication boundary

The inherited upstream PyPI publication workflow is intentionally removed.
This fork must not publish under the upstream `orca_core` package identity.
Any future FELYA distribution requires a separately reviewed package name,
registry, signing, SBOM, retention, and release policy.

The unpublished build candidate uses the distinct distribution name
`felya-orca-core` while retaining the Python import namespace `orca_core` for
compatibility. Version `0.4.1.post1.dev0` means only "FELYA candidate derived
from upstream 0.4.1". It is not a release, is not hardware-validated, and must
not be uploaded to a registry. Candidate CI builds twice from the same source
commit and validates identical wheel bytes plus an external evidence record.
Downstream repositories that still require the upstream `orca-core`
distribution remain import-checked, but their suites are reported as blocked
until they explicitly migrate to `felya-orca-core`; unrelated failures remain
fatal to the downstream check.

Candidate CI also generates a deterministic CycloneDX 1.5
`runtime-lock-union` inventory from the exact `uv.lock`. It describes every
marker/platform alternative reachable from the runtime root; it is not an
installed-environment SBOM. The companion compliance status remains
`releaseEligible: false` while runtime license review, build-toolchain
inventory, immutable retention, or vendored Feetech SDK provenance is open.
Only the byte-verified repository MIT license is asserted. No transitive or
vendored license is inferred from a package name, lock hash, or root license.

GitHub Actions dependencies are pinned to full commit IDs. A hash establishes
immutable selection, not publisher trust.

## Hardware boundary

Automated tests must not require a serial device or enable outputs. Hardware
validation is a separate staged process recorded outside this repository.
No fork commit, tag, wheel, or passing unit test grants a physical capability
tier by itself.
