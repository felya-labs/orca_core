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
compatibility. Version `0.4.1.post3.dev0` means only "FELYA candidate derived
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

The versioned offline license/provenance ledger enumerates the exact 19-member
runtime lock union and the tracked third-party source surfaces. Runtime
dependencies and the nine Feetech SDK-derived files remain `NOASSERTION` until
retained evidence supports a reviewed conclusion. The adapted ROBEL Dynamixel
source declares Apache-2.0 in its header, but its license-text and notice
obligations are still open; the repository-root MIT file is never treated as a
whole-wheel conclusion. The compliance status binds the exact ledger digest.

The PEP 517 build dependency is mirrored into a dedicated, non-runtime `build`
group. Its seven-component Hatchling closure is exported from the exact lock as
hashed constraints. CI hydrates a temporary wheelhouse, then performs both
builds with separate empty caches, `--offline`, `--no-index`, constraints, and
required hashes. This proves the selected build path can run without network
after hydration; it does not prove long-term artifact retention, publisher
identity, license clearance, or fresh-machine availability. Those blockers
remain open. Runtime SBOM generation independently compares its result with a
second normalized offline lock export, including markers and dependency edges.

GitHub Actions dependencies are pinned to full commit IDs. A hash establishes
immutable selection, not publisher trust.

## Observe-only Feetech sessions

The low-level Feetech client exposes an explicit observe-only connection for
the PATON read-only integration. It opens the configured serial bus without
writing servo mode, closes without writing torque state, reads torque-enable
state fail-closed, and rejects every public register-write operation while the
session is active. Normal control sessions retain their existing mode setup and
torque-disable cleanup. This API does not authorize hardware access; Hephaistos
must still provide the machine-local port and enforce its own approval gates.

## Hardware boundary

Automated tests must not require a serial device or enable outputs. Hardware
validation is a separate staged process recorded outside this repository.
No fork commit, tag, wheel, or passing unit test grants a physical capability
tier by itself.

Joint-scoped calibration preserves the selected motor set across operating-mode,
current-limit, torque, hard-stop, cleanup, and return-to-neutral writes. Sparse
joint interpolation must remain sparse; it must not synthesize targets for
unselected motors. Contract tests trace every mocked vendor write and reject a
single-joint run that addresses any other motor. This is a software boundary,
not evidence that mechanical coupling or passive backdrive cannot occur.

The Feetech client additionally exposes an explicit profiled position write.
It binds selected motor IDs, positions, native speed, native acceleration, and
torque into addressed per-motor packets and reports communication or device
errors for each selected motor. It rejects missing, duplicate, unknown,
non-finite, or out-of-range inputs before bus I/O and remains unavailable in an
observe-only session. The raw profile ranges are device capabilities, not a
generic safety policy; Hephaistos must impose its narrower runtime limits.

Calibration accepts that native write profile only when speed, acceleration,
and torque are supplied together and validated before the routine starts. The
profile applies to hard-stop increments and the interpolated return, is restored
after success or failure, and fails closed when the connected motor client lacks
the acknowledged profiled-write contract. This does not make calibration safe
by itself: current policy, per-step and outer deadlines, exact joint selection,
operator authorization, and physical observation remain the integrator's
responsibility.
