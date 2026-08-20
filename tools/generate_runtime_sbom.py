#!/usr/bin/env python3
"""Generate deterministic, hardware-free runtime SBOM and compliance status."""

from __future__ import annotations

import argparse
import hashlib
import json
import subprocess
import tempfile
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[1]
LOCK_PATH = ROOT / "uv.lock"
LICENSE_PATH = ROOT / "LICENSE"
LICENSE_LEDGER_PATH = ROOT / "compliance/license-provenance-review.v1.json"
EXPECTED_UV = "0.11.16"
ROOT_NAME = "felya-orca-core"
ROOT_VERSION = "0.4.1.post1.dev0"
ROOT_PURL = f"pkg:pypi/{ROOT_NAME}@{ROOT_VERSION}"
FULL_SHA = "0123456789abcdef"
OPEN_BLOCKERS = (
    "adapted-dynamixel-license-obligations",
    "artifact-retention",
    "build-toolchain-inventory",
    "runtime-license-review",
    "vendored-feetech-provenance",
)


class SbomError(ValueError):
    """The runtime inventory or compliance boundary is invalid."""


def sha256_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _git(*args: str) -> str:
    completed = subprocess.run(
        ["git", *args], cwd=ROOT, check=True, capture_output=True, text=True
    )
    return completed.stdout.strip()


def _source_identity() -> tuple[str, int]:
    if _git("status", "--porcelain", "--untracked-files=all"):
        raise SbomError("source tree must be clean before SBOM generation")
    commit = _git("rev-parse", "HEAD")
    if len(commit) != 40 or any(character not in FULL_SHA for character in commit):
        raise SbomError("source commit must be a full lowercase SHA")
    timestamp = int(_git("show", "-s", "--format=%ct", "HEAD"))
    return commit, timestamp


def _export_uv_sbom() -> dict[str, Any]:
    version_output = subprocess.run(
        ["uv", "--version"], check=True, capture_output=True, text=True
    ).stdout.strip()
    parts = version_output.split()
    if len(parts) < 2 or parts[:2] != ["uv", EXPECTED_UV]:
        raise SbomError(f"expected uv {EXPECTED_UV}, got {version_output!r}")
    with tempfile.TemporaryDirectory(prefix="felya-orca-sbom-") as directory:
        output = Path(directory) / "uv.cdx.json"
        subprocess.run(
            [
                "uv",
                "export",
                "--quiet",
                "--format",
                "cyclonedx1.5",
                "--preview-features",
                "sbom-export",
                "--locked",
                "--offline",
                "--no-default-groups",
                "--output-file",
                str(output),
            ],
            cwd=ROOT,
            check=True,
        )
        value = json.loads(output.read_text(encoding="utf-8"))
    if not isinstance(value, dict):
        raise SbomError("uv SBOM root must be an object")
    return value


def normalize_sbom(
    document: dict[str, Any], *, source_commit: str, source_timestamp: int
) -> dict[str, Any]:
    """Normalize uv's random UUID/timestamp and add explicit trust-boundary facts."""

    value = json.loads(json.dumps(document))
    lock_sha = sha256_bytes(LOCK_PATH.read_bytes())
    identity = f"{ROOT_PURL}:{source_commit}:{lock_sha}"
    value["serialNumber"] = f"urn:uuid:{uuid.uuid5(uuid.NAMESPACE_URL, identity)}"
    metadata = value["metadata"]
    metadata["timestamp"] = datetime.fromtimestamp(
        source_timestamp, tz=timezone.utc
    ).isoformat(timespec="seconds").replace("+00:00", "Z")
    root = metadata["component"]
    root["purl"] = ROOT_PURL
    root["licenses"] = [{"license": {"id": "MIT"}}]
    properties = [
        {"name": "felya:artifact-retained", "value": "false"},
        {"name": "felya:hardware-validated", "value": "false"},
        {"name": "felya:license-review-status", "value": "incomplete"},
        {"name": "felya:lock-sha256", "value": lock_sha},
        {"name": "felya:publisher-verified", "value": "false"},
        {"name": "felya:scope", "value": "runtime-lock-union"},
        {"name": "felya:source-commit", "value": source_commit},
    ]
    root["properties"] = sorted(
        [*root.get("properties", []), *properties], key=lambda item: item["name"]
    )
    value["components"] = sorted(
        value["components"], key=lambda item: (item.get("purl", ""), item["bom-ref"])
    )
    for dependency in value["dependencies"]:
        if "dependsOn" in dependency:
            dependency["dependsOn"] = sorted(dependency["dependsOn"])
    value["dependencies"] = sorted(value["dependencies"], key=lambda item: item["ref"])
    return value


def validate_sbom(
    document: dict[str, Any],
    *,
    expected_source_commit: str | None = None,
    expected_source_timestamp: int | None = None,
) -> None:
    if document.get("bomFormat") != "CycloneDX" or document.get("specVersion") != "1.5":
        raise SbomError("SBOM must be CycloneDX 1.5")
    metadata = document.get("metadata")
    if not isinstance(metadata, dict):
        raise SbomError("SBOM metadata is required")
    root = metadata.get("component")
    if not isinstance(root, dict) or (root.get("name"), root.get("version"), root.get("purl")) != (
        ROOT_NAME,
        ROOT_VERSION,
        ROOT_PURL,
    ):
        raise SbomError("SBOM root identity is invalid")
    if root.get("licenses") != [{"license": {"id": "MIT"}}]:
        raise SbomError("only the byte-verified root MIT license may be asserted")
    property_items = root.get("properties", [])
    property_names = [item.get("name") for item in property_items]
    if len(property_names) != len(set(property_names)):
        raise SbomError("SBOM root properties must be unique")
    properties = {item.get("name"): item.get("value") for item in property_items}
    required = {
        "felya:artifact-retained": "false",
        "felya:hardware-validated": "false",
        "felya:license-review-status": "incomplete",
        "felya:publisher-verified": "false",
        "felya:scope": "runtime-lock-union",
    }
    if any(properties.get(name) != expected for name, expected in required.items()):
        raise SbomError("SBOM trust-boundary properties are missing or unsafe")
    for name, length in (("felya:lock-sha256", 64), ("felya:source-commit", 40)):
        value = properties.get(name, "")
        if len(value) != length or any(character not in FULL_SHA for character in value):
            raise SbomError(f"invalid immutable identity property: {name}")
    lock_sha = sha256_bytes(LOCK_PATH.read_bytes())
    if properties["felya:lock-sha256"] != lock_sha:
        raise SbomError("SBOM lock digest differs from uv.lock")
    if expected_source_commit is not None:
        if properties["felya:source-commit"] != expected_source_commit:
            raise SbomError("SBOM source commit differs from the clean checkout")
        identity = f"{ROOT_PURL}:{expected_source_commit}:{lock_sha}"
        expected_serial = f"urn:uuid:{uuid.uuid5(uuid.NAMESPACE_URL, identity)}"
        if document.get("serialNumber") != expected_serial:
            raise SbomError("SBOM serial number is not deterministic")
    if expected_source_timestamp is not None:
        expected_timestamp = datetime.fromtimestamp(
            expected_source_timestamp, tz=timezone.utc
        ).isoformat(timespec="seconds").replace("+00:00", "Z")
        if metadata.get("timestamp") != expected_timestamp:
            raise SbomError("SBOM timestamp differs from the source commit")
    if metadata.get("tools") != [
        {"vendor": "Astral Software Inc.", "name": "uv", "version": EXPECTED_UV}
    ]:
        raise SbomError("SBOM generator identity must be exact")

    components = document.get("components")
    dependencies = document.get("dependencies")
    if not isinstance(components, list) or not components:
        raise SbomError("runtime components are required")
    if not isinstance(dependencies, list):
        raise SbomError("dependency graph is required")
    refs = [item.get("bom-ref") for item in components]
    if len(refs) != len(set(refs)) or any(not isinstance(item, str) for item in refs):
        raise SbomError("component bom-ref values must be unique strings")
    purls = [item.get("purl") for item in components]
    if len(purls) != len(set(purls)) or any(
        not isinstance(item, str) or not item.startswith("pkg:pypi/") for item in purls
    ):
        raise SbomError("component PURLs must be unique immutable PyPI identities")
    if any("licenses" in item for item in components):
        raise SbomError("transitive licenses must not be inferred by SBOM generation")
    graph_refs = {item.get("ref") for item in dependencies}
    root_ref = root.get("bom-ref")
    if graph_refs != {*refs, root_ref}:
        raise SbomError("dependency graph must contain every component and the root")
    allowed_refs = {*refs, root_ref}
    for item in dependencies:
        if any(target not in allowed_refs for target in item.get("dependsOn", [])):
            raise SbomError("dependency graph references an unknown component")


def validate_against_locked_export(
    document: dict[str, Any], *, source_commit: str, source_timestamp: int
) -> None:
    """Require exact components, markers, hashes, and edges from a second lock export."""

    expected = normalize_sbom(
        _export_uv_sbom(),
        source_commit=source_commit,
        source_timestamp=source_timestamp,
    )
    validate_sbom(
        expected,
        expected_source_commit=source_commit,
        expected_source_timestamp=source_timestamp,
    )
    if canonical_json(document) != canonical_json(expected):
        raise SbomError("SBOM differs from the exact locked offline export")


def compliance_status(sbom: dict[str, Any]) -> dict[str, Any]:
    rendered = canonical_json(sbom)
    return {
        "schemaVersion": 1,
        "subject": {"name": ROOT_NAME, "version": ROOT_VERSION},
        "sbom": {
            "format": "CycloneDX",
            "specVersion": "1.5",
            "scope": "runtime-lock-union",
            "sha256": sha256_bytes(rendered),
        },
        "releaseEligible": False,
        "licenseReview": {
            "status": "incomplete",
            "rootExpression": "MIT",
            "transitiveConclusion": "NOASSERTION",
        },
        "licenseProvenanceLedger": {
            "path": "compliance/license-provenance-review.v1.json",
            "sha256": sha256_bytes(LICENSE_LEDGER_PATH.read_bytes()),
        },
        "openBlockers": [
            {
                "id": "adapted-dynamixel-license-obligations",
                "status": "open",
                "detail": "The adapted ROBEL Dynamixel source declares Apache-2.0, but retained license and notice-obligation review is incomplete.",
                "paths": ["orca_core/hardware/dynamixel_client.py"],
            },
            {
                "id": "artifact-retention",
                "status": "open",
                "detail": "No approved immutable artifact store or rollback location exists.",
            },
            {
                "id": "build-toolchain-inventory",
                "status": "open",
                "detail": "The Hatchling closure is locked and hash-constrained, but its artifacts are not retained and its licenses are NOASSERTION.",
            },
            {
                "id": "runtime-license-review",
                "status": "open",
                "detail": "Runtime dependency licenses have not been concluded from retained evidence.",
            },
            {
                "id": "vendored-feetech-provenance",
                "status": "open",
                "detail": "Packaged Feetech SDK-derived sources lack immutable origin and license evidence.",
                "paths": ["orca_core/hardware/feetech/"],
            },
        ],
        "claims": {
            "artifactRetained": False,
            "hardwareValidated": False,
            "publisherVerified": False,
            "signed": False,
        },
    }


def validate_compliance_status(status: dict[str, Any], sbom: dict[str, Any]) -> None:
    if set(status) != {
        "schemaVersion",
        "subject",
        "sbom",
        "releaseEligible",
        "licenseReview",
        "licenseProvenanceLedger",
        "openBlockers",
        "claims",
    }:
        raise SbomError("compliance status fields must be exact")
    if status.get("schemaVersion") != 1 or status.get("subject") != {
        "name": ROOT_NAME,
        "version": ROOT_VERSION,
    }:
        raise SbomError("compliance status identity is invalid")
    if status.get("releaseEligible") is not False:
        raise SbomError("release eligibility must remain false while blockers are open")
    blockers = status.get("openBlockers")
    if not isinstance(blockers, list) or tuple(sorted(item.get("id") for item in blockers)) != OPEN_BLOCKERS:
        raise SbomError("all mandatory compliance blockers must remain explicit")
    if any(item.get("status") != "open" for item in blockers):
        raise SbomError("compliance blockers must remain open")
    claims = status.get("claims")
    expected_claims = {
        "artifactRetained": False,
        "hardwareValidated": False,
        "publisherVerified": False,
        "signed": False,
    }
    if claims != expected_claims:
        raise SbomError("candidate trust and hardware claims must remain false")
    expected_digest = sha256_bytes(canonical_json(sbom))
    if status.get("sbom") != {
        "format": "CycloneDX",
        "specVersion": "1.5",
        "scope": "runtime-lock-union",
        "sha256": expected_digest,
    }:
        raise SbomError("compliance status does not bind the exact SBOM bytes")
    if status.get("licenseProvenanceLedger") != {
        "path": "compliance/license-provenance-review.v1.json",
        "sha256": sha256_bytes(LICENSE_LEDGER_PATH.read_bytes()),
    }:
        raise SbomError("compliance status does not bind the exact review ledger")
    if status.get("licenseReview") != {
        "status": "incomplete",
        "rootExpression": "MIT",
        "transitiveConclusion": "NOASSERTION",
    }:
        raise SbomError("license review must remain incomplete and fail closed")
    if status != compliance_status(sbom):
        raise SbomError("compliance status details differ from the fail-closed policy")


def canonical_json(value: dict[str, Any]) -> bytes:
    return (json.dumps(value, indent=2, sort_keys=True) + "\n").encode("utf-8")


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--sbom-out", type=Path, required=True)
    parser.add_argument("--status-out", type=Path, required=True)
    args = parser.parse_args()
    commit, timestamp = _source_identity()
    sbom = normalize_sbom(_export_uv_sbom(), source_commit=commit, source_timestamp=timestamp)
    validate_sbom(
        sbom,
        expected_source_commit=commit,
        expected_source_timestamp=timestamp,
    )
    validate_against_locked_export(
        sbom,
        source_commit=commit,
        source_timestamp=timestamp,
    )
    status = compliance_status(sbom)
    validate_compliance_status(status, sbom)
    args.sbom_out.parent.mkdir(parents=True, exist_ok=True)
    args.status_out.parent.mkdir(parents=True, exist_ok=True)
    args.sbom_out.write_bytes(canonical_json(sbom))
    args.status_out.write_bytes(canonical_json(status))
    print(f"runtime-sbom: {len(sbom['components'])} components, releaseEligible=false")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
