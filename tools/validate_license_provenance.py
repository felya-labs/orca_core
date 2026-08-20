#!/usr/bin/env python3
"""Validate the FELYA license/provenance ledger entirely offline."""

from __future__ import annotations

import argparse
import ast
import hashlib
import json
import re
import subprocess
from pathlib import Path
from typing import Any

try:
    from tools.validate_build_toolchain import (
        CONSTRAINTS_PATH,
        BuildToolchainError,
        parse_constraints,
    )
except ModuleNotFoundError:  # Direct `python tools/...` execution.
    from validate_build_toolchain import (  # type: ignore[no-redef]
        CONSTRAINTS_PATH,
        BuildToolchainError,
        parse_constraints,
    )

ROOT = Path(__file__).resolve().parents[1]
LEDGER_PATH = ROOT / "compliance/license-provenance-review.v1.json"
FULL_SHA = set("0123456789abcdef")
EXPECTED_BLOCKERS = {
    "adapted-dynamixel-license-obligations",
    "artifact-retention",
    "build-toolchain-inventory",
    "runtime-license-review",
    "vendored-feetech-provenance",
}
EXPECTED_REVIEWED_SOURCE_COMMIT = "b721c6c290ee3a9727ddab18eef477f9896e572b"
EXPECTED_FEETECH = {
    path.as_posix()
    for path in (ROOT / "orca_core/hardware/feetech").glob("*.py")
    if path.is_file()
}
EXPECTED_FEETECH = {path.removeprefix(f"{ROOT.as_posix()}/") for path in EXPECTED_FEETECH}


class LedgerError(ValueError):
    """The review ledger makes an incomplete or unsupported claim."""


def sha256_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _exact_keys(value: Any, keys: set[str], label: str) -> dict[str, Any]:
    if not isinstance(value, dict) or set(value) != keys:
        raise LedgerError(f"{label} must contain exactly {sorted(keys)}")
    return value


def _digest(value: Any, label: str) -> str:
    if not isinstance(value, str) or len(value) != 64 or any(c not in FULL_SHA for c in value):
        raise LedgerError(f"{label} must be a lowercase SHA-256")
    return value


def _repo_file(path_value: Any, digest: Any, label: str) -> Path:
    if not isinstance(path_value, str):
        raise LedgerError(f"{label} path must be a string")
    relative = Path(path_value)
    if relative.is_absolute() or ".." in relative.parts or relative.as_posix() != path_value:
        raise LedgerError(f"{label} path must be normalized and repository-relative")
    path = ROOT / relative
    if path.is_symlink() or not path.is_file():
        raise LedgerError(f"{label} must identify a regular repository file")
    if sha256_bytes(path.read_bytes()) != _digest(digest, f"{label} digest"):
        raise LedgerError(f"{label} digest differs from local bytes")
    return path


def _tracked_feetech_files() -> set[str]:
    completed = subprocess.run(
        ["git", "ls-files", "--", "orca_core/hardware/feetech/*.py"],
        cwd=ROOT,
        check=True,
        capture_output=True,
        text=True,
    )
    return set(completed.stdout.splitlines())


def _build_requirements() -> list[str]:
    text = (ROOT / "pyproject.toml").read_text(encoding="utf-8")
    section = re.search(r"(?ms)^\[build-system\]\s*$\n(.*?)(?=^\[|\Z)", text)
    if section is None:
        raise LedgerError("pyproject build-system section is required")
    match = re.search(r"(?m)^requires\s*=\s*(\[[^\n]*\])\s*$", section.group(1))
    if match is None:
        raise LedgerError("build-system requirements must use a single-line string array")
    try:
        value = ast.literal_eval(match.group(1))
    except (SyntaxError, ValueError) as error:
        raise LedgerError("build-system requirements are invalid") from error
    if not isinstance(value, list) or not value or any(not isinstance(item, str) for item in value):
        raise LedgerError("build-system requirements must be a non-empty string array")
    return value


def load_json(path: Path) -> dict[str, Any]:
    value = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(value, dict):
        raise LedgerError(f"{path.name} root must be an object")
    return value


def validate_ledger(ledger: dict[str, Any], sbom: dict[str, Any]) -> None:
    _exact_keys(
        ledger,
        {"schemaVersion", "subject", "evidence", "rootConclusion", "runtimeReviews", "sourceSurfaces", "buildToolchain", "review"},
        "ledger",
    )
    if ledger["schemaVersion"] != 1:
        raise LedgerError("unsupported ledger schema version")

    subject = _exact_keys(
        ledger["subject"],
        {"purl", "reviewedSourceCommit", "uvLockSha256", "pyprojectSha256"},
        "subject",
    )
    root = sbom.get("metadata", {}).get("component", {})
    if subject["purl"] != root.get("purl"):
        raise LedgerError("ledger subject differs from SBOM root")
    commit = subject["reviewedSourceCommit"]
    if not isinstance(commit, str) or len(commit) != 40 or any(c not in FULL_SHA for c in commit):
        raise LedgerError("reviewed source commit must be a full lowercase SHA")
    if commit != EXPECTED_REVIEWED_SOURCE_COMMIT:
        raise LedgerError("reviewed source commit differs from the approved baseline")
    if subject["uvLockSha256"] != sha256_bytes((ROOT / "uv.lock").read_bytes()):
        raise LedgerError("ledger uv.lock digest differs from local bytes")
    if subject["pyprojectSha256"] != sha256_bytes((ROOT / "pyproject.toml").read_bytes()):
        raise LedgerError("ledger pyproject digest differs from local bytes")

    evidence = ledger["evidence"]
    if not isinstance(evidence, list) or not evidence:
        raise LedgerError("at least one local evidence record is required")
    evidence_ids: set[str] = set()
    for item in evidence:
        item = _exact_keys(item, {"id", "kind", "path", "sha256"}, "evidence")
        if item["id"] in evidence_ids or not isinstance(item["id"], str):
            raise LedgerError("evidence IDs must be unique strings")
        evidence_ids.add(item["id"])
        if item["kind"] not in {"license-text", "source-archive", "package-metadata", "review-note"}:
            raise LedgerError("unknown evidence kind")
        _repo_file(item["path"], item["sha256"], f"evidence {item['id']}")

    conclusion = _exact_keys(
        ledger["rootConclusion"], {"kind", "expression", "evidenceIds", "scope"}, "root conclusion"
    )
    if conclusion != {
        "kind": "spdx",
        "expression": "MIT",
        "evidenceIds": ["repository-mit-license"],
        "scope": "repository-root-only",
    } or not set(conclusion["evidenceIds"]).issubset(evidence_ids):
        raise LedgerError("only the evidence-bound repository-root MIT conclusion is allowed")

    components = sbom.get("components")
    if not isinstance(components, list):
        raise LedgerError("SBOM components are required")
    sbom_purls = {item.get("purl") for item in components}
    reviews = ledger["runtimeReviews"]
    if not isinstance(reviews, list):
        raise LedgerError("runtime reviews must be a list")
    review_purls: list[Any] = []
    for item in reviews:
        item = _exact_keys(item, {"purl", "conclusion"}, "runtime review")
        if item["conclusion"] != "NOASSERTION":
            raise LedgerError("runtime licenses must remain NOASSERTION without retained evidence")
        review_purls.append(item["purl"])
    if len(review_purls) != len(set(review_purls)) or set(review_purls) != sbom_purls:
        raise LedgerError("runtime review PURLs must exactly cover the SBOM lock union")

    surfaces = ledger["sourceSurfaces"]
    if not isinstance(surfaces, list) or len(surfaces) != 2:
        raise LedgerError("both known third-party source surfaces are required")
    by_id = {item.get("id"): item for item in surfaces if isinstance(item, dict)}
    if set(by_id) != {"adapted-dynamixel-client", "vendored-feetech-sdk-derived"}:
        raise LedgerError("source surface IDs must be exact and unique")
    all_paths: list[str] = []
    for identifier, item in by_id.items():
        item = _exact_keys(
            item,
            {"id", "classification", "declaredLicense", "conclusion", "provenanceStatus", "files"},
            f"surface {identifier}",
        )
        if item["conclusion"] != "NOASSERTION" or item["provenanceStatus"] not in {"unreviewed", "incomplete"}:
            raise LedgerError("third-party source conclusions must remain incomplete and NOASSERTION")
        if not isinstance(item["files"], list) or not item["files"]:
            raise LedgerError("source surface files are required")
        for file_item in item["files"]:
            file_item = _exact_keys(file_item, {"path", "sha256"}, "source file")
            _repo_file(file_item["path"], file_item["sha256"], f"surface {identifier}")
            all_paths.append(file_item["path"])
    if len(all_paths) != len(set(all_paths)):
        raise LedgerError("source surface paths must not overlap")
    dynamixel = by_id["adapted-dynamixel-client"]
    if dynamixel["classification"] != "adapted-third-party" or dynamixel["declaredLicense"] != "Apache-2.0" or [item["path"] for item in dynamixel["files"]] != ["orca_core/hardware/dynamixel_client.py"]:
        raise LedgerError("adapted Dynamixel surface must preserve its declared header and exact path")
    feetech = by_id["vendored-feetech-sdk-derived"]
    feetech_paths = {item["path"] for item in feetech["files"]}
    if feetech["classification"] != "vendored-third-party" or feetech["declaredLicense"] != "NOASSERTION" or feetech_paths != _tracked_feetech_files() or feetech_paths != EXPECTED_FEETECH:
        raise LedgerError("vendored Feetech inventory must exactly cover tracked Python sources")

    build = _exact_keys(
        ledger["buildToolchain"],
        {"directRequirements", "closureStatus", "constraints", "components", "conclusion"},
        "build toolchain",
    )
    constraint_reference = _exact_keys(
        build["constraints"], {"path", "sha256"}, "build constraints"
    )
    if constraint_reference["path"] != "compliance/build-toolchain-constraints.txt":
        raise LedgerError("build constraints path must be exact")
    _repo_file(
        constraint_reference["path"],
        constraint_reference["sha256"],
        "build constraints",
    )
    try:
        locked = parse_constraints(CONSTRAINTS_PATH.read_bytes())
    except BuildToolchainError as error:
        raise LedgerError("build constraints are invalid") from error
    expected_components = [
        {
            "name": name,
            "version": record["version"],
            "marker": record["marker"],
            "conclusion": "NOASSERTION",
        }
        for name, record in sorted(locked.items())
    ]
    if build != {
        "directRequirements": _build_requirements(),
        "closureStatus": "locked-unretained",
        "constraints": constraint_reference,
        "components": expected_components,
        "conclusion": "NOASSERTION",
    }:
        raise LedgerError("build-toolchain closure must remain locked, unretained, and NOASSERTION")

    review = _exact_keys(ledger["review"], {"status", "releaseEligible", "openBlockers"}, "review")
    if review["status"] != "incomplete" or review["releaseEligible"] is not False or set(review["openBlockers"]) != EXPECTED_BLOCKERS or len(review["openBlockers"]) != len(EXPECTED_BLOCKERS):
        raise LedgerError("review must remain fail-closed with every mandatory blocker")


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--ledger", type=Path, default=LEDGER_PATH)
    parser.add_argument("--sbom", type=Path, required=True)
    args = parser.parse_args()
    ledger = load_json(args.ledger)
    sbom = load_json(args.sbom)
    validate_ledger(ledger, sbom)
    print(f"license-provenance: {len(ledger['runtimeReviews'])} runtime reviews, releaseEligible=false")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
