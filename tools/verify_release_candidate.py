#!/usr/bin/env python3
"""Strict offline validation for an unpublished FELYA ORCA wheel candidate."""

from __future__ import annotations

import argparse
import base64
import csv
import hashlib
import json
import re
import subprocess
from email.parser import BytesParser
from pathlib import Path, PurePosixPath
from zipfile import ZipFile

EXPECTED_NAME = "felya-orca-core"
EXPECTED_VERSION = "0.4.1.post5.dev0"
EXPECTED_WHEEL_STEM = "felya_orca_core-0.4.1.post5.dev0"
EXPECTED_DIST_INFO = f"{EXPECTED_WHEEL_STEM}.dist-info"
EXPECTED_GENERATOR = "hatchling 1.32.0"
UPSTREAM_BASE_COMMIT = "c783006ee65432bd0155708cedc685d074448c65"
FELYA_PATCH_COMMITS = ("2d782e6e77bffb434906f9d8f471ce487aa4a0d1",)
FULL_COMMIT = re.compile(r"^[0-9a-f]{40}$")
PROHIBITED_MEMBERS = {"calibration.yaml", ".env", "device-record.json"}
PROHIBITED_CONTENT = (
    re.compile(rb"/Users/[^/\s]+/"),
    re.compile(rb"/home/[^/\s]+/"),
    re.compile(rb"(?:usbserial|usbmodem)-[A-Za-z0-9]{4,}"),
)


class CandidateValidationError(ValueError):
    """The candidate cannot cross the FELYA distribution boundary."""


def _sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as source:
        for chunk in iter(lambda: source.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _record_digest(data: bytes) -> str:
    encoded = base64.urlsafe_b64encode(hashlib.sha256(data).digest()).rstrip(b"=")
    return f"sha256={encoded.decode('ascii')}"


def _validate_member_name(name: str) -> None:
    path = PurePosixPath(name)
    if not name or name.startswith("/") or ".." in path.parts or "\\" in name:
        raise CandidateValidationError(f"unsafe wheel member path: {name!r}")
    if path.name in PROHIBITED_MEMBERS:
        raise CandidateValidationError(f"prohibited local artifact in wheel: {name}")
    if not (name.startswith("orca_core/") or name.startswith(f"{EXPECTED_DIST_INFO}/")):
        raise CandidateValidationError(f"unexpected wheel member namespace: {name}")


def validate_candidate(wheel: Path, repository_license: Path) -> dict[str, object]:
    """Validate metadata, archive integrity, RECORD, and prohibited local data."""

    if not wheel.is_file():
        raise CandidateValidationError(f"wheel does not exist: {wheel}")
    if wheel.name != f"{EXPECTED_WHEEL_STEM}-py3-none-any.whl":
        raise CandidateValidationError(f"unexpected candidate filename: {wheel.name}")

    with ZipFile(wheel) as archive:
        infos = archive.infolist()
        names = [item.filename for item in infos]
        if len(names) != len(set(names)):
            raise CandidateValidationError("wheel contains duplicate member names")
        for info in infos:
            _validate_member_name(info.filename)
            if (info.external_attr >> 16) & 0o170000 == 0o120000:
                raise CandidateValidationError(f"wheel contains symlink: {info.filename}")

        metadata_name = f"{EXPECTED_DIST_INFO}/METADATA"
        wheel_name = f"{EXPECTED_DIST_INFO}/WHEEL"
        license_name = f"{EXPECTED_DIST_INFO}/licenses/LICENSE"
        record_name = f"{EXPECTED_DIST_INFO}/RECORD"
        required = {metadata_name, wheel_name, license_name, record_name, "orca_core/__init__.py"}
        missing = sorted(required.difference(names))
        if missing:
            raise CandidateValidationError(f"wheel is missing required members: {missing}")

        metadata = BytesParser().parsebytes(archive.read(metadata_name))
        if metadata["Name"] != EXPECTED_NAME or metadata["Version"] != EXPECTED_VERSION:
            raise CandidateValidationError("wheel name/version does not match FELYA identity")
        if metadata["License"] != "MIT":
            raise CandidateValidationError("wheel must declare the reviewed MIT root license")
        wheel_metadata = archive.read(wheel_name).decode("utf-8")
        if (
            f"Generator: {EXPECTED_GENERATOR}" not in wheel_metadata
            or "Root-Is-Purelib: true" not in wheel_metadata
            or "Tag: py3-none-any" not in wheel_metadata
        ):
            raise CandidateValidationError("candidate must be a pure Python py3-none-any wheel")
        if archive.read(license_name) != repository_license.read_bytes():
            raise CandidateValidationError("packaged LICENSE differs from the reviewed root LICENSE")

        for name in names:
            data = archive.read(name)
            if any(pattern.search(data) for pattern in PROHIBITED_CONTENT):
                raise CandidateValidationError(f"member contains a concrete local device/path value: {name}")

        rows = list(csv.reader(archive.read(record_name).decode("utf-8").splitlines()))
        recorded = {row[0]: row[1:] for row in rows if len(row) == 3}
        if set(recorded) != set(names):
            raise CandidateValidationError("RECORD inventory differs from wheel members")
        for name in names:
            digest, size = recorded[name]
            if name == record_name:
                if digest or size:
                    raise CandidateValidationError("RECORD must not hash itself")
                continue
            data = archive.read(name)
            if digest != _record_digest(data) or size != str(len(data)):
                raise CandidateValidationError(f"invalid RECORD entry: {name}")

    return {
        "schemaVersion": 1,
        "artifactRole": "release-candidate",
        "distribution": EXPECTED_NAME,
        "version": EXPECTED_VERSION,
        "filename": wheel.name,
        "sha256": _sha256(wheel),
        "sizeBytes": wheel.stat().st_size,
        "buildBackend": EXPECTED_GENERATOR,
        "licenseSha256": _sha256(repository_license),
        "hardwareValidated": False,
        "publisherVerified": False,
    }


def validate_reproducible_pair(first: Path, second: Path) -> None:
    """Require byte-identical artifacts produced in separate build directories."""

    if not second.is_file():
        raise CandidateValidationError(f"comparison wheel does not exist: {second}")
    if first.name != second.name or _sha256(first) != _sha256(second):
        raise CandidateValidationError("independent candidate builds are not byte-identical")


def _git_output(root: Path, *args: str) -> str:
    completed = subprocess.run(
        ["git", *args], cwd=root, check=True, capture_output=True, text=True
    )
    return completed.stdout.strip()


def _git_source(root: Path) -> tuple[str, str]:
    status = _git_output(root, "status", "--porcelain", "--untracked-files=all")
    if status:
        raise CandidateValidationError("source tree must be clean before evidence emission")
    commit = _git_output(root, "rev-parse", "HEAD")
    if FULL_COMMIT.fullmatch(commit) is None:
        raise CandidateValidationError("source commit is not a full lowercase SHA")
    tree = _git_output(root, "rev-parse", "HEAD^{tree}")
    if FULL_COMMIT.fullmatch(tree) is None:
        raise CandidateValidationError("source tree is not a full lowercase SHA")
    return commit, tree


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("wheel", type=Path)
    parser.add_argument("--comparison-wheel", type=Path, required=True)
    parser.add_argument("--evidence-out", type=Path)
    args = parser.parse_args()
    root = Path(__file__).resolve().parents[1]
    wheel = args.wheel.resolve()
    comparison = args.comparison_wheel.resolve()
    evidence = validate_candidate(wheel, root / "LICENSE")
    validate_candidate(comparison, root / "LICENSE")
    validate_reproducible_pair(wheel, comparison)
    source_commit, source_tree = _git_source(root)
    evidence.update(
        {
            "sourceCommit": source_commit,
            "sourceTree": source_tree,
            "upstreamBaseCommit": UPSTREAM_BASE_COMMIT,
            "patchCommits": list(FELYA_PATCH_COMMITS),
            "reproducible": True,
            "independentBuildCount": 2,
        }
    )
    rendered = json.dumps(evidence, indent=2, sort_keys=True) + "\n"
    if args.evidence_out is not None:
        args.evidence_out.write_text(rendered, encoding="utf-8")
    print(rendered, end="")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
