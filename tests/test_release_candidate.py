from __future__ import annotations

import base64
import csv
import hashlib
import io
import shutil
from pathlib import Path
from zipfile import ZIP_DEFLATED, ZipFile, ZipInfo

import pytest

import tools.verify_release_candidate as candidate_module
from tools.verify_release_candidate import (
    CandidateValidationError,
    EXPECTED_DIST_INFO,
    EXPECTED_WHEEL_STEM,
    validate_candidate,
    validate_reproducible_pair,
)


def _digest(data: bytes) -> str:
    value = base64.urlsafe_b64encode(hashlib.sha256(data).digest()).rstrip(b"=")
    return f"sha256={value.decode('ascii')}"


def _candidate(
    tmp_path: Path,
    license_path: Path,
    *,
    extra: dict[str, bytes] | None = None,
    name: str = "felya-orca-core",
    corrupt_record: bool = False,
) -> Path:
    tmp_path.mkdir(parents=True, exist_ok=True)
    metadata = (
        "Metadata-Version: 2.4\n"
        f"Name: {name}\n"
        "Version: 0.4.1.post2.dev0\n"
        "License: MIT\n\n"
    ).encode()
    members = {
        "orca_core/__init__.py": b"\n",
        f"{EXPECTED_DIST_INFO}/METADATA": metadata,
        f"{EXPECTED_DIST_INFO}/WHEEL": (
            b"Wheel-Version: 1.0\nGenerator: hatchling 1.32.0\n"
            b"Root-Is-Purelib: true\nTag: py3-none-any\n"
        ),
        f"{EXPECTED_DIST_INFO}/licenses/LICENSE": license_path.read_bytes(),
    }
    members.update(extra or {})
    record_name = f"{EXPECTED_DIST_INFO}/RECORD"
    output = io.StringIO()
    writer = csv.writer(output, lineterminator="\n")
    for member_name, data in members.items():
        digest = "sha256=wrong" if corrupt_record and member_name == "orca_core/__init__.py" else _digest(data)
        writer.writerow((member_name, digest, len(data)))
    writer.writerow((record_name, "", ""))
    members[record_name] = output.getvalue().encode()

    wheel = tmp_path / f"{EXPECTED_WHEEL_STEM}-py3-none-any.whl"
    with ZipFile(wheel, "w", ZIP_DEFLATED) as archive:
        for member_name, data in members.items():
            archive.writestr(member_name, data)
    return wheel


def test_valid_candidate_emits_disabled_untrusted_evidence(tmp_path: Path) -> None:
    license_path = Path(__file__).parents[1] / "LICENSE"
    evidence = validate_candidate(_candidate(tmp_path, license_path), license_path)

    assert evidence["artifactRole"] == "release-candidate"
    assert evidence["hardwareValidated"] is False
    assert evidence["publisherVerified"] is False
    assert len(str(evidence["sha256"])) == 64


@pytest.mark.parametrize(
    ("extra", "match"),
    [
        ({"../escape": b"x"}, "unsafe wheel member"),
        ({"calibration.yaml": b"x"}, "prohibited local artifact"),
        ({"orca_core/local.py": b"PORT = '/Users/operator/device'"}, "concrete local"),
        ({"orca_core/local.py": b"PORT = 'usbserial-FT62AFSR'"}, "concrete local"),
    ],
)
def test_candidate_rejects_prohibited_members_and_values(
    tmp_path: Path, extra: dict[str, bytes], match: str
) -> None:
    license_path = Path(__file__).parents[1] / "LICENSE"

    with pytest.raises(CandidateValidationError, match=match):
        validate_candidate(_candidate(tmp_path, license_path, extra=extra), license_path)


def test_candidate_rejects_upstream_distribution_identity(tmp_path: Path) -> None:
    license_path = Path(__file__).parents[1] / "LICENSE"

    with pytest.raises(CandidateValidationError, match="name/version"):
        validate_candidate(
            _candidate(tmp_path, license_path, name="orca-core"), license_path
        )


def test_candidate_rejects_invalid_record_digest(tmp_path: Path) -> None:
    license_path = Path(__file__).parents[1] / "LICENSE"

    with pytest.raises(CandidateValidationError, match="invalid RECORD"):
        validate_candidate(
            _candidate(tmp_path, license_path, corrupt_record=True), license_path
        )


def test_candidate_rejects_symlink(tmp_path: Path) -> None:
    license_path = Path(__file__).parents[1] / "LICENSE"
    wheel = _candidate(tmp_path, license_path)
    with ZipFile(wheel, "a") as archive:
        link = ZipInfo("orca_core/link")
        link.create_system = 3
        link.external_attr = 0o120777 << 16
        archive.writestr(link, "target")

    with pytest.raises(CandidateValidationError, match="symlink"):
        validate_candidate(wheel, license_path)


def test_evidence_rejects_dirty_source_tree(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    monkeypatch.setattr(
        candidate_module,
        "_git_output",
        lambda root, *args: " M local-config.yaml"
        if args[0] == "status"
        else "0" * 40,
    )

    with pytest.raises(CandidateValidationError, match="must be clean"):
        candidate_module._git_source(tmp_path)


def test_reproducible_pair_requires_identical_bytes(tmp_path: Path) -> None:
    license_path = Path(__file__).parents[1] / "LICENSE"
    first = _candidate(tmp_path / "first", license_path)
    second = tmp_path / "second" / first.name
    second.parent.mkdir()
    shutil.copyfile(first, second)

    validate_reproducible_pair(first, second)
    second.write_bytes(second.read_bytes() + b"mutation")

    with pytest.raises(CandidateValidationError, match="not byte-identical"):
        validate_reproducible_pair(first, second)


def test_packaged_source_has_no_concrete_local_device_identity() -> None:
    package_root = Path(__file__).parents[1] / "orca_core"
    prohibited = (
        b"/Users/",
        b"/home/",
        b"usbserial-FT62AFSR",
    )

    violations = [
        str(path.relative_to(package_root))
        for path in package_root.rglob("*")
        if path.is_file()
        and path.suffix in {".py", ".yaml"}
        and any(value in path.read_bytes() for value in prohibited)
    ]

    assert violations == []
