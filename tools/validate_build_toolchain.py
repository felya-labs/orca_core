#!/usr/bin/env python3
"""Validate the locked, hashed ORCA Core build-toolchain selection offline."""

from __future__ import annotations

import argparse
import ast
import re
import subprocess
import tempfile
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[1]
CONSTRAINTS_PATH = ROOT / "compliance/build-toolchain-constraints.txt"
EXPECTED_UV = "0.11.16"
EXPECTED_COMPONENTS = {
    "hatchling": "1.32.0",
    "packaging": "26.0",
    "pathspec": "1.0.4",
    "pluggy": "1.6.0",
    "tomli": "2.4.1",
    "tomlkit": "0.15.1",
    "trove-classifiers": "2026.6.1.19",
}


class BuildToolchainError(ValueError):
    """The selected build toolchain is stale, incomplete, or unsafe."""


def _uv_version() -> None:
    output = subprocess.run(
        ["uv", "--version"], check=True, capture_output=True, text=True
    ).stdout.split()
    if len(output) < 2 or output[:2] != ["uv", EXPECTED_UV]:
        raise BuildToolchainError(f"expected uv {EXPECTED_UV}")


def _array_from_section(section_name: str, key: str) -> list[str]:
    text = (ROOT / "pyproject.toml").read_text(encoding="utf-8")
    section = re.search(
        rf"(?ms)^\[{re.escape(section_name)}\]\s*$\n(.*?)(?=^\[|\Z)", text
    )
    if section is None:
        raise BuildToolchainError(f"missing pyproject section: {section_name}")
    match = re.search(rf"(?ms)^{re.escape(key)}\s*=\s*(\[[^\]]*\])", section.group(1))
    if match is None:
        raise BuildToolchainError(f"missing string array: {section_name}.{key}")
    try:
        value = ast.literal_eval(match.group(1))
    except (SyntaxError, ValueError) as error:
        raise BuildToolchainError(f"invalid string array: {section_name}.{key}") from error
    if not isinstance(value, list) or not value or any(not isinstance(item, str) for item in value):
        raise BuildToolchainError(f"invalid string array: {section_name}.{key}")
    return value


def export_locked_constraints() -> bytes:
    _uv_version()
    with tempfile.TemporaryDirectory(prefix="felya-build-toolchain-") as directory:
        output = Path(directory) / "constraints.txt"
        subprocess.run(
            [
                "uv",
                "export",
                "--quiet",
                "--format",
                "requirements.txt",
                "--no-header",
                "--locked",
                "--offline",
                "--only-group",
                "build",
                "--output-file",
                str(output),
            ],
            cwd=ROOT,
            check=True,
        )
        return output.read_bytes()


def parse_constraints(data: bytes) -> dict[str, dict[str, Any]]:
    text = data.decode("utf-8")
    logical = text.replace("\\\n", " ")
    records: dict[str, dict[str, Any]] = {}
    pattern = re.compile(
        r"(?m)^(?P<name>[a-z0-9-]+)==(?P<version>[^ ;\\\n]+)"
        r"(?P<marker>\s*;.*?)?(?P<body>(?:\s+--hash=sha256:[0-9a-f]{64})+)"
    )
    for match in pattern.finditer(logical):
        name = match.group("name")
        hashes = re.findall(r"--hash=sha256:([0-9a-f]{64})", match.group("body"))
        if name in records or not hashes or len(hashes) != len(set(hashes)):
            raise BuildToolchainError("constraint identities and hashes must be unique")
        records[name] = {
            "version": match.group("version"),
            "marker": (match.group("marker") or "").strip().removeprefix(";").strip() or None,
            "hashes": hashes,
        }
    if set(records) != set(EXPECTED_COMPONENTS) or any(
        records[name]["version"] != version for name, version in EXPECTED_COMPONENTS.items()
    ):
        raise BuildToolchainError("constraints must exactly cover the reviewed build closure")
    if records["tomli"]["marker"] != "python_full_version < '3.11'" or any(
        item["marker"] is not None for name, item in records.items() if name != "tomli"
    ):
        raise BuildToolchainError("build-toolchain markers differ from the reviewed closure")
    return records


def validate_build_toolchain(data: bytes) -> dict[str, dict[str, Any]]:
    direct = _array_from_section("build-system", "requires")
    group = _array_from_section("dependency-groups", "build")
    if direct != ["hatchling==1.32.0"] or group != direct:
        raise BuildToolchainError("build-system and build audit group must match exactly")
    records = parse_constraints(data)
    expected = export_locked_constraints()
    if data != expected:
        raise BuildToolchainError("checked build constraints differ from the locked offline export")
    return records


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--constraints", type=Path, default=CONSTRAINTS_PATH)
    args = parser.parse_args()
    records = validate_build_toolchain(args.constraints.read_bytes())
    print(f"build-toolchain: {len(records)} locked components, artifacts-retained=false")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
