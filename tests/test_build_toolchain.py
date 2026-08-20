from __future__ import annotations

from collections.abc import Callable

import pytest

import tools.validate_build_toolchain as build_toolchain
from tools.validate_build_toolchain import (
    CONSTRAINTS_PATH,
    BuildToolchainError,
    parse_constraints,
    validate_build_toolchain,
)


def constraints() -> bytes:
    return CONSTRAINTS_PATH.read_bytes()


def test_checked_in_build_constraints_match_exact_locked_export(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    data = constraints()
    monkeypatch.setattr(build_toolchain, "export_locked_constraints", lambda: data)

    records = validate_build_toolchain(data)

    assert len(records) == 7
    assert records["hatchling"]["version"] == "1.32.0"
    assert records["tomli"]["marker"] == "python_full_version < '3.11'"
    assert all(record["hashes"] for record in records.values())


@pytest.mark.parametrize(
    "mutate",
    [
        lambda data: data.replace(b"hatchling==1.32.0", b"hatchling==9.9.9", 1),
        lambda data: data.replace(b"packaging==26.0", b"", 1),
        lambda data: data.replace(b"--hash=sha256:", b"--hash=sha512:", 1),
        lambda data: data.replace(
            b"python_full_version < '3.11'", b"python_full_version >= '3.11'", 1
        ),
    ],
)
def test_constraints_reject_mutated_versions_coverage_hashes_and_markers(
    mutate: Callable[[bytes], bytes],
) -> None:
    with pytest.raises(BuildToolchainError):
        parse_constraints(mutate(constraints()))


def test_constraints_reject_stale_bytes_even_if_parseable(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    data = constraints()
    regenerated = b"# stale but parseable\n" + data
    monkeypatch.setattr(
        build_toolchain, "export_locked_constraints", lambda: regenerated
    )

    with pytest.raises(BuildToolchainError, match="locked offline export"):
        validate_build_toolchain(data)
