from __future__ import annotations

import copy
from collections.abc import Callable
from typing import Any

import pytest

import tools.generate_runtime_sbom as runtime_sbom
from tools.generate_runtime_sbom import (
    OPEN_BLOCKERS,
    ROOT_NAME,
    ROOT_PURL,
    ROOT_VERSION,
    SbomError,
    canonical_json,
    compliance_status,
    normalize_sbom,
    validate_against_locked_export,
    validate_compliance_status,
    validate_sbom,
)


def uv_document() -> dict[str, Any]:
    root_ref = "felya-orca-core-1@0.4.1.post2.dev0"
    dependency_ref = "pyserial-2@3.5"
    return {
        "bomFormat": "CycloneDX",
        "specVersion": "1.5",
        "version": 1,
        "serialNumber": "urn:uuid:random",
        "metadata": {
            "timestamp": "random",
            "tools": [
                {"vendor": "Astral Software Inc.", "name": "uv", "version": "0.11.16"}
            ],
            "component": {
                "type": "library",
                "bom-ref": root_ref,
                "name": ROOT_NAME,
                "version": ROOT_VERSION,
                "properties": [
                    {"name": "uv:package:is_project_root", "value": "true"}
                ],
            },
        },
        "components": [
            {
                "type": "library",
                "bom-ref": dependency_ref,
                "name": "pyserial",
                "version": "3.5",
                "purl": "pkg:pypi/pyserial@3.5",
            }
        ],
        "dependencies": [
            {"ref": root_ref, "dependsOn": [dependency_ref]},
            {"ref": dependency_ref},
        ],
    }


def set_root_property(value: dict[str, Any], name: str, replacement: str) -> None:
    item = next(
        item
        for item in value["metadata"]["component"]["properties"]
        if item["name"] == name
    )
    item["value"] = replacement


@pytest.fixture
def sbom() -> dict[str, Any]:
    return normalize_sbom(
        uv_document(), source_commit="a" * 40, source_timestamp=1_700_000_000
    )


def test_normalized_runtime_sbom_is_deterministic_and_fail_closed(
    sbom: dict[str, Any],
) -> None:
    second = normalize_sbom(
        uv_document(), source_commit="a" * 40, source_timestamp=1_700_000_000
    )

    validate_sbom(sbom)
    assert canonical_json(sbom) == canonical_json(second)
    assert sbom["metadata"]["component"]["purl"] == ROOT_PURL
    assert sbom["metadata"]["component"]["licenses"] == [
        {"license": {"id": "MIT"}}
    ]
    assert "licenses" not in sbom["components"][0]


def test_runtime_sbom_exactly_matches_second_locked_export(
    sbom: dict[str, Any], monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(runtime_sbom, "_export_uv_sbom", uv_document)

    validate_against_locked_export(
        sbom, source_commit="a" * 40, source_timestamp=1_700_000_000
    )


@pytest.mark.parametrize(
    "mutate",
    [
        lambda value: value["components"][0].update(
            {"version": "9.9", "purl": "pkg:pypi/pyserial@9.9"}
        ),
        lambda value: value["dependencies"][0].update({"dependsOn": []}),
        lambda value: value["components"].pop(),
    ],
)
def test_locked_export_comparison_rejects_consistent_graph_mutations(
    sbom: dict[str, Any],
    monkeypatch: pytest.MonkeyPatch,
    mutate: Callable[[dict[str, Any]], object],
) -> None:
    monkeypatch.setattr(runtime_sbom, "_export_uv_sbom", uv_document)
    mutate(sbom)

    with pytest.raises(SbomError, match="exact locked offline export"):
        validate_against_locked_export(
            sbom, source_commit="a" * 40, source_timestamp=1_700_000_000
        )


@pytest.mark.parametrize(
    "mutate",
    [
        lambda value: value["metadata"]["component"].update(
            {"licenses": [{"license": {"id": "Apache-2.0"}}]}
        ),
        lambda value: value["components"][0].update(
            {"licenses": [{"license": {"id": "MIT"}}]}
        ),
        lambda value: value["dependencies"].pop(),
        lambda value: set_root_property(
            value, "felya:hardware-validated", "true"
        ),
        lambda value: set_root_property(value, "felya:lock-sha256", "0" * 64),
    ],
)
def test_sbom_rejects_unsubstantiated_or_incomplete_mutations(
    sbom: dict[str, Any], mutate: Callable[[dict[str, Any]], object]
) -> None:
    candidate = copy.deepcopy(sbom)
    mutate(candidate)

    with pytest.raises(SbomError):
        validate_sbom(candidate)


def test_compliance_status_keeps_every_release_blocker_open(
    sbom: dict[str, Any],
) -> None:
    status = compliance_status(sbom)

    validate_compliance_status(status, sbom)
    assert status["releaseEligible"] is False
    assert tuple(sorted(item["id"] for item in status["openBlockers"])) == OPEN_BLOCKERS
    assert status["licenseReview"]["transitiveConclusion"] == "NOASSERTION"


def test_compliance_status_rejects_promotion_and_digest_mutation(
    sbom: dict[str, Any],
) -> None:
    status = compliance_status(sbom)
    promoted = copy.deepcopy(status)
    promoted["releaseEligible"] = True
    with pytest.raises(SbomError, match="eligibility"):
        validate_compliance_status(promoted, sbom)

    altered = copy.deepcopy(status)
    altered["sbom"]["sha256"] = "0" * 64
    with pytest.raises(SbomError, match="exact SBOM"):
        validate_compliance_status(altered, sbom)

    wrong_subject = copy.deepcopy(status)
    wrong_subject["subject"]["version"] = "9.9.9"
    with pytest.raises(SbomError, match="identity"):
        validate_compliance_status(wrong_subject, sbom)

    missing_notice = copy.deepcopy(status)
    missing_notice["openBlockers"][0]["paths"] = []
    with pytest.raises(SbomError, match="details"):
        validate_compliance_status(missing_notice, sbom)


def test_vendored_feetech_surface_remains_an_explicit_blocker(
    sbom: dict[str, Any],
) -> None:
    status = compliance_status(sbom)
    blocker = next(
        item
        for item in status["openBlockers"]
        if item["id"] == "vendored-feetech-provenance"
    )

    assert blocker["status"] == "open"
    assert blocker["paths"] == ["orca_core/hardware/feetech/"]
