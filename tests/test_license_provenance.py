from __future__ import annotations

import copy
import json
from collections.abc import Callable
from pathlib import Path
from typing import Any

import pytest

from tools.validate_license_provenance import (
    LEDGER_PATH,
    LedgerError,
    load_json,
    validate_ledger,
)


def ledger() -> dict[str, Any]:
    return load_json(LEDGER_PATH)


def sbom_for(value: dict[str, Any]) -> dict[str, Any]:
    return {
        "metadata": {"component": {"purl": value["subject"]["purl"]}},
        "components": [
            {"purl": item["purl"]} for item in value["runtimeReviews"]
        ],
    }


def test_checked_in_ledger_is_exact_and_fail_closed() -> None:
    value = ledger()

    validate_ledger(value, sbom_for(value))

    assert len(value["runtimeReviews"]) == 19
    assert all(item["conclusion"] == "NOASSERTION" for item in value["runtimeReviews"])
    assert value["review"]["releaseEligible"] is False


def test_root_mit_conclusion_is_scoped_to_repository_evidence() -> None:
    value = ledger()

    assert value["rootConclusion"] == {
        "kind": "spdx",
        "expression": "MIT",
        "evidenceIds": ["repository-mit-license"],
        "scope": "repository-root-only",
    }


def test_third_party_sources_remain_noassertion() -> None:
    value = ledger()
    surfaces = {item["id"]: item for item in value["sourceSurfaces"]}

    assert surfaces["adapted-dynamixel-client"]["declaredLicense"] == "Apache-2.0"
    assert surfaces["adapted-dynamixel-client"]["conclusion"] == "NOASSERTION"
    assert surfaces["vendored-feetech-sdk-derived"]["declaredLicense"] == "NOASSERTION"
    assert surfaces["vendored-feetech-sdk-derived"]["conclusion"] == "NOASSERTION"
    assert len(surfaces["vendored-feetech-sdk-derived"]["files"]) == 9


@pytest.mark.parametrize(
    "mutate",
    [
        lambda value: value["subject"].update({"uvLockSha256": "0" * 64}),
        lambda value: value["subject"].update({"reviewedSourceCommit": "main"}),
        lambda value: value["runtimeReviews"].pop(),
        lambda value: value["runtimeReviews"].append(copy.deepcopy(value["runtimeReviews"][0])),
        lambda value: value["runtimeReviews"][0].update({"conclusion": "MIT"}),
        lambda value: value["rootConclusion"].update({"scope": "whole-package"}),
        lambda value: value["sourceSurfaces"][1].update({"provenanceStatus": "verified"}),
        lambda value: value["sourceSurfaces"][1]["files"].pop(),
        lambda value: value["sourceSurfaces"][0]["files"][0].update({"sha256": "0" * 64}),
        lambda value: value["buildToolchain"].update({"closureStatus": "complete"}),
        lambda value: value["review"].update({"releaseEligible": True}),
        lambda value: value["review"]["openBlockers"].pop(),
    ],
)
def test_ledger_rejects_unsupported_claims_and_incomplete_coverage(
    mutate: Callable[[dict[str, Any]], object],
) -> None:
    value = ledger()
    document = sbom_for(value)
    mutate(value)

    with pytest.raises(LedgerError):
        validate_ledger(value, document)


def test_sbom_component_identity_must_match_ledger_exactly() -> None:
    value = ledger()
    document = sbom_for(value)
    document["components"][0]["purl"] = "pkg:pypi/annotated-types@9.9.9"

    with pytest.raises(LedgerError, match="exactly cover"):
        validate_ledger(value, document)


def test_evidence_paths_must_not_escape_repository(tmp_path: Path) -> None:
    value = ledger()
    document = sbom_for(value)
    value["evidence"][0]["path"] = str(tmp_path / "LICENSE")

    with pytest.raises(LedgerError, match="repository-relative"):
        validate_ledger(value, document)


def test_schema_identifies_strict_v1_wire_format() -> None:
    schema_path = LEDGER_PATH.parent / "schemas/license-provenance-review-v1.schema.json"
    schema = json.loads(schema_path.read_text(encoding="utf-8"))

    assert schema["properties"]["schemaVersion"] == {"const": 1}
    assert schema["additionalProperties"] is False
