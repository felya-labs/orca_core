from __future__ import annotations

import re
from pathlib import Path


ROOT = Path(__file__).parents[1]
WORKFLOW_ROOT = ROOT / ".github" / "workflows"
FULL_COMMIT = re.compile(r"^[0-9a-f]{40}$")


def test_felya_fork_has_no_upstream_publication_workflow() -> None:
    assert not (WORKFLOW_ROOT / "release.yml").exists()
    workflow_text = "\n".join(
        path.read_text(encoding="utf-8") for path in sorted(WORKFLOW_ROOT.glob("*.yml"))
    )
    assert "pypa/gh-action-pypi-publish" not in workflow_text
    assert "id-token: write" not in workflow_text


def test_every_external_action_is_pinned_to_a_full_commit() -> None:
    unpinned: list[str] = []
    for path in sorted(WORKFLOW_ROOT.glob("*.yml")):
        for line_number, line in enumerate(
            path.read_text(encoding="utf-8").splitlines(), start=1
        ):
            match = re.search(r"\buses:\s*([^\s#]+)", line)
            if match is None or match.group(1).startswith("./"):
                continue
            action, separator, revision = match.group(1).rpartition("@")
            if not action or separator != "@" or FULL_COMMIT.fullmatch(revision) is None:
                unpinned.append(f"{path.relative_to(ROOT)}:{line_number}: {match.group(1)}")
    assert not unpinned, "unpinned GitHub Actions:\n" + "\n".join(unpinned)


def test_candidate_uses_distinct_identity_and_exact_build_backend() -> None:
    pyproject = (ROOT / "pyproject.toml").read_text(encoding="utf-8")

    assert 'name = "felya-orca-core"' in pyproject
    assert 'version = "0.4.1.post1.dev0"' in pyproject
    assert 'requires = ["hatchling==1.32.0"]' in pyproject


def test_required_pr_ci_builds_and_compares_two_candidates() -> None:
    workflow = (WORKFLOW_ROOT / "test.yml").read_text(encoding="utf-8")

    assert "version: '0.11.16'" in workflow
    assert workflow.count("uv build --wheel") == 2
    assert "cmp build/candidate-a/*.whl build/candidate-b/*.whl" in workflow
    assert "tools/verify_release_candidate.py" in workflow


def test_required_pr_ci_generates_and_compares_runtime_sbom() -> None:
    workflow = (WORKFLOW_ROOT / "test.yml").read_text(encoding="utf-8")

    assert workflow.count("tools/generate_runtime_sbom.py") == 2
    assert "cmp build/compliance-a/runtime.cdx.json" in workflow
    assert "cmp build/compliance-a/status.json" in workflow
    assert workflow.count("tools/validate_license_provenance.py") == 2
    assert "compliance/license-provenance-review.v1.json" in (
        ROOT / "FELYA_FORK.md"
    ).read_text(encoding="utf-8") or "license/provenance ledger" in (
        ROOT / "FELYA_FORK.md"
    ).read_text(encoding="utf-8")
    assert "upload-artifact" not in workflow
