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
