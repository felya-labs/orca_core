from pathlib import Path

from tools.check_downstream import distribution_migration_blocker


def _project(tmp_path: Path, dependency: str) -> Path:
    tmp_path.mkdir(parents=True, exist_ok=True)
    (tmp_path / "pyproject.toml").write_text(
        "[project]\n"
        'name = "consumer"\n'
        "dependencies = [\n"
        f'    "{dependency}",\n'
        '    "fastapi",\n'
        "]\n",
        encoding="utf-8",
    )
    return tmp_path


def test_legacy_distribution_is_an_explicit_migration_blocker(tmp_path: Path) -> None:
    blocker = distribution_migration_blocker(_project(tmp_path, "orca_core"))

    assert blocker == (
        "distribution migration pending: consumer requires orca-core, "
        "candidate provides felya-orca-core"
    )


def test_felya_distribution_allows_downstream_tests(tmp_path: Path) -> None:
    assert (
        distribution_migration_blocker(_project(tmp_path, "felya-orca-core")) is None
    )


def test_unrelated_orca_text_does_not_skip_tests(tmp_path: Path) -> None:
    project = _project(tmp_path, "fastapi")
    with (project / "pyproject.toml").open("a", encoding="utf-8") as output:
        output.write('# docs mention "orca_core" but it is not a dependency\n')

    assert distribution_migration_blocker(project) is None
