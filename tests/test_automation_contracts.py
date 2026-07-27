from __future__ import annotations

import re
from pathlib import Path

ROOT = Path(__file__).parents[1]
RANGED_REQUIREMENT = re.compile(
    r"^(?P<name>[A-Za-z0-9][A-Za-z0-9._-]*)"
    r">=(?P<floor>[0-9]+(?:\.[0-9]+)*),"
    r"<(?P<ceiling>[0-9]+(?:\.[0-9]+)*)$"
)
PINNED_REQUIREMENT = re.compile(
    r"^(?P<name>[A-Za-z0-9][A-Za-z0-9._-]*)"
    r"==(?P<version>[0-9]+(?:\.[0-9]+)*)$"
)


def read_repo_file(path: str) -> str:
    return (ROOT / path).read_text(encoding="utf-8")


def requirement_lines(contents: str) -> list[str]:
    return [
        line.strip()
        for line in contents.splitlines()
        if line.strip() and not line.lstrip().startswith("#")
    ]


def parse_ranged_requirements(contents: str) -> dict[str, tuple[str, str]]:
    requirements: dict[str, tuple[str, str]] = {}
    for line in requirement_lines(contents):
        match = RANGED_REQUIREMENT.fullmatch(line)
        assert match is not None, f"Unsupported ranged requirement: {line}"
        requirements[match["name"]] = (match["floor"], match["ceiling"])
    return requirements


def parse_pinned_requirements(contents: str) -> dict[str, str]:
    requirements: dict[str, str] = {}
    for line in requirement_lines(contents):
        match = PINNED_REQUIREMENT.fullmatch(line)
        assert match is not None, f"Unsupported pinned requirement: {line}"
        requirements[match["name"]] = match["version"]
    return requirements


def numeric_version(version: str) -> tuple[int, ...]:
    return tuple(int(part) for part in version.split("."))


def test_ci_aggregate_requires_quality_and_dependency_boundaries() -> None:
    workflow = read_repo_file(".github/workflows/pr-validate.yml")

    assert "name: Quality and coverage" in workflow
    assert "boundary: minimum" in workflow
    assert "boundary: latest" in workflow
    assert "scripts/validate.sh all" in workflow
    assert "QUALITY_RESULT: ${{ needs.quality.result }}" in workflow
    assert "DEPENDENCY_RESULT: ${{ needs.dependency_boundaries.result }}" in workflow


def test_prerelease_canary_is_scheduled_non_blocking_and_actionable() -> None:
    workflow = read_repo_file(".github/workflows/prerelease-canary.yml")
    triggers = workflow[: workflow.index("\npermissions:")]

    assert "\n  schedule:" in triggers
    assert "\n  workflow_dispatch:" in triggers
    assert "\n  pull_request:" not in triggers
    assert "\n  push:" not in triggers
    assert "python_prerelease:" in workflow
    assert "pytest_prerelease:" in workflow
    assert 'python-version: "3.15"' in workflow
    assert "allow-prereleases: true" in workflow
    assert "python -m pip install --upgrade --pre pytest" in workflow
    assert workflow.count("scripts/validate.sh test") == 2
    assert workflow.count("if: failure()") == 2
    assert workflow.count('"$GITHUB_STEP_SUMMARY"') == 2
    assert workflow.count("python --version") == 2
    assert workflow.count("python -m pytest --version") == 2


def test_dependency_review_and_dependabot_cover_the_declared_policy() -> None:
    dependency_review = read_repo_file(".github/workflows/dependency-review.yml")
    dependabot = read_repo_file(".github/dependabot.yml")

    assert "name: Dependency review" in dependency_review
    assert "fail-on-severity: moderate" in dependency_review
    assert "license-check: false" in dependency_review
    for ecosystem in ("pip", "github-actions", "docker"):
        assert f"package-ecosystem: {ecosystem}" in dependabot


def test_dependency_constraints_pin_both_supported_boundaries() -> None:
    ranges = parse_ranged_requirements(read_repo_file("requirements-dev.txt"))
    minimum = parse_pinned_requirements(read_repo_file("requirements-dev-minimum.txt"))
    latest = parse_pinned_requirements(read_repo_file("requirements-dev-latest.txt"))

    assert minimum.keys() == ranges.keys()
    assert latest.keys() == ranges.keys()

    for package, (floor, ceiling) in ranges.items():
        assert minimum[package] == floor
        assert (
            numeric_version(floor)
            <= numeric_version(latest[package])
            < numeric_version(ceiling)
        )


def test_readme_unsupported_issues_match_the_support_matrix() -> None:
    readme = read_repo_file("readme.md")
    support_matrix = read_repo_file("docs/conversion-support-matrix.md")

    readme_section = readme[
        readme.index("## What It Does Not Convert") : readme.index("## Python Version")
    ]
    matrix_section = support_matrix[
        support_matrix.index("## Explicitly unsupported work") : support_matrix.index(
            "## Contribution checklist"
        )
    ]

    readme_issues = set(re.findall(r"issues/(\d+)", readme_section))
    matrix_issues = set(re.findall(r"#(\d+)", matrix_section))

    assert readme_issues == matrix_issues


def test_release_publishes_only_after_validating_the_resolved_sha() -> None:
    workflow = read_repo_file(".github/workflows/release.yml")

    validate_job = workflow.index("\n  validate:")
    publish_job = workflow.index("\n  publish:")

    assert validate_job < publish_job
    assert "target_sha: ${{ steps.meta.outputs.target_sha }}" in workflow
    assert "ref: ${{ needs.resolve.outputs.target_sha }}" in workflow
    assert "../validation-contract/scripts/validate.sh all" in workflow
    assert "if: github.event_name != 'pull_request'" in workflow
    assert "contents: write" not in workflow[:publish_job]
    assert "contents: write" in workflow[publish_job:]
