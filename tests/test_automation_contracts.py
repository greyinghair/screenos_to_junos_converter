from __future__ import annotations

from pathlib import Path

ROOT = Path(__file__).parents[1]


def read_repo_file(path: str) -> str:
    return (ROOT / path).read_text(encoding="utf-8")


def test_ci_aggregate_requires_quality_and_dependency_boundaries() -> None:
    workflow = read_repo_file(".github/workflows/pr-validate.yml")

    assert "name: Quality and coverage" in workflow
    assert "boundary: minimum" in workflow
    assert "boundary: latest" in workflow
    assert "scripts/validate.sh all" in workflow
    assert "QUALITY_RESULT: ${{ needs.quality.result }}" in workflow
    assert "DEPENDENCY_RESULT: ${{ needs.dependency_boundaries.result }}" in workflow


def test_dependency_review_and_dependabot_cover_the_declared_policy() -> None:
    dependency_review = read_repo_file(".github/workflows/dependency-review.yml")
    dependabot = read_repo_file(".github/dependabot.yml")

    assert "name: Dependency review" in dependency_review
    assert "fail-on-severity: moderate" in dependency_review
    assert "license-check: false" in dependency_review
    for ecosystem in ("pip", "github-actions", "docker"):
        assert f"package-ecosystem: {ecosystem}" in dependabot


def test_dependency_constraints_pin_both_supported_boundaries() -> None:
    minimum = read_repo_file("requirements-dev-minimum.txt")
    latest = read_repo_file("requirements-dev-latest.txt")

    assert "pytest==9.0.3" in minimum
    assert "pytest-cov==7.0.0" in minimum
    assert "ruff==0.15.0" in minimum
    assert "pytest==9.1.1" in latest
    assert "pytest-cov==7.1.0" in latest
    assert "ruff==0.16.0" in latest


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
