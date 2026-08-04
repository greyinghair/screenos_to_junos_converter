from __future__ import annotations

import re
from pathlib import Path

ROOT = Path(__file__).parents[1]
BACKTICKED = re.compile(r"`([^`\n]+)`")
REPO_PATH = re.compile(
    r"^(?:convert\.py|readme\.md|pyproject\.toml|AGENTS\.md|CHANGELOG\.md"
    r"|requirements(?:-dev)?(?:-minimum|-latest)?\.txt"
    r"|packages|tests|docs|scripts|docker|\.github|\.dockerignore)(?:/|$)"
)
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


def test_runtime_dependencies_are_exactly_pinned() -> None:
    runtime = parse_pinned_requirements(read_repo_file("requirements.txt"))

    assert runtime.keys() == {"Flask", "gunicorn"}


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


def test_agent_guidance_only_references_paths_that_exist() -> None:
    guidance = read_repo_file("AGENTS.md")

    referenced = {
        token
        for span in BACKTICKED.findall(guidance)
        # A span may be a command such as "scripts/validate.sh all"; the path is
        # its first word.
        for token in [span.split(" ", 1)[0]]
        if REPO_PATH.match(token)
    }

    assert referenced, "AGENTS.md must reference the repository paths it describes."
    missing = sorted(path for path in referenced if not (ROOT / path).exists())
    assert not missing, f"AGENTS.md references paths that no longer exist: {missing}"


def test_agent_guidance_documents_every_module_and_script() -> None:
    guidance = read_repo_file("AGENTS.md")

    tracked = [
        f"{path.parent.name}/{path.name}"
        for path in sorted(
            [*(ROOT / "packages").glob("*.py"), *(ROOT / "scripts").glob("*.sh")]
        )
    ]

    undocumented = [path for path in tracked if path not in guidance]
    assert not undocumented, (
        f"AGENTS.md does not document these modules or scripts: {undocumented}"
    )


def test_agent_guidance_matches_the_shared_validation_entrypoints() -> None:
    guidance = read_repo_file("AGENTS.md")
    validate = read_repo_file("scripts/validate.sh")

    for mode in ("all", "test"):
        assert f"scripts/validate.sh {mode}" in guidance
        assert f"\n  {mode})\n" in validate

    assert "SCREENOS_MAX_CONFIG_BYTES" in read_repo_file("packages/web_app.py")
    assert "SCREENOS_MAX_CONFIG_BYTES" in guidance


def test_agent_guidance_carries_no_local_or_secret_material() -> None:
    guidance = read_repo_file("AGENTS.md")

    for pattern in (
        r"/home/",
        r"/Users/",
        r"[A-Za-z]:\\\\",
        r"ssh-rsa",
        r"BEGIN [A-Z]",
    ):
        assert re.search(pattern, guidance) is None, (
            f"AGENTS.md must not contain local paths or secrets: {pattern}"
        )


def test_contributor_checklist_prompts_an_agent_guidance_review() -> None:
    template = read_repo_file(".github/pull_request_template.md")

    assert "AGENTS.md" in template


def test_release_publishes_only_after_validating_the_resolved_sha() -> None:
    workflow = read_repo_file(".github/workflows/release.yml")

    validate_job = workflow.index("\n  validate:")
    tag_job = workflow.index("\n  tag:")
    container_job = workflow.index("\n  container:")
    publish_job = workflow.index("\n  publish:")
    channels_job = workflow.index("\n  channels:")

    assert validate_job < tag_job < container_job < publish_job < channels_job
    assert "target_sha: ${{ steps.meta.outputs.target_sha }}" in workflow
    assert "ref: ${{ needs.resolve.outputs.target_sha }}" in workflow
    assert "../validation-contract/scripts/validate.sh all" in workflow
    assert workflow.count("if: github.event_name != 'pull_request'") == 3
    assert "contents: write" not in workflow[:tag_job]
    assert "git tag -f" not in workflow[tag_job:container_job]
    assert "packages: write" in workflow[container_job:publish_job]
    assert "push: false" in workflow[container_job:publish_job]
    assert "scripts/container-smoke.sh" in workflow[container_job:publish_job]
    assert (
        'docker push "$IMAGE_NAME:$TARGET_TAG"' in workflow[container_job:publish_job]
    )
    assert "ensure_immutable_alias" in workflow[container_job:publish_job]
    assert workflow[container_job:publish_job].count("--prefer-index=false") == 1
    assert workflow.count("--prefer-index=false") == 2
    assert "anchore/sbom-action@v0.24.0" in workflow[container_job:publish_job]
    assert workflow[container_job:publish_job].count("actions/attest@v4") == 2
    assert "sbom-path: container-sbom.spdx.json" in workflow[container_job:publish_job]
    assert "contents: write" in workflow[publish_job:]


def test_release_guards_immutable_and_prerelease_channel_tags() -> None:
    workflow = read_repo_file(".github/workflows/release.yml")

    assert 'update_stable_tag="false"' in workflow
    assert 'update_latest_tag="false"' in workflow
    assert (
        "Floating channel '$channel_tag' must not be an immutable image tag."
        in workflow
    )
    assert "^sha-[0-9a-f]{7,64}$" in workflow
    assert "^[A-Za-z0-9_][A-Za-z0-9_.-]{0,127}$" in workflow
    assert "is not valid for a container image" in workflow
    assert "Floating channel tag names must be distinct." in workflow
    assert "container-release-${{ needs.resolve.outputs.tag }}" in workflow
    assert "group: release-channel-publication" in workflow
    assert "queue: max" in workflow
    assert workflow.index("group: release-channel-publication") > workflow.index(
        "\n  channels:"
    )
    assert "should_promote" in workflow
    assert "sort -V" in workflow
    assert "is stale" in workflow
    assert "steps.container_channels.outputs.stable" in workflow
    assert "Immutable image tag $TARGET_TAG belongs to" in workflow
    assert "Immutable image tag $image_ref already points to" in workflow
    local_smoke = workflow.index(
        "scripts/container-smoke.sh screenos-to-junos:release-candidate"
    )
    registry_login = workflow.index("docker/login-action@v4", local_smoke)
    version_push = workflow.index('docker push "$IMAGE_NAME:$TARGET_TAG"')
    digest_smoke = workflow.index("Smoke test the exact registry digest")
    assert local_smoke < registry_login < version_push < digest_smoke


def test_pr_container_validation_cannot_publish_and_runs_runtime_smoke() -> None:
    workflow = read_repo_file(".github/workflows/container.yml")

    assert "pull_request:" in workflow
    assert "permissions:\n  contents: read" in workflow
    assert "packages: write" not in workflow
    assert "docker/login-action" not in workflow
    assert "push: false" in workflow
    assert "no-cache: true" in workflow
    assert "scripts/container-smoke.sh" in workflow
    for path in ("docker/**", "packages/**", "requirements.txt"):
        assert f'      - "{path}"' in workflow


def test_container_runtime_is_non_root_pinned_and_health_checked() -> None:
    dockerfile = read_repo_file("docker/Dockerfile")
    smoke = read_repo_file("scripts/container-smoke.sh")

    assert re.search(
        r"^FROM python:[^\n]+@sha256:[0-9a-f]{64}$", dockerfile, re.MULTILINE
    )
    assert "USER 10001:10001" in dockerfile
    assert 'ENTRYPOINT ["gunicorn"]' in dockerfile
    assert '"--no-control-socket"' in dockerfile
    assert "HEALTHCHECK" in dockerfile
    assert "/healthz" in dockerfile
    assert "--read-only" in smoke
    assert "--cap-drop ALL" in smoke
    assert "convert.py --help" in smoke
    assert "/convert" in smoke
