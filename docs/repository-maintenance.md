# Repository Maintenance

This document contains repository automation and GitHub workflow operations details that are intentionally excluded from the top-level README.

## CI Workflows

- PR validation: `.github/workflows/pr-validate.yml`
- Security scanning: `.github/workflows/codeql-analysis.yml`

## Release Workflow

Release workflow file: `.github/workflows/release.yml`

### Trigger Modes

- Automatic: push a tag matching `v*.*.*` (for example `v1.4.0`)
- Manual: run workflow `Release` and provide `version` as either `1.2.3` or `v1.2.3`

### Floating Release Tags

Floating tags are maintained for convenience:

- `pre-release` (default tag name)
- `stable` (default tag name)
- `latest` (default tag name)

Push-trigger defaults are configured in `.github/release-tags.env`:

- `PRERELEASE_TAG`
- `STABLE_TAG`
- `LATEST_TAG`
- `UPDATE_STABLE_TAG`
- `UPDATE_PRERELEASE_TAG`
- `UPDATE_LATEST_TAG`

One release can therefore point to multiple tags at once:

- the immutable version tag (for example `v2.0.1`)
- optional floating channel tags such as `pre-release`, `latest`, and `stable`

### Token Requirements For Tag Moves

If floating tag updates point to a commit that changes files under `.github/workflows/`, GitHub can reject updates made with the default Actions token.

Set repository secret `RELEASE_TAG_PUSH_TOKEN` with:

- `contents: write`
- `workflows: write`

### Action Runtime Compatibility

Workflows are pinned to Node 24-compatible major versions:

- `actions/checkout@v6`
- `actions/setup-python@v6`
- `github/codeql-action@v4`
- `softprops/action-gh-release@v3`
