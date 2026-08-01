# Repository Maintenance

This document contains repository automation and GitHub workflow operations details that are intentionally excluded from the top-level README.

## CI Workflows

- PR validation: `.github/workflows/pr-validate.yml`
- Non-publishing container validation: `.github/workflows/container.yml`
- Security scanning: `.github/workflows/codeql-analysis.yml`

## Release Workflow

Release workflow file: `.github/workflows/release.yml`

### Trigger Modes

- Automatic: push a tag matching `v*.*.*` (for example `v1.4.0`)
- Manual: run workflow `Release` and provide `version` as either `1.2.3` or `v1.2.3`
- Optional for manual runs: set `target_commitish` to a specific commit, branch, or tag (for example `66d3df8`) to create the release from that historic ref
- Short commit SHAs are resolved to full commit IDs before calling the GitHub release API

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

One Git commit can therefore be referenced by multiple tags at once:

- the immutable version tag (for example `v2.0.1`)
- optional floating channel tags such as `pre-release`, `latest`, and `stable`

The GitHub Release object itself still uses the version tag. The `pre-release` floating tag is only moved when the release is marked prerelease.

For non-prerelease releases, `UPDATE_LATEST_TAG` / `update_latest_tag` also controls whether the GitHub Release is marked as Latest.

`stable` is a floating git tag only; GitHub Releases does not have a separate "Stable" badge.

The same channel names are applied to container images when their update flags
are enabled. Every release also publishes immutable version and full commit-SHA
image tags. Deploy version or SHA tags; channel tags are convenience pointers
and can move. Channel names must satisfy both Git and Docker tag syntax, be
distinct, and cannot use version- or SHA-shaped names. Prereleases update only
the prerelease channel; they never advance `stable` or `latest`.

Git and container channel moves run together in one serialized job after the
immutable image and GitHub Release are complete. The concurrency group uses the
maximum pending queue so intermediate promotions are not dropped. This prevents
overlapping releases from writing simultaneously. Before moving anything, the job compares
the incoming release version with the version metadata on each existing image
channel. A stale release cannot move either the Git or container channel
backward; its immutable version and SHA assets remain available.

### Container Registry

Release images are published to
`ghcr.io/greyinghair/screenos_to_junos_converter` only after the resolved commit
passes the Python validation contract and a clean container build passes CLI,
health, and web conversion smoke tests. The image runs Gunicorn as UID/GID
10001 and includes OCI metadata. The exact local candidate is pushed and then
smoke-tested by registry digest. Syft generates an SPDX SBOM for each new
immutable image, and GitHub publishes both provenance and SBOM attestations.
Reruns verify an existing version tag's source revision and digest instead of
replacing it.

The release container job has `contents: read`, `packages: write`,
`id-token: write`, and `attestations: write`; the channel job has only the
`contents: write` and `packages: write` permissions needed to move both channel
types together. Pull-request container validation has read-only repository
permission, does not log in to a registry, and never pushes an image.

GitHub package visibility and pull access are managed in the package settings.
Keep immutable version and SHA tags for the supported release lifetime. If an
automated retention rule is introduced, exclude those immutable tags and only
prune untagged manifests or obsolete channel history after confirming no
deployment references the digest.

### Token Requirements For Tag Moves

If floating tag updates point to a commit that changes files under
`.github/workflows/`, GitHub can reject updates made with the default Actions
token.

Set repository secret `RELEASE_TAG_PUSH_TOKEN` with:

- `contents: write`
- `workflows: write`

This token is used when moving floating Git tags. Container publication uses
the job-scoped GitHub token and does not use this secret.

### Versioned Actions

Workflows use explicit maintained action releases:

- `actions/checkout@v7`
- `actions/setup-python@v7`
- `docker/build-push-action@v7`
- `docker/login-action@v4`
- `docker/metadata-action@v6`
- `docker/setup-buildx-action@v4`
- `actions/attest@v4`
- `anchore/sbom-action@v0.24.0`
- `github/codeql-action@v4`
- `softprops/action-gh-release@v3`
