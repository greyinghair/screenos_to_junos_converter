# Dependency and Validation Policy

## Supported environments

The primary CI matrix runs the required test suite on Python 3.12, 3.13, and
3.14. The stable `required` job succeeds only after that matrix, code-quality
validation, coverage, and both dependency-boundary jobs pass.

Direct development dependencies declare an inclusive floor and exclusive
ceiling in `requirements-dev.txt`. That file is the executable source of truth
for the current supported ranges; the exact values are intentionally not
duplicated here because Dependabot updates them.

`requirements-dev-minimum.txt` pins every declared floor.
`requirements-dev-latest.txt` pins the latest versions validated when the file
was updated. Their root-level names make them discoverable by Dependabot. A
floor changes only when the project intentionally adopts behavior unavailable
in the old floor; a ceiling changes only after the next major line passes the
full validation contract.

Direct production dependencies in `requirements.txt` are exact pins. This
keeps web and WSGI runtime resolution deterministic in the release container;
Dependabot proposes reviewed updates to those pins and the digest-pinned base
image.

## Prerelease canaries

The scheduled `prerelease-canary.yml` workflow runs every Monday and can also be
started manually. One independent job tests the next Python prerelease
(currently Python 3.15); another installs the newest resolvable pytest
prerelease on the newest supported Python. Both use `scripts/validate.sh test`,
record the resolved Python and package versions in the workflow summary, and
retain failure artifacts for 14 days.

The canary has no `push` or `pull_request` trigger, so it cannot become a
required check for ordinary changes. A prerelease is promoted only through an
explicit update to the supported CI matrix, dependency policy, and README.

## Quality and coverage

`scripts/validate.sh` is the shared local, CI, and release validation entry
point. The `all` mode runs Ruff lint and formatting checks, recursively compiles
all Python under `convert.py`, `packages/`, and `tests/`, then runs pytest with
branch coverage.

The initial coverage floor is 43%, including the bundled `packages/ipy.py`
compatibility module. This reflects the measured baseline and should only move
upward as coverage is added. CI uploads JUnit and coverage XML diagnostics when
quality validation fails.

Ruff excludes `packages/ipy.py` from lint and formatting because it is bundled
compatibility code maintained as a vendor-derived unit. It remains included in
recursive syntax checks and the coverage baseline.

## Vulnerability and license policy

Pull requests fail dependency review when they introduce a vulnerability rated
moderate, high, or critical in runtime, development, or unknown scope. There are
currently no vulnerability exceptions.

License enforcement is intentionally disabled until the project adopts a
separate approved allow or deny policy. Any future vulnerability or license
exception must be documented here with its owner, justification, and removal
date before it is configured in the workflow.

## Automated updates

Dependabot checks Python requirements, GitHub Actions, and the Dockerfile every
Monday. Compatible minor and patch updates are grouped per ecosystem, labeled,
and bounded by open-pull-request limits to keep review volume manageable.

## Release validation

The release workflow resolves every requested branch, tag, or SHA to an
immutable commit. It checks out that commit separately from the current
validation contract, runs `scripts/validate.sh all`, and records the requested
target and tested SHA in the workflow summary. Only the tag, GitHub Release,
and serialized channel jobs receive `contents: write`; only the container and
channel jobs receive `packages: write`. The immutable version tag is created without force after
validation. A clean, non-publishing container candidate then passes CLI,
health, and conversion smoke checks before that exact image is pushed. Existing
version/SHA image tags are verified rather than replaced. The published digest
is smoke-tested again, scanned for an SPDX SBOM, and given provenance and SBOM
attestations. The final job publishes the GitHub Release and verifies every
requested floating tag against the tested SHA.
