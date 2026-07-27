# Dependency and Validation Policy

## Supported environments

The primary CI matrix runs the required test suite on Python 3.12, 3.13, and
3.14. The stable `required` job succeeds only after that matrix, code-quality
validation, coverage, and both dependency-boundary jobs pass.

Direct development dependencies declare an inclusive floor and exclusive major
ceiling in `requirements-dev.txt`:

- pytest 9.0.3 through the latest compatible 9.x release
- pytest-cov 7.0.0 through the latest compatible 7.x release
- Ruff 0.15.0 through the latest compatible pre-1.0 release

`requirements-dev-minimum.txt` pins every declared floor.
`requirements-dev-latest.txt` pins the latest versions validated when the file
was updated. Their root-level names make them discoverable by Dependabot. A
floor changes only when the project intentionally adopts behavior unavailable
in the old floor; a ceiling changes only after the next major line passes the
full validation contract.

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
target and tested SHA in the workflow summary. Only the publishing job receives
`contents: write`; it creates or moves release tags only after validation and
verifies that every published tag resolves to the tested SHA.
