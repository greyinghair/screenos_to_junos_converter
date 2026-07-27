#!/bin/sh
set -eu

README="readme.md"
START_MARKER="<!-- repo-tree:start -->"
END_MARKER="<!-- repo-tree:end -->"

if [ ! -f "$README" ]; then
  echo "ERROR: $README not found" >&2
  exit 1
fi

if ! grep -q "$START_MARKER" "$README"; then
  echo "ERROR: start marker not found in $README" >&2
  exit 1
fi

if ! grep -q "$END_MARKER" "$README"; then
  echo "ERROR: end marker not found in $README" >&2
  exit 1
fi

TREE_BLOCK_FILE="$(mktemp)"
OUTPUT_FILE="$(mktemp)"
trap 'rm -f "$TREE_BLOCK_FILE" "$OUTPUT_FILE"' EXIT

{
  echo '```text'
  echo '.'

  [ -f convert.py ] && echo '|-- convert.py                          # CLI entrypoint: parses args and runs conversion'
  [ -f readme.md ] && echo '|-- readme.md                           # Project overview, usage, CI, and development guidance'
  [ -f requirements.txt ] && echo '|-- requirements.txt                    # Runtime dependencies'
  [ -f requirements-dev.txt ] && echo '|-- requirements-dev.txt                # Ranged developer dependencies'
  [ -f requirements-dev-minimum.txt ] && echo '|-- requirements-dev-minimum.txt        # Exact supported dependency floors'
  [ -f requirements-dev-latest.txt ] && echo '|-- requirements-dev-latest.txt         # Exact latest-compatible dependencies'
  [ -f pyproject.toml ] && echo '|-- pyproject.toml                       # Ruff, coverage, and pytest configuration'
  if [ -d input ]; then
    echo '|-- input/                              # Source ScreenOS configs to convert'
    [ -f input/netscreen_config.txt ] && echo '|   `-- netscreen_config.txt            # Default converter input file'
  fi

  if [ -d outputs ]; then
    echo '|-- outputs/                            # Generated Junos conversion outputs (txt ignored)'
  fi

  if [ -d docker ]; then
    echo '|-- docker/                             # Container build context'
    [ -f docker/Dockerfile ] && echo '|   `-- Dockerfile                      # Container image definition'
  fi

  if [ -d docs ]; then
    echo '|-- docs/                               # Vendor reference docs'
    [ -f docs/readme.md ] && echo '|   |-- readme.md                       # Notes on bundled vendor documentation'
    [ -f docs/dependency-policy.md ] && echo '|   |-- dependency-policy.md            # Version, quality, and security policy'
    [ -d docs/screenos ] && echo '|   |-- screenos/                       # ScreenOS command references'
    [ -d docs/junos ] && echo '|   `-- junos/                          # Junos command references'
  fi

  if [ -d packages ]; then
    echo '|-- packages/                           # Python package with conversion logic'
    [ -f packages/__init__.py ] && echo '|   |-- __init__.py                     # Explicit package exports'
    [ -f packages/converter_core.py ] && echo '|   |-- converter_core.py               # Core conversion engine and state'
    [ -f packages/convert_service.py ] && echo '|   |-- convert_service.py              # Service conversion helpers'
    [ -f packages/sanity_check_naming.py ] && echo '|   |-- sanity_check_naming.py          # Name normalization for Junos compatibility'
    [ -f packages/ipy.py ] && echo '|   `-- ipy.py                          # Local IP/network parsing utility'
  fi

  if [ -d tests ]; then
    echo '|-- tests/                              # Regression and unit tests'
    [ -f tests/conftest.py ] && echo '|   |-- conftest.py                     # Shared pytest fixtures'
    [ -f tests/test_automation_contracts.py ] && echo '|   |-- test_automation_contracts.py    # CI, dependency, and release contracts'
    [ -f tests/test_cli.py ] && echo '|   |-- test_cli.py                     # CLI path and diagnostics tests'
    [ -f tests/test_converter_smoke.py ] && echo '|   |-- test_converter_smoke.py         # End-to-end smoke test'
    [ -f tests/test_converter_syntax_coverage.py ] && echo '|   |-- test_converter_syntax_coverage.py # Supported grammar tests'
    [ -f tests/test_validation_fixtures.py ] && echo '|   |-- test_validation_fixtures.py     # Fixture validation harness'
    [ -d tests/fixtures ] && echo '|   |-- fixtures/                       # Sanitized conversion fixtures'
    [ -f tests/test_convert_service.py ] && echo '|   |-- test_convert_service.py         # Service parser unit tests'
    [ -f tests/test_sanity_check_naming.py ] && echo '|   `-- test_sanity_check_naming.py     # Naming helper unit tests'
  fi

  if [ -d scripts ]; then
    echo '|-- scripts/                            # Local maintenance/helper scripts'
    [ -f scripts/session-close.sh ] && echo '|   |-- session-close.sh                # Appends dated session handoff template'
    [ -f scripts/update-readme-tree.sh ] && echo '|   |-- update-readme-tree.sh           # Regenerates this README tree section'
    [ -f scripts/validate.sh ] && echo '|   `-- validate.sh                     # Shared local, CI, and release validation'
  fi

  if [ -d .github ]; then
    echo '`-- .github/                            # Repository automation and CI config'
    [ -f .github/dependabot.yml ] && echo '    |-- dependabot.yml                  # Automated dependency updates'
    if [ -d .github/workflows ]; then
      echo '    `-- workflows/                      # GitHub Actions workflows'
      [ -f .github/workflows/pr-validate.yml ] && echo '        |-- pr-validate.yml             # Required Python and quality CI'
      [ -f .github/workflows/codeql-analysis.yml ] && echo '        |-- codeql-analysis.yml         # Security analysis workflow'
      [ -f .github/workflows/dependency-review.yml ] && echo '        |-- dependency-review.yml       # Vulnerable dependency gate'
      [ -f .github/workflows/release.yml ] && echo '        `-- release.yml                 # Validated release publishing'
    fi
  fi

  echo '```'
} > "$TREE_BLOCK_FILE"

awk -v start="$START_MARKER" -v end="$END_MARKER" -v repl="$TREE_BLOCK_FILE" '
$0 == start {
  print
  while ((getline line < repl) > 0) {
    print line
  }
  skip = 1
  next
}
$0 == end {
  skip = 0
  print
  next
}
!skip {
  print
}
' "$README" > "$OUTPUT_FILE"

mv "$OUTPUT_FILE" "$README"

echo "Updated README repository tree section."
