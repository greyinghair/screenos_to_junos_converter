#!/usr/bin/env bash

set -uo pipefail

mode="${1:-all}"
python_bin="${PYTHON_BIN:-}"
artifact_dir="${ARTIFACT_DIR:-artifacts}"
junit_xml="${JUNIT_XML:-${artifact_dir}/junit.xml}"
coverage_xml="${COVERAGE_XML:-${artifact_dir}/coverage.xml}"
script_dir="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
contract_root="$(cd -- "${script_dir}/.." && pwd)"
ruff_config="${RUFF_CONFIG:-${contract_root}/pyproject.toml}"
coverage_config="${COVERAGE_CONFIG:-${contract_root}/pyproject.toml}"

if [[ -z "$python_bin" ]]; then
  if command -v python >/dev/null 2>&1; then
    python_bin="python"
  else
    python_bin="python3"
  fi
fi

mkdir -p "$artifact_dir"

run_tests() {
  local result=0

  "$python_bin" -m compileall -q convert.py packages tests || result=1
  "$python_bin" -m pytest -q --junitxml="$junit_xml" || result=1

  return "$result"
}

run_all() {
  local result=0

  "$python_bin" -m ruff check --config "$ruff_config" . || result=1
  "$python_bin" -m ruff format --config "$ruff_config" --check . || result=1
  "$python_bin" -m compileall -q convert.py packages tests || result=1
  "$python_bin" -m pytest -q \
    --junitxml="$junit_xml" \
    --cov=. \
    --cov-branch \
    --cov-config="$coverage_config" \
    --cov-report=term-missing \
    --cov-report="xml:${coverage_xml}" || result=1

  return "$result"
}

case "$mode" in
  test)
    run_tests
    ;;
  all)
    run_all
    ;;
  *)
    echo "Usage: $0 [test|all]" >&2
    exit 2
    ;;
esac
