# ScreenOS to Junos Converter

This repository converts selected Juniper ScreenOS configuration objects into Junos SRX `set` commands to help with migration projects.

## What It Converts
- Custom services/applications
- Service groups to Junos application-sets
- Addresses and address groups to address-book entries/sets
- Policies (including multiline `set src-address`, `set dst-address`, and `set service` continuations)

## What It Does Not Fully Convert
- NAT behavior (MIP/DIP/interface NAT still requires manual migration)
- Interfaces
- VPNs
- Routes
- Global policy behavior

Use converted output as a migration accelerator, not as an unattended full-fidelity migration.

## Python Version
- Recommended: Python 3.14 (latest stable release as of 2026-04-01)
- Supported: Python 3.12+

## Project Structure
- `convert.py`: thin CLI entrypoint and argument parsing
- `packages/converter_core.py`: conversion engine and state model
- `packages/convert_service.py`: service parsing/conversion helpers
- `packages/sanity_check_naming.py`: Junos-safe name normalization
- `packages/ipy.py`: local IP utility module used for address conversion
- `tests/`: pytest fixtures and regression tests


## Repository Tree
<!-- repo-tree:start -->
```text
.
|-- convert.py                          # CLI entrypoint: parses args and runs conversion
|-- readme.md                           # Project overview, usage, CI, and development guidance
|-- requirements.txt                    # Runtime dependencies
|-- requirements-dev.txt                # Developer dependencies (pytest)
|-- input/                              # Source ScreenOS configs to convert
|   `-- netscreen_config.txt            # Default converter input file
|-- outputs/                            # Generated Junos conversion outputs (txt ignored)
|-- docker/                             # Container build context
|   `-- Dockerfile                      # Container image definition
|-- docs/                               # Vendor reference docs
|   |-- readme.md                       # Notes on bundled vendor documentation
|   |-- screenos/                       # ScreenOS command references
|   `-- junos/                          # Junos command references
|-- packages/                           # Python package with conversion logic
|   |-- __init__.py                     # Explicit package exports
|   |-- converter_core.py               # Core conversion engine and state
|   |-- convert_service.py              # Service conversion helpers
|   |-- sanity_check_naming.py          # Name normalization for Junos compatibility
|   `-- ipy.py                          # Local IP/network parsing utility
|-- tests/                              # Regression and unit tests
|   |-- conftest.py                     # Shared pytest fixtures
|   |-- test_converter_smoke.py         # End-to-end smoke test
|   |-- test_convert_service.py         # Service parser unit tests
|   `-- test_sanity_check_naming.py     # Naming helper unit tests
|-- scripts/                            # Local maintenance/helper scripts
|   |-- session-close.sh                # Appends dated session handoff template
|   `-- update-readme-tree.sh           # Regenerates this README tree section
`-- .github/                            # Repository automation and CI config
    `-- workflows/                      # GitHub Actions workflows
        |-- pr-validate.yml             # PR CI: py_compile + pytest
        `-- codeql-analysis.yml         # Security analysis workflow
```
<!-- repo-tree:end -->

## Usage
1. Place your full ScreenOS config in a text file (default: `input/netscreen_config.txt`).
2. Run:

```bash
python3 convert.py --input input/netscreen_config.txt
```

Optional flags:

```bash
python3 convert.py \
  --input input/netscreen_config.txt \
  --output outputs/converted_custom.txt \
  --progress-interval 500 \
  --log-level INFO
```

## Output
- Default output file: `outputs/converted_<YYYYMMDD_HHMMSS>.txt`
- Contains generated Junos `set` commands.

## Security and Operational Notes
- Review output before deployment. Firewall migrations are security-sensitive and should include human validation.
- Sample configs may contain sensitive values; avoid committing real production configs to source control.
- Unmatched or unsupported lines are counted in the "NOT converted" metric.

## Development

### Runtime Dependencies
No external runtime dependencies are required.

### Dev Dependencies
```bash
python3 -m pip install --no-cache-dir -r requirements-dev.txt
```

### Validate and Test
```bash
python3 -m py_compile convert.py packages/converter_core.py \
  packages/convert_service.py packages/sanity_check_naming.py
python3 -m pytest -q
```

### Refresh Repository Tree
```bash
./scripts/update-readme-tree.sh
```

CI also runs these checks automatically on every pull request via `.github/workflows/pr-validate.yml`. Security analysis remains in `.github/workflows/codeql-analysis.yml`.

### Docker
```bash
docker build -f docker/Dockerfile -t screenos-to-junos .
docker run --rm -v "$PWD":/app screenos-to-junos \
  python convert.py --input input/netscreen_config.txt --output outputs/converted_from_container.txt
```

## Reference Documentation
- `docs/screenos/` contains ScreenOS reference PDFs
- `docs/junos/` contains Junos CLI reference PDFs

These references are intended to support future enhancement of conversion coverage.
