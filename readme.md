# ScreenOS to Junos Converter

[![Python 3.12](https://img.shields.io/github/check-runs/greyinghair/screenos_to_junos_converter/main?nameFilter=Python%203.12&label=Python%203.12&logo=python)](https://github.com/greyinghair/screenos_to_junos_converter/actions/workflows/pr-validate.yml?query=branch%3Amain)
[![Python 3.13](https://img.shields.io/github/check-runs/greyinghair/screenos_to_junos_converter/main?nameFilter=Python%203.13&label=Python%203.13&logo=python)](https://github.com/greyinghair/screenos_to_junos_converter/actions/workflows/pr-validate.yml?query=branch%3Amain)
[![Python 3.14](https://img.shields.io/github/check-runs/greyinghair/screenos_to_junos_converter/main?nameFilter=Python%203.14&label=Python%203.14&logo=python)](https://github.com/greyinghair/screenos_to_junos_converter/actions/workflows/pr-validate.yml?query=branch%3Amain)

This program converts a tested subset of Juniper ScreenOS services, addresses,
interfaces, routing, NAT, firewall policies, IPsec VPNs, and IDP attachments
into Junos SRX `set` commands.
It is a migration aid, not a complete device configuration translator.

## What It Converts

- TCP and UDP custom services with numeric destination ports, plus supported
  ScreenOS default services.
- Service groups to Junos application sets.
- Dotted-IPv4/netmask addresses and FQDN addresses, plus address groups, to
  zone or global address books and address sets.
- Physical Ethernet interfaces, tagged subinterfaces, VLAN/IRB interfaces,
  tunnel interfaces, and the management interface. The converter handles
  descriptions, CIDR IPv4 and IPv6 interface addresses, MTU, administrative
  state, VLAN tags, IPv4 unnumbered donors, and security-zone bindings.
- Numeric zone-specific and global permit/deny/reject policies through one
  policy model, including names, ordering directives, multiline source,
  destination, and service matches, logging, and counters. Zone policies are
  emitted before global policies to reflect Junos evaluation precedence.
- Static routes in the default or named virtual routers, including mapped
  interfaces, next hops, metrics, preferences, tags, and discard routes.
- BGP local-AS/router-ID configuration and enabled IPv4/IPv6 peers, including
  peer groups, hold times, source interfaces, and import/export policy
  references.
- MIP static NAT, DIP source pools, and policy-linked DIP or egress-interface
  source NAT. NAT rules reuse converted interfaces, zones, address prefixes,
  services, and policy ordering.
- Disabled policies are identified and intentionally omitted with a
  line-specific diagnostic, including their linked NAT rules.
- Explicit IKE Phase 1 and IPsec Phase 2 proposals, static or dynamic IKE
  gateways, route-based VPNs bound to converted `st0` interfaces, proxy IDs,
  and paired policy-based VPN actions. Preshared secrets are redacted and must
  be configured manually on the generated IKE policy.
- ScreenOS Deep Inspection severity/service signature and anomaly groups to
  Junos dynamic attack groups and ordered IDP rulebases, attached directly to
  the converted permit policy on Junos 18.2R1 and later.

The exact accepted ScreenOS grammar and Junos output hierarchy are maintained
in the [conversion support matrix](docs/conversion-support-matrix.md).

## What It Does Not Convert

- [XML input or output](https://github.com/greyinghair/screenos_to_junos_converter/issues/4)
- Source-based routes, BGP network origination/redistribution, and ScreenOS
  route-map definitions. BGP MD5 authentication secrets are redacted and
  diagnosed instead of being copied into generated configuration; configure
  authentication keys manually on the target. Converted BGP import/export
  policy names must already exist on the target or be migrated separately.
- Policy NAT-dst/VIP, global policy NAT-src, raw interface NAT mode without
  destination context, and extended/incoming/random/shifted DIP variants.
- Platform-specific interface aliases outside the documented
  Ethernet/`mgt`/`tunnel.N`/`vlanN` mapping, management-interface MTU, or
  interface attributes outside the tested support matrix.
- IPv6, CIDR, wildcard, and address-range address-book input forms;
  non-TCP/UDP custom services; service source-port rendering; and policy
  schedules, alert logging, count alarms, or other unlisted policy options.
- IKE security-level bundles, IKEv2-specific syntax, certificate authentication,
  VPN groups/L2TP/manual-key VPNs, multiple proposals, service-specific proxy
  IDs, and nonzero VPN idle timers. DES and MD5 are rejected; legacy DH, 3DES,
  and SHA-1 selections are preserved only with deprecation diagnostics.
- Arbitrary ScreenOS IDP signature names, custom attack definitions, IP-actions,
  per-attack logging suppression, exempt rulebases, and application DDoS rules.
  Unknown signatures are reported, never silently replaced with a Junos
  signature, and cause the affected firewall policy to be omitted rather than
  rendered as an uninspected permit.

Unsupported or unrecognized lines are reported with line numbers and reasons.
Always review the generated configuration before deployment.

## Python Version

- Tested and supported: Python 3.12–3.14
- Experimental weekly canaries exercise the next Python prerelease and the
  newest resolvable pytest prerelease. Canary success does not promote either
  one into the supported range.

## Project Structure
- `convert.py`: thin CLI entrypoint and argument parsing
- `packages/converter_core.py`: conversion engine and state model
- `packages/conversion_models.py`: normalized interface, policy, routing, and NAT models
- `packages/convert_service.py`: service parsing/conversion helpers
- `packages/sanity_check_naming.py`: Junos-safe name normalization
- `packages/ipy.py`: local IP utility module used for address conversion
- `tests/`: pytest fixtures and regression tests
- `tests/fixtures/`: sanitized positive, negative, and end-to-end configurations


## Repository Tree
<!-- repo-tree:start -->
```text
.
|-- convert.py                          # CLI entrypoint: parses args and runs conversion
|-- readme.md                           # Project overview, usage, CI, and development guidance
|-- requirements.txt                    # Runtime dependencies
|-- requirements-dev.txt                # Ranged developer dependencies
|-- requirements-dev-minimum.txt        # Exact supported dependency floors
|-- requirements-dev-latest.txt         # Exact latest-compatible dependencies
|-- pyproject.toml                       # Ruff, coverage, and pytest configuration
|-- docker/                             # Container build context
|   `-- Dockerfile                      # Container image definition
|-- docs/                               # Vendor reference docs
|   |-- readme.md                       # Notes on bundled vendor documentation
|   |-- dependency-policy.md            # Version, quality, and security policy
|   |-- conversion-support-matrix.md    # Accepted grammar and known limitations
|   |-- screenos/                       # ScreenOS command references
|   `-- junos/                          # Junos command references
|-- packages/                           # Python package with conversion logic
|   |-- __init__.py                     # Explicit package exports
|   |-- converter_core.py               # Core conversion engine and state
|   |-- conversion_models.py            # Normalized interface, policy, routing, and NAT models
|   |-- convert_service.py              # Service conversion helpers
|   |-- sanity_check_naming.py          # Name normalization for Junos compatibility
|   `-- ipy.py                          # Local IP/network parsing utility
|-- tests/                              # Regression and unit tests
|   |-- conftest.py                     # Shared pytest fixtures
|   |-- test_automation_contracts.py    # CI, dependency, and release contracts
|   |-- test_cli.py                     # CLI path and diagnostics tests
|   |-- test_converter_smoke.py         # End-to-end smoke test
|   |-- test_converter_syntax_coverage.py # Supported grammar tests
|   |-- test_policy_interface_models.py # Interface mapping and shared policy model tests
|   |-- test_routing_nat_models.py      # Routing and NAT model/reference tests
|   |-- test_validation_fixtures.py     # Fixture validation harness
|   |-- fixtures/                       # Sanitized conversion fixtures
|   |-- test_convert_service.py         # Service parser unit tests
|   `-- test_sanity_check_naming.py     # Naming helper unit tests
|-- scripts/                            # Local maintenance/helper scripts
|   |-- update-readme-tree.sh           # Regenerates this README tree section
|   `-- validate.sh                     # Shared local, CI, and release validation
`-- .github/                            # Repository automation and CI config
    |-- dependabot.yml                  # Automated dependency updates
    `-- workflows/                      # GitHub Actions workflows
        |-- pr-validate.yml             # Required Python and quality CI
        |-- prerelease-canary.yml       # Non-blocking Python/pytest canaries
        |-- codeql-analysis.yml         # Security analysis workflow
        |-- dependency-review.yml       # Vulnerable dependency gate
        `-- release.yml                 # Validated release publishing
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
- Each unconverted line produces a line-numbered diagnostic explaining why it
  was omitted.
- IPsec and IDP conversion adds an explicit `MANUAL REVIEW REQUIRED` warning.
  Validate peer IDs, keys, routing/NAT, algorithms, Junos version and platform,
  signature package contents, and IDP licensing before deployment.

## Development

### Runtime Dependencies
No external runtime dependencies are required.

### Dev Dependencies
```bash
python3 -m pip install --no-cache-dir -r requirements-dev.txt
```

### Validate and Test
```bash
scripts/validate.sh all
```

Feature changes must add or update sanitized fixtures in the same pull request.
The fixture harness asserts exact deterministic output, conversion counts, and
unsupported-line diagnostics.

To reproduce the dependency boundaries used in CI:

```bash
python3 -m pip install \
  -r requirements.txt \
  -r requirements-dev.txt \
  -c requirements-dev-minimum.txt
scripts/validate.sh test
```

Replace `requirements-dev-minimum.txt` with `requirements-dev-latest.txt` for
the latest-compatible environment. See the
[dependency and validation policy](docs/dependency-policy.md) for the
version-boundary, coverage, vulnerability, and license rules.

### Docker
```bash
docker build -f docker/Dockerfile -t screenos-to-junos .
docker run --rm -v "$PWD":/app screenos-to-junos \
  python convert.py --input input/netscreen_config.txt --output outputs/converted_from_container.txt
```

## Reference Documentation
- `docs/screenos/` contains ScreenOS reference PDFs
- `docs/junos/` contains Junos CLI reference PDFs
- [Conversion support matrix](docs/conversion-support-matrix.md) defines the
  accepted grammar, rendered Junos hierarchy, and known limitations.

These references are intended to support future enhancement of conversion coverage.
