# ScreenOS to Junos Converter

[![Python 3.12](https://img.shields.io/github/check-runs/greyinghair/screenos_to_junos_converter/main?nameFilter=Python%203.12&label=Python%203.12&logo=python)](https://github.com/greyinghair/screenos_to_junos_converter/actions/workflows/pr-validate.yml?query=branch%3Amain)
[![Python 3.13](https://img.shields.io/github/check-runs/greyinghair/screenos_to_junos_converter/main?nameFilter=Python%203.13&label=Python%203.13&logo=python)](https://github.com/greyinghair/screenos_to_junos_converter/actions/workflows/pr-validate.yml?query=branch%3Amain)
[![Python 3.14](https://img.shields.io/github/check-runs/greyinghair/screenos_to_junos_converter/main?nameFilter=Python%203.14&label=Python%203.14&logo=python)](https://github.com/greyinghair/screenos_to_junos_converter/actions/workflows/pr-validate.yml?query=branch%3Amain)

This program converts a tested subset of Juniper ScreenOS services, addresses,
interfaces, routing, NAT, firewall policies, IPsec VPNs, and IDP attachments
into Junos SRX `set` commands.
It is a migration aid, not a complete device configuration translator.

## What It Converts

- TCP and UDP custom services with numeric destination ports, ICMP services
  with a type and optional code, numeric IP-protocol services, plus supported
  ScreenOS default services.
- Service groups to Junos application sets, including group comments as
  application-set descriptions.
- Dotted-IPv4/netmask addresses and FQDN addresses, plus address groups and
  their comments, to zone or global address books and address sets.
- Physical Ethernet interfaces, tagged subinterfaces, VLAN/IRB interfaces,
  tunnel interfaces, and the management interface. The converter handles
  descriptions, CIDR or dotted-netmask IPv4 and IPv6 interface addresses, MTU,
  administrative state, VLAN tags, IPv4 unnumbered donors, and security-zone
  bindings.
- Optional operator-approved interface mappings that retarget a ScreenOS
  interface onto a chosen Junos interface, logical unit, and tagged or untagged
  VLAN. An applied mapping rewrites every supported reference — zones, policies
  through their zones, static routes, routing instances, MIP/DIP NAT, proxy ARP,
  unnumbered donors, and VPN bindings — and is recorded as a comment at the top
  of the generated configuration. Mappings are validated before conversion, and
  conflicting destinations, dropped VLAN tags, and unusable mappings are
  diagnosed instead of rendered. Without a mapping the default interface-name
  strategy is unchanged.
- An interface binding inventory that reports, for each ScreenOS interface, the
  zones, policies, address objects, routes, routing instances, NAT rules, VPN
  and tunnel references, unnumbered donors, and unsupported attributes that
  depend on it, plus references to interfaces the configuration never defines.
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
- The command forms a device writes when it saves its configuration: blank
  and comment lines, `set policy id NUMBER` context blocks terminated by
  `exit`, in-context `set log` and `set count` flags, and the abbreviated
  `vr` keyword on MIPs.
- Disabled policies are identified and intentionally omitted with a
  line-specific diagnostic, including their linked NAT rules. Scheduled
  policies are omitted the same way so a time-bounded rule is never
  converted into an always-on one.
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
  interface attributes outside the tested support matrix. Interface mapping
  destinations are limited to the documented Junos families, and one ScreenOS
  interface maps to exactly one Junos unit.
- The interactive interface-mapping workspace in the web page:
  [issue 70](https://github.com/greyinghair/screenos_to_junos_converter/issues/70).
  Approved mappings are accepted by the conversion service and the CLI today,
  and the web page shows the interface inventory read-only.
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
- `packages/conversion_service.py`: request-scoped in-memory conversion API
- `packages/conversion_models.py`: normalized interface, policy, routing, and NAT models
- `packages/interface_inventory.py`: interface binding inventory for migration mapping
- `packages/convert_service.py`: service parsing/conversion helpers
- `packages/web_app.py`: Flask application factory, input validation, and routes
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
|-- AGENTS.md                           # Contributor and AI agent guidance for this repository
|-- requirements.txt                    # Runtime dependencies
|-- requirements-dev.txt                # Ranged developer dependencies
|-- requirements-dev-minimum.txt        # Exact supported dependency floors
|-- requirements-dev-latest.txt         # Exact latest-compatible dependencies
|-- pyproject.toml                       # Ruff, coverage, and pytest configuration
|-- .dockerignore                       # Reproducible container build exclusions
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
|   |-- conversion_service.py           # Request-scoped in-memory conversion API
|   |-- interface_inventory.py          # Interface binding inventory for migration mapping
|   |-- convert_service.py              # Service conversion helpers
|   |-- web_app.py                      # Flask application factory and routes
|   |-- static/                         # Web application styles and behavior
|   |-- templates/                      # Web application HTML templates
|   |-- sanity_check_naming.py          # Name normalization for Junos compatibility
|   `-- ipy.py                          # Local IP/network parsing utility
|-- tests/                              # Regression and unit tests
|   |-- conftest.py                     # Shared pytest fixtures
|   |-- test_automation_contracts.py    # CI, dependency, and release contracts
|   |-- test_cli.py                     # CLI path and diagnostics tests
|   |-- test_conversion_service.py      # In-memory service and isolation tests
|   |-- test_converter_smoke.py         # End-to-end smoke test
|   |-- test_converter_syntax_coverage.py # Supported grammar tests
|   |-- test_policy_interface_models.py # Interface mapping and shared policy model tests
|   |-- test_routing_nat_models.py      # Routing and NAT model/reference tests
|   |-- test_validation_fixtures.py     # Fixture validation harness
|   |-- test_web_app.py                 # Flask request and security tests
|   |-- fixtures/                       # Sanitized conversion fixtures
|   |-- test_convert_service.py         # Service parser unit tests
|   `-- test_sanity_check_naming.py     # Naming helper unit tests
|-- scripts/                            # Local maintenance/helper scripts
|   |-- container-smoke.sh              # Reusable CLI and web image smoke checks
|   |-- update-readme-tree.sh           # Regenerates this README tree section
|   `-- validate.sh                     # Shared local, CI, and release validation
`-- .github/                            # Repository automation and CI config
    |-- dependabot.yml                  # Automated dependency updates
    `-- workflows/                      # GitHub Actions workflows
        |-- pr-validate.yml             # Required Python and quality CI
        |-- container.yml               # Non-publishing image build and smoke test
        |-- prerelease-canary.yml       # Non-blocking Python/pytest canaries
        |-- codeql-analysis.yml         # Security analysis workflow
        |-- dependency-review.yml       # Vulnerable dependency gate
        `-- release.yml                 # Validated release publishing
```
<!-- repo-tree:end -->

## Usage

### Command line

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
  --interface-map input/interface_map.json \
  --interface-inventory outputs/interface_inventory.json \
  --progress-interval 500 \
  --log-level INFO
```

`--interface-inventory` writes the interface binding inventory as JSON: for
each ScreenOS interface, its default Junos destination and every zone, policy,
address object, route, NAT rule, VPN reference, and unsupported attribute bound
to it, with the source line each one came from.

`--interface-map` is optional. It takes a JSON list of approved destinations
and is validated before conversion starts; the run stops with an error rather
than emitting partially remapped configuration:

```json
[
  { "screenos_name": "ethernet0/0", "physical_name": "ge-0/0/9" },
  {
    "screenos_name": "ethernet0/1.100",
    "physical_name": "xe-2/0/1",
    "unit": 7,
    "vlan_mode": "tagged",
    "vlan_id": 100
  }
]
```

`unit` defaults to `0` and `vlan_mode` to `access` (untagged). An untagged
Ethernet destination must use unit 0, and a tagged one needs a non-zero unit
and a VLAN ID. Omitting the flag leaves the default interface-name mapping in
place, so existing conversions are unchanged.

### Web application

The Flask application uses the same in-memory conversion service as the CLI.
It accepts either pasted configuration or one UTF-8 `.txt` upload and keeps
submitted configuration in memory only for the duration of the request. Each
preview also lists the interface binding inventory so an operator can see what
depends on every interface before choosing migration destinations.

For local development:

```bash
python3 -m pip install -r requirements.txt
flask --app 'packages.web_app:create_app()' run
```

Open `http://127.0.0.1:5000`. Flask's development server is not intended for
production; the container uses Gunicorn instead.

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
- The web application does not persist submitted configurations, but operators
  must still protect network access and application logs as sensitive systems.

## Development

Repository-specific architecture, testing, untrusted-input, web interface, and
contribution rules are collected in [AGENTS.md](AGENTS.md). Contributors and AI
coding agents should read it before changing the converter, the Flask
application, or the test fixtures.

### Runtime Dependencies

Flask and Gunicorn are exactly pinned in `requirements.txt` so release image
builds use reviewed runtime versions. The CLI conversion path remains available
inside the same environment.

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

### Container

Build and run the production web service locally:

```bash
docker build -f docker/Dockerfile -t screenos-to-junos .
docker run --rm --read-only --tmpfs /tmp \
  --cap-drop ALL --security-opt no-new-privileges \
  -p 127.0.0.1:8080:8080 screenos-to-junos
```

Open `http://127.0.0.1:8080`; the health endpoint is `/healthz`. The maximum
submitted configuration defaults to 1 MiB and can be set at container start:

```bash
docker run --rm -p 127.0.0.1:8080:8080 \
  -e SCREENOS_MAX_CONFIG_BYTES=2097152 screenos-to-junos
```

Released images are published as
`ghcr.io/greyinghair/screenos_to_junos_converter`. Prefer immutable version or
full-SHA tags for deployments, for example:

```bash
docker pull ghcr.io/greyinghair/screenos_to_junos_converter:v1.2.3
```

The package may require GitHub Container Registry authentication while it is
private. Release retention and channel-tag behavior are documented in
[repository maintenance](docs/repository-maintenance.md).

## Reference Documentation
- `docs/screenos/` contains ScreenOS reference PDFs
- `docs/junos/` contains Junos CLI reference PDFs
- [Conversion support matrix](docs/conversion-support-matrix.md) defines the
  accepted grammar, rendered Junos hierarchy, and known limitations.

These references are intended to support future enhancement of conversion coverage.
