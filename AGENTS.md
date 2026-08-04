# AGENTS.md

Instructions for AI coding agents working in this repository. Human maintainer
instructions, `readme.md`, CI configuration, and tool configuration always win
where they disagree with this file.

## What this project is

A migration aid that converts a tested subset of Juniper ScreenOS configuration
into Junos SRX `set` commands. It is not a complete device translator. Two front
ends share one conversion engine:

- CLI: `convert.py` reads a ScreenOS text file and writes a Junos text file.
- Web: `packages/web_app.py` accepts pasted text or one UTF-8 `.txt` upload and
  converts it in memory for the duration of the request.

Both paths must produce identical output for identical input. Unsupported or
ambiguous input is never silently dropped: it is counted and reported as a
line-numbered diagnostic.

## Project structure and ownership

| Path | Owns |
| --- | --- |
| `convert.py` | CLI argument parsing, output path selection, diagnostic logging. No conversion logic. |
| `packages/converter_core.py` | ScreenOS parsing, `ConversionState`, and Junos rendering. The engine. |
| `packages/conversion_models.py` | Normalized interface, policy, routing, NAT, BGP, IPsec, and IDP records shared by parsers and renderers. Also owns `map_screenos_interface`. |
| `packages/conversion_service.py` | Request-scoped API: decode, size/control-byte validation, one fresh `Converter` per call, immutable `ConversionResult`. |
| `packages/convert_service.py` | ScreenOS *service* (application) parsing helpers. |
| `packages/web_app.py` | Flask application factory, request validation, security headers, routes. |
| `packages/sanity_check_naming.py` | Junos-safe name normalization. |
| `packages/ipy.py` | Vendored IP utility. Excluded from lint; do not restyle it. |
| `packages/static/`, `packages/templates/` | Web assets and Jinja templates. |
| `tests/`, `tests/fixtures/` | Regression tests and sanitized positive/negative/end-to-end fixtures. |
| `scripts/` | Shared validation, container smoke, and README tree helpers. |
| `.github/workflows/` | CI, container, canary, security, and release automation. |

## Commands

Use Python 3.12–3.14 (the CI matrix). Run everything from the repository root.

```bash
python3 -m pip install --no-cache-dir -r requirements.txt -r requirements-dev.txt
scripts/validate.sh all     # ruff check, ruff format --check, compileall, pytest, coverage
scripts/validate.sh test    # compileall and pytest only (fast loop)
```

`scripts/validate.sh all` is the single gate: CI, release validation, and local
work all call it. Run it before every push. It writes JUnit and coverage XML
under `artifacts/` (override with `ARTIFACT_DIR`, `JUNIT_XML`, `COVERAGE_XML`).

Narrower commands, when you need them:

```bash
python3 -m pytest -q tests/test_web_app.py
python3 -m ruff check .
python3 -m ruff format .
```

Run the two front ends:

```bash
python3 convert.py --input input/netscreen_config.txt --output outputs/out.txt
flask --app 'packages.web_app:create_app()' run     # development only
```

Container build and smoke check (requires Docker):

```bash
docker build -f docker/Dockerfile -t screenos-to-junos .
scripts/container-smoke.sh screenos-to-junos
```

If you add or rename a tracked top-level file, regenerate the README tree with
`scripts/update-readme-tree.sh` (it edits `readme.md` between the
`repo-tree` markers) rather than hand-editing that block.

## Architecture rules

- Keep the four concerns separate: ScreenOS parsing, normalized models,
  validation, and Junos rendering. New features extend
  `packages/conversion_models.py` with a normalized record first; do not let a
  parser emit Junos strings directly or a renderer re-parse ScreenOS text.
- There is exactly one interface-name resolver: `map_screenos_interface` in
  `packages/conversion_models.py`. Every interface, zone binding, route, NAT
  rule, and VPN reference resolves names through it. Never add a second mapping
  table or inline regex for `ethernet*`/`mgt`/`tunnel.N`/`vlanN`.
- Do not duplicate ScreenOS parsing in browser code. `packages/static/app.js`
  is limited to presentation; all conversion happens server-side through
  `convert_configuration`.
- Every unsupported, ambiguous, or intentionally omitted line must produce a
  visible diagnostic with a line number and a reason, and must count toward the
  unsupported total. Silently skipping input is a bug. Security-relevant
  omissions (disabled or scheduled policies, unknown IDP signatures, redacted
  secrets) additionally warrant a manual-review warning.
- Never emit a secret into generated configuration. Preshared keys and BGP MD5
  keys are redacted and diagnosed so an operator sets them manually.
- Conversion must stay deterministic: stable ordering, no wall-clock or random
  values in output, no dependence on dict insertion order that input can vary.
- `packages/conversion_service.py` constructs a fresh `Converter` per call.
  Do not introduce module-level mutable conversion state; concurrent web
  requests must not share it.
- Export new public names from `packages/__init__.py` and keep `__all__` sorted.

## Testing expectations

- Feature code and its fixtures land in the same pull request. Add a minimal
  sanitized positive fixture under `tests/fixtures/features/` plus a malformed
  or unsupported variant under `tests/fixtures/negative/`.
- `tests/test_validation_fixtures.py` asserts exact deterministic output,
  conversion counts, and line-specific diagnostic reasons. Do not loosen it to
  substring matching to make a change pass.
- Cross-reference integrity (policies referencing addresses, services, zones,
  interfaces; NAT referencing interfaces and policies) belongs in
  `tests/test_policy_interface_models.py` and `tests/test_routing_nat_models.py`.
- Flask behavior is covered by `tests/test_web_app.py`: security headers,
  rejection paths and status codes, escaping of generated output, and
  per-request converter isolation. Web changes need a request-level test, not
  only a service-level one.
- Accessible names, labels, and keyboard operation for new UI must be asserted
  in the rendered template, not left to manual review.
- Large-configuration behavior must stay linear-ish and bounded. Do not add
  per-line work that rescans the whole configuration.
- Keep the repository/CI contracts in `tests/test_automation_contracts.py`
  passing; update them deliberately when automation genuinely changes.
- Coverage has a floor (`fail_under` in `pyproject.toml`). Raise it when
  coverage improves; never lower it to accommodate untested code.

## Untrusted input rules

Pasted and uploaded configurations are untrusted, potentially sensitive, and
possibly hostile. Treat them accordingly.

- Enforce the size limit before conversion. `SCREENOS_MAX_CONFIG_BYTES`
  (default 1 MiB) bounds the configuration; Flask's `MAX_CONTENT_LENGTH`,
  `MAX_FORM_MEMORY_SIZE`, and `MAX_FORM_PARTS` bound the request.
- Accept UTF-8 text only. Reject non-text control bytes, non-`.txt` uploads,
  and uploads whose content type is not `text/plain`.
- Never log configuration content, generated output, filenames as supplied, or
  exception messages that may embed them. Log counts and exception *types*.
- Do not persist submitted configuration. The web path is in-memory only; if a
  temporary file ever becomes necessary, create it with `tempfile` under the
  container's writable `/tmp`, never a predictable path, and remove it.
- Never pass configuration content to a shell, `eval`, `exec`, or a subprocess.
- Escape everything rendered back to the page. Jinja autoescaping is on; do not
  add `|safe`, `Markup`, or `innerHTML` on converted output or diagnostics.
- Derive download filenames with `secure_filename`, never from the raw upload
  name. Keep the security headers set in `apply_security_headers` intact; the
  CSP is `default-src 'self'` with no inline scripts or styles.
- Fixtures use documentation ranges (`192.0.2.0/24`, `198.51.100.0/24`,
  `203.0.113.0/24`) and placeholder names. Never commit real customer
  configuration, addresses, or credentials.

## Web interface

The interface is server-rendered Jinja plus two small static files,
`packages/static/styles.css` and `packages/static/app.js`. Keep it that shape.

- No frontend framework, bundler, or client-side dependency. Enhancements are
  plain CSS and small vanilla JavaScript served from `packages/static/`.
- The interface must stay fully usable with JavaScript disabled. Conversion,
  preview, diagnostics, and download are server-side; the only script is a
  convenience download of the already-rendered preview.
- The response CSP is `default-src 'self'` with no `unsafe-inline`. Add styles
  and scripts as files, never as an inline `<script>` or `style=` attribute.
- Do not add server-side image generation; it grows Flask worker memory.
- Keep controls keyboard-operable, labelled, and visibly focusable. Do not
  remove the default focus outline without replacing it with a visible one.
- Note the size of any new client asset in the pull request.

## Git and pull requests

- Never commit to `main`. Work on a branch and open a pull request.
- Preserve unrelated working-tree changes. Do not `git checkout .`,
  `git stash`, `git reset --hard`, or revert files you did not intend to touch.
- Commit only what the change needs. `input/*.txt`, `outputs/*.txt`, and
  `artifacts/` are ignored on purpose; keep them out of commits.
- Fill in `.github/pull_request_template.md` honestly, including whether
  documentation still matches behavior.
- Disclose AI authorship. Issues and pull requests authored by an agent state
  it plainly (for example, a trailing `— <agent name> (AI)` line), and commits
  keep their `Co-Authored-By` trailer.
- Update `docs/conversion-support-matrix.md` and `readme.md` in the same pull
  request when supported grammar or rendered output changes.

## Keeping this file current

`tests/test_automation_contracts.py` asserts that every repository path named
here exists and that each `packages/` module and `scripts/` helper is
documented above, so renames and additions fail CI until this file is updated.
That check cannot verify prose: when commands, architecture rules, or limits
change, revise the affected section in the same pull request.

## Canonical documentation

Link to these rather than copying them; they are the source of truth.

- `readme.md` — supported and unsupported conversions, usage, container.
- `docs/conversion-support-matrix.md` — accepted grammar, rendered Junos
  hierarchy, known limitations, contribution checklist.
- `docs/dependency-policy.md` — supported versions, boundaries, coverage,
  vulnerability and license rules.
- `docs/repository-maintenance.md` — CI and release workflow behavior.
