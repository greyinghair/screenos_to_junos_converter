# Changelog

All notable changes to this project are documented in this file.

## Unreleased

- feat: add an in-memory conversion service and request-isolated Flask web UI.
- feat: add safe paste/upload, preview, diagnostics, and download workflows.
- ci: build and smoke-test containers on relevant pull requests without publishing.
- ci: publish non-root Gunicorn images to GHCR with immutable tags, SBOM, and provenance.
- fix: omit BGP authentication secrets from generated configuration and redact them from diagnostics.
- feat: convert static routes, routing instances, and supported BGP peer groups.
- feat: convert MIP static NAT, DIP pools, and policy-linked source NAT.
- test: add deterministic positive, negative, model, and end-to-end routing/NAT coverage.
- docs: moved GitHub workflow and release automation setup details out of `readme.md` into `docs/repository-maintenance.md`.
- docs: kept `readme.md` focused on program behavior, usage, and operation.
- ci: manual releases can now target a specific historic commit, branch, or tag via `target_commitish`.
- ci: release workflow now supports multiple floating tags on the same versioned release, including optional `pre-release`, `latest`, and `stable` tags.
- ci: release creation now uses `RELEASE_TAG_PUSH_TOKEN` (when present) to avoid 403 integration errors on protected historic commits.
