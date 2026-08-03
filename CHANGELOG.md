# Changelog

All notable changes to this project are documented in this file.

## Unreleased

- feat: generate a fresh random pre-shared key for every converted IKE gateway
  and write it to the Junos IKE policy, so a converted VPN is complete rather
  than half configured. The ScreenOS secret is still never read into the
  output; the generated key is a placeholder that must be agreed with the
  remote peer owner and set on both ends.
- feat: convert ScreenOS BGP routing policy. Access lists become Junos
  route-filter subroutine policies, as-path and community lists become
  `policy-options` objects, and route maps become policy statements whose names
  match the import/export references the BGP conversion already emitted.
- fix: withhold a whole route map when a match condition or referenced filter
  has no Junos equivalent, rather than emitting the remaining terms and
  changing which routes the policy accepts.

- feat: accept the ScreenOS command forms a device writes when saving its
  configuration, so a `get config` capture no longer needs hand editing before
  conversion: blank and comment lines, `set policy id NUMBER` context blocks
  terminated by `exit`, in-context `set log [session-init]` and `set count`,
  dotted-netmask interface addresses, combined subinterface `tag VLAN zone ZONE`
  lines, and the abbreviated `vr` keyword on MIPs.
- feat: convert ICMP services with a type and optional code, and numeric
  IP-protocol services, to Junos applications. Protocols 1, 6, and 17 are
  rejected because a bare protocol number would discard their type or port
  semantics.
- feat: convert address-group and service-group comments to Junos address-set
  and application-set descriptions.
- feat: add the `TRACEROUTE` ScreenOS default service to the built-in
  application map.
- fix: omit a policy that carries a ScreenOS scheduler instead of converting it
  into an always-on Junos policy, and name the manual scheduler step in the
  diagnostic.
- fix: convert a policy that uses `count alarm` or per-policy traffic shaping
  instead of dropping it, and diagnose only the unsupported option.

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
