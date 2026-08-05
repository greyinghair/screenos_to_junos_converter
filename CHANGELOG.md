# Changelog

All notable changes to this project are documented in this file.

## Unreleased

- feat: add the interface-mapping workspace to the web interface. After a
  configuration is pasted or uploaded, "Review interface mappings" lists every
  discovered ScreenOS interface as a card carrying its current Junos target,
  zone, addresses, VLAN tag, and the policies, routes, NAT rules, address
  objects, and VPN bindings that depend on it, then offers a Junos destination
  with SRX suggestions, an optional logical unit, and a VLAN treatment of
  preserve, untagged, or tagged with an ID. Choices are validated by the same
  rules as the CLI mapping file, reported inline on the control that caused
  them, and preserved through a rejection; conversion is refused until they are
  valid. Interfaces left unmapped keep the converter default, and nothing is
  stored between requests. `review_interface_mappings` is the new
  non-raising form of `resolve_interface_mappings` behind both front ends.
- feat: give the web interface a visual identity and lightweight graphics — an
  original SVG application icon used as the favicon and page mark, a
  server-rendered four-stage conversion flow graphic with text status for every
  stage, and an inline icon sprite for interfaces, VLAN tagging, policies, NAT,
  routes, VPNs, warnings, and completed mappings. Light and dark themes,
  reduced-motion support, and a bounded page for large configurations are
  included; first-party client assets total roughly 4.4 KB gzipped against a
  100 KB budget asserted in the test suite.
- feat: inventory every ScreenOS interface binding that affects migration —
  zones, zone policies, contained address objects, static routes, routing
  instances, MIP/DIP NAT, VPN and tunnel references, unnumbered donors, and
  unsupported interface attributes — keyed by the exact source-interface
  identifier, with the source line behind each reference, an explicit empty
  state, and references to undefined interfaces reported separately. The
  inventory is exposed through the conversion service, the web preview, and a
  new `--interface-inventory` CLI flag.
- feat: apply operator-approved interface mappings when rendering Junos.
  A validated mapping retargets a ScreenOS interface onto a chosen Junos
  interface, unit, and untagged or tagged VLAN, and every supported reference
  follows it. Mappings are validated before rendering, conflicting destinations
  and dropped VLAN tags are diagnosed instead of emitted, and the applied
  mapping is recorded in the generated configuration. Conversions without
  mappings are byte-for-byte unchanged.

- docs: add a repository-root `AGENTS.md` covering project structure, verified
  commands, architecture boundaries, testing, untrusted-input handling, the web
  interface, and contribution workflow, with automation contracts that fail when
  the documented paths, modules, scripts, or validation entrypoints drift.
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
