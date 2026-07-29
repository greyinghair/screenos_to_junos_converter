# Conversion Support Matrix

This document is the versioned contract for the ScreenOS-to-Junos parser. It
records the exact input grammar currently accepted, the Junos hierarchy emitted,
and the limitations that must be resolved before expanding coverage.

## Documentation baseline

- Bundled ScreenOS references: `docs/screenos/UG_ISG2000.pdf`,
  `docs/screenos/rn-screenos-63r21.pdf`, and
  `docs/screenos/ScreenOS-glossary.pdf`.
- Bundled Junos reference: `docs/junos/juniper-junos-cli-reference.pdf`.
- Target hierarchies are cross-checked against Juniper documentation for
  [applications and application sets](https://www.juniper.net/documentation/us/en/software/junos/security-policies/topics/topic-map/policy-application-sets-configuration.html),
  [address books and address sets](https://www.juniper.net/documentation/us/en/software/junos/security-policies/topics/topic-map/security-address-books-sets.html),
  [security policies](https://www.juniper.net/documentation/us/en/software/junos/security-policies/topics/topic-map/security-policy-configuration.html),
  [global policy evaluation](https://www.juniper.net/documentation/us/en/software/junos/security-policies/topics/topic-map/security-global-policies.html),
  [security-zone interfaces](https://www.juniper.net/documentation/us/en/software/junos/security-policies/topics/topic-map/security-zone-configuration.html),
  [interface addresses](https://www.juniper.net/documentation/us/en/software/junos/interfaces-fundamentals/topics/topic-map/protocol-family-interface-address-properties.html),
  [VLAN tagging](https://www.juniper.net/documentation/us/en/software/junos/cli-reference/topics/ref/statement/vlan-tagging-edit-interfaces.html),
  [static routes](https://www.juniper.net/documentation/us/en/software/junos/cli-reference/topics/ref/statement/static-edit-routing-options.html),
  [routing instances](https://www.juniper.net/documentation/us/en/software/junos/routing-overview/topics/concept/routing-instances-overview.html),
  [BGP groups and neighbors](https://www.juniper.net/documentation/us/en/software/junos/bgp/topics/topic-map/bgp-peering-sessions.html),
  [NAT processing and rule ordering](https://www.juniper.net/documentation/us/en/software/junos/nat/topics/topic-map/security-nat-overview.html),
  [source NAT](https://www.juniper.net/documentation/us/en/software/junos/nat/topics/topic-map/nat-security-source-and-source-pool.html),
  and [static NAT](https://www.juniper.net/documentation/us/en/software/junos/nat/topics/topic-map/security-nat-static.html).

Do not add a command form until its ScreenOS source syntax, Junos equivalent,
fixture, and unsupported-path behaviour are recorded here. This avoids silently
turning an assumption into a migration guarantee.

## Status terms

- **Supported**: covered by an automated test and emitted deterministically.
- **Assumption**: current behaviour is intentional but needs a specific vendor
  syntax reference before it is expanded.
- **Unsupported**: counted as an unconverted line; it needs a dedicated issue.

## Supported grammar

| ScreenOS input contract | Junos output hierarchy | Status and limits | Regression coverage |
| --- | --- | --- | --- |
| `set service "NAME" protocol (tcp\|udp) src-port START-END dst-port START-END [timeout N]` | `set applications application PROTOCOL_PORT[-END] protocol PROTOCOL destination-port START[-END]` | **Supported.** Only TCP and UDP numeric port ranges are accepted. Source ports are validated but not rendered by the current model. | Unit tests plus `fixtures/features/services.screenos` |
| `set service "NAME" + (tcp\|udp) src-port START-END dst-port START-END` | Custom application plus a generated application set | **Assumption.** Multiple-server service variants need more source fixtures before extension. | Services and end-to-end fixtures |
| `set group service "GROUP" add "MEMBER"` | `set applications application-set GROUP application MEMBER` | **Supported.** Quoted names may contain spaces; the member must be defined first. | Services and negative-reference fixtures |
| `set address "ZONE" "NAME" IPV4 NETMASK` | `set security zones security-zone ZONE address-book address NAME PREFIX` | **Supported, limited to dotted IPv4/netmask input.** CIDR, IPv6, wildcard, and range forms are unsupported for address-book objects. | Address and negative-address fixtures |
| `set address "Global" "NAME" IPV4 NETMASK` | `set security address-book global address NAME PREFIX` | **Supported.** Global objects are kept separate from same-named zone objects and resolve in global policies. | Global-policy fixture |
| `set address "(ZONE\|Global)" "NAME" FQDN` | Zone or global address-book `dns-name` entry | **Assumption.** A non-IP value is treated as a DNS name; broaden only with vendor-validated syntax. | Address and end-to-end fixtures |
| `set group address "(ZONE\|Global)" "GROUP" add "MEMBER"` | Zone or global address-set entry | **Supported.** Nested sets are emitted when a previously recognized member is a set. | Address and negative-reference fixtures |
| `set policy id NUMBER [top\|before NUMBER] [name "NAME"] from "FROM" to "TO" "SRC" "DST" "SERVICE" (permit\|deny\|reject) [log [session-init]] [count]` | `set security policies from-zone FROM to-zone TO policy NAME match …` and `then ACTION` | **Supported.** Numeric IDs are required; the ID is the policy name unless an explicit name is supplied. Log emits both `session-init` and `session-close`; count emits `then count`. | Policy, global-policy, negative-policy, and end-to-end fixtures |
| `set policy global id NUMBER [top\|before NUMBER] [name "NAME"] "SRC" "DST" "SERVICE" (permit\|deny\|reject) [log [session-init]] [count]` | `set security policies global policy NAME match …` and `then ACTION` | **Supported.** Global policies resolve objects from the global address book. Zone policies render before global policies because Junos evaluates matching zone policies before global policies. | Global-policy and negative-policy fixtures |
| `set src-address "NAME"`, `set dst-address "NAME"`, or `set service "NAME"` immediately after a base policy | Additional policy match statement | **Supported.** Continuations are stateful and must follow a successfully parsed base policy. | Policy, negative-reference, and end-to-end fixtures |
| `set policy [global] move NUMBER (before\|after) NUMBER` | Reorders policies within the same zone-pair or global context before rendering | **Supported.** Undefined and cross-context targets are diagnosed. `top` and `before` base-policy placement use the same ordering pipeline. | Global-policy and negative-policy fixtures |
| `set policy [global] id NUMBER disable` | Omits the converted statements for that numeric policy | **Supported with diagnostic.** Disabled state is retained in the normalized model, and the policy is intentionally omitted rather than activated on the target. | Syntax-coverage, negative-policy, and end-to-end tests |
| `set interface ethernetS/P ...` | `set interfaces ge-S/0/P unit 0 ...` | **Supported mapping contract.** Description, CIDR IPv4/IPv6 address, physical MTU, `phy link-down`, and zone are supported. Hardware-specific mappings must be reviewed for the target SRX. | Interface and end-to-end fixtures |
| `set interface ethernetS/P.U tag VLAN ...` | `set interfaces ge-S/0/P vlan-tagging` and `unit U vlan-id VLAN ...` | **Supported.** An explicit tag is required. Description, CIDR IPv4/IPv6 address, logical-unit MTU, administrative state, and zone are supported. | Positive and negative interface fixtures |
| `set interface mgt ...` | `set interfaces fxp0 unit 0 ...` in `System-Management` | **Supported.** CIDR IPv4/IPv6 address, description, administrative state, and zone are supported; management MTU is diagnosed as non-portable. | Positive and negative interface fixtures |
| `set interface tunnel.U ...` | `set interfaces st0 unit U ...` | **Supported.** CIDR IPv4/IPv6 address, description, MTU, administrative state, zone, and IPv4 `ip unnumbered interface DONOR` are supported. Donors must resolve to a converted numbered interface. | Positive and negative interface fixtures |
| `set interface (vlanU\|vlan.U) [tag VLAN] ...` | VLAN `screenos_vlan_VLAN` with `l3-interface irb.U`, plus `set interfaces irb unit U ...` | **Supported.** The unit is used as the VLAN ID when `tag` is omitted. Description, CIDR IPv4/IPv6 address, MTU, administrative state, and zone are supported. | Interface fixture |
| `set vrouter VR route PREFIX interface IF [gateway IP] [metric N] [preference N] [tag N]` | Primary `routing-options static route` hierarchy for `trust-vr`; other VRs become `routing-instances NAME instance-type virtual-router` with referenced logical interfaces attached | **Supported.** IPv4/IPv6 prefixes and gateways, interface-only next hops, default routes, null/discard routes, metrics, preferences, and tags are deterministic. Interfaces must have emitted logical units. ScreenOS route descriptions and `permanent` state are diagnosed because Junos has no lossless equivalent `set` command. Source-based routes are unsupported. | Routing, negative-routing, and end-to-end fixtures |
| `set vrouter VR protocol bgp AS`, `router-id IP`, `enable`, and `neighbor (IP\|peer-group NAME) ...` | Primary or per-routing-instance `routing-options` and `protocols bgp group` hierarchies | **Supported subset.** Named peer groups and ungrouped IPv4/IPv6 peers support `remote-as`, `hold-time`, `md5-authentication`, `route-map NAME (in\|out)`, `local-ip`, `src-interface`/`outgoing-interface`, peer-group membership, and explicit enablement. Source interfaces resolve to emitted interface addresses. Route-map names become Junos import/export policy references; this converter does not define the referenced policy statements. An explicit ScreenOS keepalive is lossless only when it is one-third of hold time, which Junos derives automatically. | Routing and negative-routing fixtures plus normalized-model tests |
| `set interface IF mip MAPPED host HOST [vrouter VR] [netmask MASK]` | Global host address plus `security nat static rule-set` from the converted interface; same-subnet mappings also emit `security nat proxy-arp` | **Supported for aligned IPv4 one-to-one or equal-prefix mappings.** Generated MIP names resolve in converted policies, and custom host routing instances are declared. Static NAT is rendered before source NAT to preserve Junos processing precedence. | NAT fixture and normalized-model tests |
| `set interface IF dip ID START [END] [fix-port]` | `security nat source pool screenos_dip_ID`; same-subnet pools also emit proxy ARP | **Supported for IPv4 pool IDs 4–1023.** `fix-port` maps to `port no-translation`. Extended-IP, incoming, random-port, and shifted DIP variants are diagnosed instead of partially converted. | NAT and negative-NAT fixtures |
| `set policy id NUMBER ... nat src [dip-id ID] permit` | Zone-pair `security nat source rule-set` ordered by the normalized policy pipeline; action uses a DIP pool or `source-nat interface` | **Supported.** Address objects and sets must resolve completely to IP prefixes, services must resolve to Junos applications, DIP interfaces must belong to the policy destination zone, and disabled policies omit both policy and NAT output. Global NAT-src and policy NAT-dst are diagnosed because their required context or semantics are not represented by this subset. | NAT, negative-NAT, and end-to-end fixtures |

## Explicitly unsupported work

- IPsec VPN: #21
- IDP rules: #26
- Alternate XML output or input: #4
- Source-based routing, BGP redistribution/network origination, route-map
  definitions, and BGP options outside the table above.
- ScreenOS `set interface IF nat` mode without explicit policy destination
  context, policy NAT-dst/VIP, and extended, incoming, random-port, or shifted
  DIP variants.

## Contribution checklist

1. Link the ScreenOS reference and record the target Junos hierarchy in this file.
2. Add a minimal, sanitized positive fixture and one malformed or unsupported variant.
3. Assert generated output, conversion counts, and diagnostic behaviour.
4. Keep recognition strict enough that unknown syntax is counted as unconverted.
5. Keep production addresses, credentials, and customer configuration out of fixtures.

Feature implementation and its fixtures must land in the same pull request.
`tests/test_validation_fixtures.py` validates exact output and deterministic
ordering for the supported-feature and end-to-end fixtures, and validates
line-specific reasons for unsupported input.
