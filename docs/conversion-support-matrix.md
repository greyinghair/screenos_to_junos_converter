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
  and [VLAN tagging](https://www.juniper.net/documentation/us/en/software/junos/cli-reference/topics/ref/statement/vlan-tagging-edit-interfaces.html).

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

## Explicitly unsupported work

- Static routes and BGP: #20
- NAT: #17
- IPsec VPN: #21
- IDP rules: #26
- Alternate XML output or input: #4

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
