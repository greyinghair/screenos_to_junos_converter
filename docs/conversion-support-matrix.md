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
- Phase 3 target hierarchies are cross-checked against Juniper documentation
  for [IKE/IPsec VPN configuration](https://www.juniper.net/documentation/us/en/software/junos/vpn-ipsec/topics/topic-map/security-ipsec-vpn-configuration-overview.html),
  [route-based VPNs](https://www.juniper.net/documentation/us/en/software/junos/vpn-ipsec/topics/topic-map/security-route-based-ipsec-vpns.html),
  [policy-based VPNs](https://www.juniper.net/documentation/us/en/software/junos/vpn-ipsec/topics/topic-map/security-policy-based-ipsecvpns.html),
  [IDP rulebases](https://www.juniper.net/documentation/us/en/software/junos/idp-policy/topics/topic-map/security-idp-policy-rules-and-rulebases.html),
  and [per-security-policy IDP attachment](https://www.juniper.net/documentation/us/en/software/junos/idp-policy/topics/topic-map/security-idp-policies-overview.html).

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
| `set service "NAME" protocol (tcp\|udp) src-port START-END dst-port START-END [timeout N]` | `set applications application PROTOCOL_PORT[-END] protocol PROTOCOL destination-port START[-END]` | **Supported.** Only TCP and UDP numeric port ranges are accepted here; ICMP and numeric IP protocols use the rows below. Source ports are validated but not rendered by the current model. | Unit tests plus `fixtures/features/services.screenos` |
| `set service "NAME" + (tcp\|udp) src-port START-END dst-port START-END` | Custom application plus a generated application set | **Assumption.** Multiple-server service variants need more source fixtures before extension. | Services and end-to-end fixtures |
| `set service "NAME" (protocol\|+) icmp type TYPE [code CODE] [timeout N]` | `set applications application icmp_TYPE[_CODE] protocol icmp icmp-type TYPE [icmp-code CODE]` | **Supported.** Type and code are validated as 0-255. The ScreenOS `protocol icmp src-port ... dst-port ...` form remains unsupported because it carries no ICMP type. | `fixtures/features/device_output.screenos`, negative-service fixture, and unit tests |
| `set service "NAME" (protocol\|+) NUMBER [src-port START-END dst-port START-END] [timeout N]` | `set applications application protocol_NUMBER protocol NUMBER` | **Supported for IP protocols other than 1, 6, and 17.** ICMP, TCP, and UDP carry type or port semantics that a bare protocol number would discard, so they are rejected and must use their own service form. Any ScreenOS port range on a non-ported protocol is not rendered. | `fixtures/features/device_output.screenos`, negative-service fixture, and unit tests |
| `set group service "GROUP" comment "TEXT"` | `set applications application-set GROUP description "TEXT"` | **Supported.** The description is emitted after the set's first member because Junos rejects an application set with no members. | `fixtures/features/device_output.screenos` and unit tests |
| `set group service "GROUP" add "MEMBER"` | `set applications application-set GROUP application MEMBER` | **Supported.** Quoted names may contain spaces; the member must be defined first. | Services and negative-reference fixtures |
| `set address "ZONE" "NAME" IPV4 NETMASK` | `set security zones security-zone ZONE address-book address NAME PREFIX` | **Supported, limited to dotted IPv4/netmask input.** CIDR, IPv6, wildcard, and range forms are unsupported for address-book objects. | Address and negative-address fixtures |
| `set address "Global" "NAME" IPV4 NETMASK` | `set security address-book global address NAME PREFIX` | **Supported.** Global objects are kept separate from same-named zone objects and resolve in global policies. | Global-policy fixture |
| `set address "(ZONE\|Global)" "NAME" FQDN` | Zone or global address-book `dns-name` entry | **Assumption.** A non-IP value is treated as a DNS name; broaden only with vendor-validated syntax. | Address and end-to-end fixtures |
| `set group address "(ZONE\|Global)" "GROUP" add "MEMBER"` | Zone or global address-set entry | **Supported.** Nested sets are emitted when a previously recognized member is a set. | Address and negative-reference fixtures |
| `set group address "(ZONE\|Global)" "GROUP" comment "TEXT"` | Zone or global address-set `description` | **Supported.** The description is emitted after the set's first member because Junos rejects an address set with no members. | `fixtures/features/device_output.screenos` and unit tests |
| `set policy id NUMBER [top\|before NUMBER] [name "NAME"] from "FROM" to "TO" "SRC" "DST" "SERVICE" (permit\|deny\|reject) [log [session-init]] [count]` | `set security policies from-zone FROM to-zone TO policy NAME match …` and `then ACTION` | **Supported.** Numeric IDs are required; the ID is the policy name unless an explicit name is supplied. Log emits both `session-init` and `session-close`; count emits `then count`. | Policy, global-policy, negative-policy, and end-to-end fixtures |
| `set policy global id NUMBER [top\|before NUMBER] [name "NAME"] "SRC" "DST" "SERVICE" (permit\|deny\|reject) [log [session-init]] [count]` | `set security policies global policy NAME match …` and `then ACTION` | **Supported.** Global policies resolve objects from the global address book. Zone policies render before global policies because Junos evaluates matching zone policies before global policies. | Global-policy and negative-policy fixtures |
| `set src-address "NAME"`, `set dst-address "NAME"`, or `set service "NAME"` immediately after a base policy | Additional policy match statement | **Supported.** Continuations are stateful and must follow a successfully parsed base policy. | Policy, negative-reference, and end-to-end fixtures |
| `set policy [global] move NUMBER (before\|after) NUMBER` | Reorders policies within the same zone-pair or global context before rendering | **Supported.** Undefined and cross-context targets are diagnosed. `top` and `before` base-policy placement use the same ordering pipeline. | Global-policy and negative-policy fixtures |
| Blank lines and `#` or `!` comment lines | Nothing | **Supported.** They carry no configuration state, so they are skipped and are neither converted nor counted as unconverted input. | `fixtures/features/device_output.screenos` and unit tests |
| `exit` | Nothing | **Supported.** `exit` closes the policy context opened by a bare `set policy id NUMBER`; a continuation after it is diagnosed instead of being applied to the previous policy. | `fixtures/features/device_output.screenos` and unit tests |
| `set log [session-init]` or `set count` inside a policy context | `then log session-init`, `then log session-close`, or `then count` on the enclosing policy | **Supported.** These are the per-policy flags a saved configuration writes inside a `set policy id NUMBER` block. Without a base policy the line is diagnosed. | `fixtures/features/device_output.screenos` and unit tests |
| `set policy id NUMBER ... count alarm THRESHOLD THRESHOLD` | `then count` on the converted policy | **Supported with diagnostic.** Alarm thresholds only annotate the counter and have no Junos policy equivalent, so the policy and its counter still convert and the thresholds are diagnosed. Non-numeric thresholds are rejected. | Negative-policy fixture and unit tests |
| `set policy [global] id NUMBER schedule "NAME"` | Omits the converted statements for that numeric policy | **Supported with diagnostic.** A scheduler bounds when the rule is active, so emitting it would convert a time-bounded policy into an always-on one. The policy is omitted instead, and the diagnostic names the manual Junos scheduler step. | Negative-policy fixture and unit tests |
| `set policy [global] id NUMBER traffic ...` | Nothing, the policy still converts | **Supported with diagnostic.** Traffic shaping and prioritisation are enforcement-neutral, so the policy is converted without them and Junos CoS must be configured manually. | Negative-policy fixture and unit tests |
| `set policy [global] id NUMBER disable` | Omits the converted statements for that numeric policy | **Supported with diagnostic.** Disabled state is retained in the normalized model, and the policy is intentionally omitted rather than activated on the target. | Syntax-coverage, negative-policy, and end-to-end tests |
| `set interface ethernetS/P ...` | `set interfaces ge-S/0/P unit 0 ...` | **Supported mapping contract.** Description, IPv4/IPv6 address in either the CIDR `ip ADDRESS/PREFIX` or dotted `ip ADDRESS NETMASK` form, physical MTU, `phy link-down`, and zone are supported. Hardware-specific mappings must be reviewed for the target SRX. | Interface and end-to-end fixtures |
| `set interface ethernetS/P.U tag VLAN [zone ZONE] ...` | `set interfaces ge-S/0/P vlan-tagging` and `unit U vlan-id VLAN ...` | **Supported.** An explicit tag is required. A combined `tag VLAN zone ZONE` line is split and each half is validated separately. Description, CIDR IPv4/IPv6 address, logical-unit MTU, administrative state, and zone are supported. | Positive and negative interface fixtures |
| `set interface mgt ...` | `set interfaces fxp0 unit 0 ...` in `System-Management` | **Supported.** CIDR IPv4/IPv6 address, description, administrative state, and zone are supported; management MTU is diagnosed as non-portable. | Positive and negative interface fixtures |
| `set interface tunnel.U ...` | `set interfaces st0 unit U ...` | **Supported.** CIDR IPv4/IPv6 address, description, MTU, administrative state, zone, and IPv4 `ip unnumbered interface DONOR` are supported. Donors must resolve to a converted numbered interface. | Positive and negative interface fixtures |
| `set interface (vlanU\|vlan.U) [tag VLAN] ...` | VLAN `screenos_vlan_VLAN` with `l3-interface irb.U`, plus `set interfaces irb unit U ...` | **Supported.** The unit is used as the VLAN ID when `tag` is omitted. Description, CIDR IPv4/IPv6 address, MTU, administrative state, and zone are supported. | Interface fixture |
| Approved interface mapping (service or CLI input, not ScreenOS syntax): source interface to Junos `(ge\|xe\|et\|fe\|em\|xle)-S/P/N`, `ae\|reth` bundle, `fxp0`, `st0`, or `irb`, with a logical unit and an untagged or tagged VLAN selection | The mapped interface, unit, and `vlan-id` plus every supported reference: security zones, zone-policy zone membership, static routes, routing-instance attachment, MIP/DIP NAT and proxy ARP, unnumbered donors, and IKE/VPN interfaces | **Supported and optional.** Mappings are validated before rendering: unknown Junos names, out-of-range units and VLAN IDs, an untagged Ethernet unit other than 0, a tagged unit 0, tagged `st0`/`fxp0`, duplicate sources, two sources claiming one unit, and tagged/untagged units mixed on one physical interface are all rejected. At render time a destination that collides with another interface's resolved unit, and a mapping that would drop a ScreenOS VLAN tag, are diagnosed and the interface is omitted so no reference silently changes meaning. Retagging to a different VLAN ID converts and raises a manual-review warning. Applied mappings are recorded as `#` comment lines at the top of the generated configuration and are not counted as converted input. Without mappings the default `ethernet*`/`mgt`/`tunnel.N`/`vlanN` strategy is used unchanged. | `fixtures/features/interface_mapping.screenos` with its `.mappings.json`, the negative mapping fixture, resolver unit tests, and CLI tests |
| Interface binding inventory (derived output, not ScreenOS syntax) | No Junos output; a deterministic per-interface record of zone, policy, address-object, route, routing-instance, static/source NAT, VPN, unnumbered, and unsupported-attribute bindings, plus references to undefined interfaces | **Supported.** Every binding is derived from a normalized model or a recorded diagnostic and carries its source line; secrets stay redacted. Address objects bind only when their prefix is contained in one of the interface's IPv4 networks. Global policies are excluded because they name no zone and therefore do not depend on any one interface. Interfaces with no discovered bindings are reported with an explicit empty state. | `fixtures/features/interface_inventory.screenos`, inventory unit tests, CLI JSON test, and a web request test |
| `set vrouter VR route PREFIX interface IF [gateway IP] [metric N] [preference N] [tag N]` | Primary `routing-options static route` hierarchy for `trust-vr`; other VRs become `routing-instances NAME instance-type virtual-router` with referenced logical interfaces attached | **Supported.** IPv4/IPv6 prefixes and gateways, interface-only next hops, default routes, null/discard routes, metrics, preferences, and tags are deterministic. Interfaces must have emitted logical units. ScreenOS route descriptions and `permanent` state are diagnosed because Junos has no lossless equivalent `set` command. Source-based routes are unsupported. | Routing, negative-routing, and end-to-end fixtures |
| `set vrouter VR protocol bgp AS`, `router-id IP`, `enable`, and `neighbor (IP\|peer-group NAME) ...` | Primary or per-routing-instance `routing-options` and `protocols bgp group` hierarchies | **Supported subset.** Named peer groups and ungrouped IPv4/IPv6 peers support `remote-as`, `hold-time`, `route-map NAME (in\|out)`, `local-ip`, `src-interface`/`outgoing-interface`, peer-group membership, and explicit enablement. Source interfaces resolve to emitted interface addresses. Route-map names become Junos import/export policy references; this converter does not define the referenced policy statements. An explicit ScreenOS keepalive is lossless only when it is one-third of hold time, which Junos derives automatically. BGP `md5-authentication` values are omitted and redacted from diagnostics; configure the Junos authentication key manually. | Routing and negative-routing fixtures plus normalized-model tests |
| `set interface IF mip MAPPED host HOST [(vrouter\|vr) VR] [netmask MASK]` | Global host address plus `security nat static rule-set` from the converted interface; same-subnet mappings also emit `security nat proxy-arp` | **Supported for aligned IPv4 one-to-one or equal-prefix mappings.** Generated MIP names resolve in converted policies, and custom host routing instances are declared. Static NAT is rendered before source NAT to preserve Junos processing precedence. `vr` is accepted as the abbreviation a saved configuration writes for `vrouter`. | NAT fixture and normalized-model tests |
| `set interface IF dip ID START [END] [fix-port]` | `security nat source pool screenos_dip_ID`; same-subnet pools also emit proxy ARP | **Supported for IPv4 pool IDs 4–1023.** `fix-port` maps to `port no-translation`. Extended-IP, incoming, random-port, and shifted DIP variants are diagnosed instead of partially converted. | NAT and negative-NAT fixtures |
| `set policy id NUMBER ... nat src [dip-id ID] permit` | Zone-pair `security nat source rule-set` ordered by the normalized policy pipeline; action uses a DIP pool or `source-nat interface` | **Supported.** Address objects and sets must resolve completely to IP prefixes, services must resolve to Junos applications, DIP interfaces must belong to the policy destination zone, and disabled policies omit both policy and NAT output. Global NAT-src and policy NAT-dst are diagnosed because their required context or semantics are not represented by this subset. | NAT, negative-NAT, and end-to-end fixtures |
| `set ike p1-proposal NAME preshare GROUP esp ENCRYPTION AUTH second SECONDS` | `security ike proposal` | **Supported subset.** Preshared-key authentication, DH groups 1/2/5/14/15/16/19/20/21, AES-128/192/256 or 3DES, SHA-1/SHA-256/SHA-384 (including ScreenOS `sha2-384`), and 180–86400 second lifetimes are modeled. DES and MD5 are rejected. Group 1/2/5, 3DES, and SHA-1 are preserved with deprecation diagnostics. SHA-384 IPsec support is platform/release dependent and requires validation. | IPsec fixture and normalized-model tests |
| `set ike gateway NAME (address PEER\|dynamic ID) (main\|aggressive) [local-id ID] outgoing-interface IF preshare SECRET proposal P1 [nat-traversal]` | Generated `security ike policy` and `security ike gateway` | **Supported subset.** Static IP/DNS peers and strictly validated dynamic IP/hostname/user-at-hostname IDs are supported. The outgoing interface must resolve to an emitted logical interface. NAT traversal is recorded and relies on the Junos SRX default-enabled behavior. Preshared secrets are never persisted or emitted, including quoted and escaped forms; the source line is redacted and a manual-key diagnostic is produced. Security-level bundles and other authentication methods are unsupported. | IPsec fixture, adversarial redaction tests, and negative crypto/identity tests |
| `set ike p2-proposal NAME (GROUP\|no-pfs) esp ENCRYPTION AUTH second SECONDS` | `security ipsec proposal` plus generated `security ipsec policy` | **Supported subset.** The algorithm and lifetime limits match the Phase 1 row. A DH group maps to `perfect-forward-secrecy`; `no-pfs` omits PFS. | IPsec fixture and normalized-model tests |
| `set vpn NAME gateway GATEWAY (replay\|no-replay) tunnel [idletime 0] proposal P2`, followed by optional `bind interface TUNNEL` and `proxy-id local-ip PREFIX remote-ip PREFIX ANY` | `security ipsec vpn` with gateway/policy references, optional `ike no-anti-replay`, optional `bind-interface st0.N`, and optional `ike proxy-identity` | **Supported.** A tunnel binding creates a route-based VPN and must resolve to a rendered `tunnel.N`; routing continues through the shared routing model. An unbound VPN can be used by a policy-based tunnel action. Explicit proxy IDs require same-family prefixes and service `ANY`. `replay` preserves the Junos anti-replay default; `no-replay` emits `no-anti-replay`. Nonzero idle time and service-specific proxy IDs are diagnosed. | Exact IPsec fixture covers route- and policy-based VPNs plus routing, replay behavior, and proxy IDs |
| `set policy id NUMBER ... tunnel vpn NAME [id ID] [pair-policy NUMBER]` | `security policies ... then permit tunnel ipsec-vpn NAME [pair-policy POLICY]` | **Supported for IKEv1-style policy-based VPNs.** A pair target must be reciprocal and reference the same unbound VPN. Policy NAT-src and IDP cannot be combined with this action. Current Junos releases and the optional `junos-ike` package have platform/process-specific policy-based VPN limitations, so route-based migration is preferred. | Exact IPsec fixture and normalized-model tests |
| `set policy id NUMBER ... permit attack "SEVERITY:SERVICE:(SIGS\|ANOM)" action (close\|close-client\|close-server\|drop)`, flattened `set policy id NUMBER attack ...`, or policy-context `set attack ...` | Generated `security idp dynamic-attack-group` objects, ordered per-firewall-policy `security idp idp-policy ... rulebase-ips`, a deterministic `security idp default-policy` when multiple policies require it, and `then permit application-services idp-policy` attachment | **Supported for Junos 18.2R1 and later.** ScreenOS Critical/High/Medium/Low/Info map to Junos critical/major/minor/warning/info. Service, severity, and signature/anomaly type become dynamic-group filters; actions map to their closest documented connection action and attack logging is enabled. Severity-only groups such as `CRITICAL:` are also supported. Arbitrary or individual ScreenOS signature names are diagnosed and never substituted; the affected firewall policy and its linked source NAT rule are omitted so inspection cannot silently degrade to plain permit. The multiple-policy default requires Junos 18.3R1 or later. A current signature package and platform/license review are required. | Exact IDP fixture, normalized-model tests, unknown-signature fail-closed test, multiple-policy default test, and CLI manual-review test |

## Explicitly unsupported work

- Alternate XML output or input: #4
- ScreenOS `set scheduler` definitions and their conversion to Junos
  `schedulers`; a scheduled policy is omitted rather than converted.
- ScreenOS system commands (`set hostname`, `set admin`, `set syslog`,
  `set snmp`, `set flow`, `set alg`, `set dns`, `set auth-server`),
  standalone `set zone` definitions, and `set interface` management,
  routing-mode, or DHCP-relay attributes.
- Source-based routing, BGP redistribution/network origination, route-map
  definitions, and BGP options outside the table above.
- ScreenOS `set interface IF nat` mode without explicit policy destination
  context, policy NAT-dst/VIP, and extended, incoming, random-port, or shifted
  DIP variants.
- Interface mapping destinations outside the documented Junos families, Junos
  aggregate/redundant member-link configuration, native VLAN selection on a
  tagged physical interface, and mapping one ScreenOS interface onto several
  Junos units. The web mapping workspace maps the first 400 discovered
  interfaces per submission; use the CLI `--interface-map` beyond that.
- IKEv2-specific ScreenOS gateway syntax, certificates/RSA/DSA/XAuth, multiple
  proposals per gateway or VPN, VPN groups, L2TP, manual-key VPNs, VPN monitor,
  nonzero VPN idle timers, and service-specific proxy IDs.
- ScreenOS custom/individual attack signatures, attack IP-actions and timeouts,
  per-attack logging suppression, exempt rulebases, application DDoS rules, and
  IDP objects that do not match the documented severity/service/type group form.

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
