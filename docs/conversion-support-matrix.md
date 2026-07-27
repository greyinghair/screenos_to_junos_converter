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
  and [security policies](https://www.juniper.net/documentation/us/en/software/junos/security-policies/topics/topic-map/security-policy-configuration.html).

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
| `set service "NAME" protocol (tcp\|udp) src-port START-END dst-port START-END [timeout N]` | `set applications application PROTOCOL_PORT[-END] protocol PROTOCOL destination-port START[-END]` | **Supported.** Only TCP and UDP numeric port ranges are accepted. Source ports are validated but not rendered by the current model. | `tests/test_convert_service.py` |
| `set service "NAME" + (tcp\|udp) src-port START-END dst-port START-END` | Custom application plus a generated application set | **Assumption.** Multiple-server service variants need more source fixtures before extension. | Existing smoke coverage |
| `set group service "GROUP" add "MEMBER"` | `set applications application-set GROUP application MEMBER` | **Supported.** Quoted names may contain spaces; the member must be defined first. | `tests/test_converter_syntax_coverage.py` |
| `set address "ZONE" "NAME" IPV4 NETMASK` | `set security zones security-zone ZONE address-book address NAME PREFIX` | **Supported, limited to dotted IPv4/netmask input.** CIDR, IPv6, wildcard, and range forms are unsupported. | Smoke and syntax-coverage tests |
| `set address "ZONE" "NAME" FQDN` | `set security zones security-zone ZONE address-book address NAME dns-name FQDN` | **Assumption.** A non-IP value is treated as a DNS name; add a verified FQDN fixture before broadening this path. | Add with the next FQDN change |
| `set group address "ZONE" "GROUP" add "MEMBER"` | Zone address-set entry | **Supported.** Nested sets are emitted when a previously recognized member is a set. | `tests/test_converter_syntax_coverage.py` |
| `set policy id NUMBER from "FROM" to "TO" "SRC" "DST" "SERVICE" (permit\|deny)` | `set security policies from-zone FROM to-zone TO policy NUMBER match …` and `then permit\|deny` | **Supported base policy only.** Numeric IDs and permit/deny are the current boundary. | `tests/test_converter_smoke.py` |
| `set src-address "NAME"`, `set dst-address "NAME"`, or `set service "NAME"` immediately after a base policy | Additional policy match statement | **Supported.** Continuations are stateful and must follow a successfully parsed base policy. | `tests/test_converter_syntax_coverage.py` |
| `set policy id NUMBER disable` | Removes the converted statements for that numeric policy | **Supported.** The converter intentionally omits disabled policies rather than rendering them disabled. | `tests/test_converter_syntax_coverage.py` |

## Explicitly unsupported work

- Global policies: #18
- Interfaces: #19
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
