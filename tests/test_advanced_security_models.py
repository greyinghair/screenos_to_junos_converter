from __future__ import annotations

from pathlib import Path

import pytest

from packages.conversion_models import (
    IdpRuleModel,
    IkeGatewayModel,
    IkeProposalModel,
    IpsecProposalModel,
    IpsecVpnModel,
)
from packages.converter_core import Converter

FIXTURE_ROOT = Path(__file__).parent / "fixtures" / "features"


def run_feature(name: str) -> Converter:
    converter = Converter(progress_interval=9999)
    converter.read_file(FIXTURE_ROOT / f"{name}.screenos")
    return converter


def expected_feature(name: str) -> list[str]:
    return (FIXTURE_ROOT / f"{name}.junos").read_text(encoding="utf-8").splitlines()


def test_ipsec_fixture_is_linked_exact_and_deterministic() -> None:
    first = run_feature("ipsec_vpn")
    second = run_feature("ipsec_vpn")

    assert first.state.converted_config == expected_feature("ipsec_vpn")
    assert second.state.converted_config == first.state.converted_config
    assert first.state.succeeded == 50
    assert first.state.failed == 1
    assert all(
        isinstance(proposal, IkeProposalModel)
        for proposal in first.state.ike_proposals.values()
    )
    assert all(
        isinstance(gateway, IkeGatewayModel)
        for gateway in first.state.ike_gateways.values()
    )
    assert all(
        isinstance(proposal, IpsecProposalModel)
        for proposal in first.state.ipsec_proposals.values()
    )
    assert all(
        isinstance(vpn, IpsecVpnModel) for vpn in first.state.ipsec_vpns.values()
    )
    assert first.state.rendered_vpns == {"route_vpn", "policy_vpn"}
    assert first.state.ipsec_vpns["route_vpn"].bind_interface == "tunnel.10"
    assert first.state.ipsec_vpns["route_vpn"].anti_replay is True
    assert first.state.ipsec_vpns["policy_vpn"].bind_interface is None
    assert first.state.ipsec_vpns["policy_vpn"].anti_replay is False


def test_ipsec_secrets_are_omitted_redacted_and_warned() -> None:
    converter = run_feature("ipsec_vpn")
    persisted_state = repr(converter.state) + "\n".join(
        converter.state.converted_config
    )

    assert "fixture-only-secret" not in persisted_state
    assert [
        (item.line_number, item.reason) for item in converter.state.diagnostics
    ] == [
        (
            7,
            "IKE preshared key omitted; configure a Junos pre-shared-key manually "
            "on the generated IKE policy",
        )
    ]
    assert converter.state.diagnostics[0].line.endswith(
        'preshare <redacted> proposal "phase1_secure" nat-traversal'
    )
    assert converter.state.manual_review_warnings == [
        "IPsec output requires manual validation of peer identities, routing, "
        "NAT traversal, cryptographic policy, and omitted preshared keys before deployment."
    ]


def test_idp_fixture_preserves_rule_order_actions_and_attachment() -> None:
    converter = run_feature("idp")

    assert converter.state.converted_config == expected_feature("idp")
    assert converter.state.succeeded == 47
    assert converter.state.failed == 0
    policy = converter.state.policies[0]
    assert all(isinstance(rule, IdpRuleModel) for rule in policy.idp_rules)
    assert [rule.attack_group for rule in policy.idp_rules] == [
        "CRITICAL:HTTP:SIGS",
        "HIGH:HTTP:ANOM",
        "LOW:HTTP:SIGS",
    ]
    assert [rule.action for rule in policy.idp_rules] == [
        "close-server",
        "drop-connection",
        "close-client",
    ]
    assert converter.state.rendered_idp_policies == {("zone", "30")}
    assert converter.state.manual_review_warnings == [
        "IDP output requires a current Junos signature package and license review; "
        "validate dynamic group membership, actions, and policy attachment before deployment."
    ]


def test_unmappable_idp_signature_is_reported_without_substitution(
    write_input_file,
) -> None:
    input_path = write_input_file(
        "\n".join(
            [
                'set address "Untrust" "CLIENT" 198.51.100.10 255.255.255.255',
                'set address "Trust" "SERVER" 192.0.2.10 255.255.255.255',
                (
                    'set policy id 40 from "Untrust" to "Trust" "CLIENT" "SERVER" '
                    '"ANY" permit attack "SCREENOS-ONLY-SIGNATURE" action close'
                ),
            ]
        )
    )
    converter = Converter(progress_interval=9999)

    converter.read_file(input_path)

    assert converter.state.failed == 1
    assert converter.state.diagnostics[0].reason == (
        'unmappable ScreenOS attack group: "SCREENOS-ONLY-SIGNATURE"; '
        "no Junos signature substitution was made"
    )
    assert not any(
        "set security idp" in line for line in converter.state.converted_config
    )
    assert not any(
        "set security policies from-zone Untrust to-zone Trust policy 40" in line
        for line in converter.state.converted_config
    )


def test_deprecated_and_unmappable_crypto_is_diagnosed(write_input_file) -> None:
    input_path = write_input_file(
        "\n".join(
            [
                'set interface ethernet0/0 zone "Untrust"',
                "set interface ethernet0/0 ip 203.0.113.2/24",
                (
                    'set ike gateway "legacy" address 198.51.100.1 Main '
                    'outgoing-interface "ethernet0/0" preshare "legacy-secret" '
                    'proposal "pre-g2-des-md5"'
                ),
                (
                    'set vpn "legacy" gateway "legacy" replay tunnel idletime 0 '
                    'proposal "g2-esp-des-sha"'
                ),
            ]
        )
    )
    converter = Converter(progress_interval=9999)

    converter.read_file(input_path)

    reasons = [diagnostic.reason for diagnostic in converter.state.diagnostics]
    assert "DES encryption is deprecated and is not emitted" in reasons
    assert "MD5 authentication is deprecated and is not emitted" in reasons
    assert any("deprecated IKE Diffie-Hellman group2" in reason for reason in reasons)
    assert not any(
        "set security ike proposal" in line for line in converter.state.converted_config
    )
    assert "legacy-secret" not in repr(converter.state)


def test_policy_vpn_pair_must_point_back_to_origin(write_input_file) -> None:
    fixture_lines = (
        (FIXTURE_ROOT / "ipsec_vpn.screenos").read_text(encoding="utf-8").splitlines()
    )
    fixture_lines[-1] = fixture_lines[-1].replace("pair-policy 20", "pair-policy 10")
    input_path = write_input_file("\n".join(fixture_lines))
    converter = Converter(progress_interval=9999)

    converter.read_file(input_path)

    reasons = [diagnostic.reason for diagnostic in converter.state.diagnostics]
    assert any(
        "policy VPN pair-policy 21 is undefined, uses a different VPN, "
        "or is not reciprocal" in reason
        for reason in reasons
    )
    assert not any(
        "policy policy_out then permit tunnel" in line
        for line in converter.state.converted_config
    )


@pytest.mark.parametrize(
    ("preshare_token", "secret_fragments"),
    [
        ("'single quoted secret'", ("single", "quoted", "secret")),
        ('"escaped\\"quote suffix"', ("escaped", "quote", "suffix")),
        ("unquoted\\ secret", ("unquoted", "secret")),
        ('unquoted" embedded suffix"', ("unquoted", "embedded", "suffix")),
    ],
)
def test_ike_secret_redaction_handles_shell_quoting(
    write_input_file,
    preshare_token: str,
    secret_fragments: tuple[str, ...],
) -> None:
    input_path = write_input_file(
        "\n".join(
            [
                'set interface ethernet0/0 zone "Untrust"',
                "set interface ethernet0/0 ip 203.0.113.2/24",
                (
                    'set ike p1-proposal "secure" preshare group14 esp '
                    "aes256 sha2-256 second 28800"
                ),
                (
                    'set ike gateway "peer" address 198.51.100.1 Main '
                    'outgoing-interface "ethernet0/0" preshare '
                    f'{preshare_token} proposal "secure"'
                ),
            ]
        )
    )
    converter = Converter(progress_interval=9999)

    converter.read_file(input_path)

    persisted_state = repr(converter.state)
    assert "preshare <redacted>" in persisted_state
    for fragment in secret_fragments:
        assert fragment not in persisted_state


def test_ike_authentication_spellings_map_to_valid_junos() -> None:
    converter = Converter(progress_interval=9999)

    assert converter._map_authentication("sha1", "ike", "source", 1) == "sha1"
    assert converter._map_authentication("sha2-384", "ike", "source", 2) == "sha-384"
    assert (
        converter._map_authentication("sha2-384", "ipsec", "source", 3)
        == "hmac-sha-384"
    )


def test_ike_secret_redaction_removes_every_preshare_token() -> None:
    line = (
        'set ike gateway "peer" preshare "first secret" proposal secure '
        "preshare second\\ secret"
    )

    redacted = Converter._redact_ike_preshare(line)

    assert redacted.count("preshare <redacted>") == 2
    assert "first" not in redacted
    assert "second" not in redacted
    assert "secret" not in redacted


def test_advanced_security_names_reject_normalized_collisions() -> None:
    converter = Converter(progress_interval=9999)

    converter.parse_ike_line(
        'set ike p1-proposal "phase one" preshare group14 esp aes256 '
        "sha2-256 second 28800",
        1,
    )
    converter.parse_ike_line(
        'set ike p1-proposal "phase/one" preshare group14 esp aes256 '
        "sha2-256 second 28800",
        2,
    )
    converter.parse_ike_line(
        'set ike p2-proposal "phase two" group14 esp aes256 sha2-256 second 3600',
        3,
    )
    converter.parse_ike_line(
        'set ike p2-proposal "phase/two" group14 esp aes256 sha2-256 second 3600',
        4,
    )
    converter.parse_ike_line(
        'set ike gateway "peer one" address 198.51.100.1 Main '
        'outgoing-interface "ethernet0/0" preshare "secret" proposal "phase one"',
        5,
    )
    converter.parse_ike_line(
        'set ike gateway "peer/one" address 198.51.100.2 Main '
        'outgoing-interface "ethernet0/0" preshare "secret" proposal "phase one"',
        6,
    )
    converter.parse_vpn_line(
        'set vpn "vpn one" gateway "peer one" replay tunnel idletime 0 '
        'proposal "phase two"',
        7,
    )
    converter.parse_vpn_line(
        'set vpn "vpn/one" gateway "peer one" replay tunnel idletime 0 '
        'proposal "phase two"',
        8,
    )

    reasons = [diagnostic.reason for diagnostic in converter.state.diagnostics]
    assert any("Phase 1 proposal name collides" in reason for reason in reasons)
    assert any("Phase 2 proposal name collides" in reason for reason in reasons)
    assert any("IKE gateway name collides" in reason for reason in reasons)
    assert any("VPN name collides" in reason for reason in reasons)
    assert len(converter.state.ike_proposals) == 1
    assert len(converter.state.ipsec_proposals) == 1
    assert len(converter.state.ike_gateways) == 1
    assert len(converter.state.ipsec_vpns) == 1


def test_dynamic_ike_identities_reject_unsafe_tokens() -> None:
    dynamic_converter = Converter(progress_interval=9999)

    dynamic_converter.parse_ike_line(
        'set ike gateway "peer" dynamic "bad identity" Main '
        'outgoing-interface "ethernet0/0" preshare "secret" proposal "secure"',
        1,
    )

    assert dynamic_converter.state.ike_gateways == {}
    assert dynamic_converter.state.diagnostics[0].reason == (
        "invalid dynamic IKE gateway identity"
    )
    assert "secret" not in repr(dynamic_converter.state)

    local_converter = Converter(progress_interval=9999)
    local_converter.parse_ike_line(
        'set ike gateway "peer" address 198.51.100.1 Main '
        'local-id "bad identity" outgoing-interface "ethernet0/0" '
        'preshare "secret" proposal "secure"',
        1,
    )

    assert local_converter.state.ike_gateways == {}
    assert local_converter.state.diagnostics[0].reason == "invalid IKE local identity"
    assert "secret" not in repr(local_converter.state)


def test_multiple_idp_policies_emit_deterministic_default(write_input_file) -> None:
    input_path = write_input_file(
        "\n".join(
            [
                'set address "Untrust" "CLIENT" 198.51.100.10 255.255.255.255',
                'set address "Trust" "SERVER" 192.0.2.10 255.255.255.255',
                (
                    'set policy id 40 name "first" from "Untrust" to "Trust" '
                    '"CLIENT" "SERVER" "ANY" permit attack '
                    '"CRITICAL:HTTP:SIGS" action close'
                ),
                (
                    'set policy id 41 name "second" from "Untrust" to "Trust" '
                    '"CLIENT" "SERVER" "ANY" permit attack '
                    '"HIGH:HTTP:ANOM" action drop'
                ),
            ]
        )
    )
    converter = Converter(progress_interval=9999)

    converter.read_file(input_path)

    defaults = [
        line
        for line in converter.state.converted_config
        if line.startswith("set security idp default-policy")
    ]
    assert defaults == [
        "set security idp default-policy screenos_untrust_trust_first_idp"
    ]
    assert converter.state.rendered_idp_policies == {("zone", "40"), ("zone", "41")}


def test_policy_vpn_pair_rejects_disabled_target(write_input_file) -> None:
    fixture = (FIXTURE_ROOT / "ipsec_vpn.screenos").read_text(encoding="utf-8")
    input_path = write_input_file(f"{fixture}\nset policy id 21 disable\n")
    converter = Converter(progress_interval=9999)

    converter.read_file(input_path)

    assert not any(
        "then permit tunnel ipsec-vpn policy_vpn" in line
        for line in converter.state.converted_config
    )
    assert any(
        "policy VPN pair-policy 21 is undefined" in diagnostic.reason
        for diagnostic in converter.state.diagnostics
    )


@pytest.mark.parametrize(
    ("proposal_lines", "gateway_proposals", "vpn_proposals", "expected_reason"),
    [
        (
            [
                'set ike p1-proposal "pre_g14_aes256_sha" preshare group15 esp '
                "aes256 sha2-256 second 20000",
                'set ike p2-proposal "phase2" group14 esp aes256 sha2-256 second 3600',
            ],
            ("pre_g14_aes256_sha", "pre-g14-aes256-sha"),
            ("phase2", "phase2"),
            "Phase 1 proposal collides after Junos normalization",
        ),
        (
            [
                'set ike p1-proposal "phase1" preshare group14 esp aes256 '
                "sha2-256 second 28800",
                'set ike p2-proposal "g14_esp_aes256_sha" group15 esp aes256 '
                "sha2-256 second 2000",
            ],
            ("phase1", "phase1"),
            ("g14_esp_aes256_sha", "g14-esp-aes256-sha"),
            "Phase 2 proposal collides after Junos normalization",
        ),
    ],
)
def test_builtin_proposals_reject_explicit_normalized_collisions(
    write_input_file,
    proposal_lines: list[str],
    gateway_proposals: tuple[str, str],
    vpn_proposals: tuple[str, str],
    expected_reason: str,
) -> None:
    input_path = write_input_file(
        "\n".join(
            [
                'set interface ethernet0/0 zone "Untrust"',
                "set interface ethernet0/0 ip 203.0.113.2/24",
                *proposal_lines,
                (
                    'set ike gateway "peer_one" address 198.51.100.1 Main '
                    'outgoing-interface "ethernet0/0" preshare "first-leak-marker" proposal '
                    f'"{gateway_proposals[0]}"'
                ),
                (
                    'set vpn "vpn_one" gateway "peer_one" replay tunnel idletime 0 '
                    f'proposal "{vpn_proposals[0]}"'
                ),
                (
                    'set ike gateway "peer_two" address 198.51.100.2 Main '
                    'outgoing-interface "ethernet0/0" preshare "second-leak-marker" proposal '
                    f'"{gateway_proposals[1]}"'
                ),
                (
                    'set vpn "vpn_two" gateway "peer_two" replay tunnel idletime 0 '
                    f'proposal "{vpn_proposals[1]}"'
                ),
            ]
        )
    )
    converter = Converter(progress_interval=9999)

    converter.read_file(input_path)

    assert any(
        expected_reason in diagnostic.reason
        for diagnostic in converter.state.diagnostics
    )
    assert "vpn_one" in converter.state.rendered_vpns
    assert "vpn_two" not in converter.state.rendered_vpns
    assert "first-leak-marker" not in repr(converter.state)
    assert "second-leak-marker" not in repr(converter.state)


def test_unmappable_idp_suppresses_linked_source_nat(write_input_file) -> None:
    input_path = write_input_file(
        "\n".join(
            [
                'set address "Untrust" "CLIENT" 198.51.100.10 255.255.255.255',
                'set address "Trust" "SERVER" 192.0.2.10 255.255.255.255',
                (
                    'set policy id 40 from "Untrust" to "Trust" "CLIENT" "SERVER" '
                    '"ANY" nat src permit attack "UNKNOWN" action close'
                ),
            ]
        )
    )
    converter = Converter(progress_interval=9999)

    converter.read_file(input_path)

    assert converter.state.policies[0].idp_invalid is True
    assert not any(
        line.startswith("set security nat source")
        for line in converter.state.converted_config
    )
    assert not any(
        "set security policies" in line for line in converter.state.converted_config
    )
