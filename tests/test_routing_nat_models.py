from __future__ import annotations

from pathlib import Path

from packages.conversion_models import (
    BgpInstanceModel,
    DipPoolModel,
    MipModel,
    SourceNatRuleModel,
    StaticRouteModel,
)
from packages.converter_core import Converter

FIXTURE_ROOT = Path(__file__).parent / "fixtures"


def test_static_routes_and_bgp_share_resolved_routing_state() -> None:
    converter = Converter(progress_interval=9999)
    converter.read_file(FIXTURE_ROOT / "features" / "routing.screenos")

    assert converter.state.failed == 0
    assert all(
        isinstance(route, StaticRouteModel) for route in converter.state.static_routes
    )
    assert len(converter.state.static_routes) == 3

    bgp = converter.state.bgp_instances["trust-vr"]
    assert isinstance(bgp, BgpInstanceModel)
    assert bgp.local_as == 64500
    assert bgp.enabled is True
    assert list(bgp.peer_groups) == ["Transit Peers", "IPv6 Transit"]
    assert list(bgp.peers) == [
        "198.51.100.1",
        "198.51.100.2",
        "2001:db8::2",
    ]
    assert all(peer.enabled for peer in bgp.peers.values())

    output = converter.state.converted_config
    for route in converter.state.static_routes:
        if route.interface is None or route.interface == "null":
            continue
        assert route.interface in converter.state.rendered_interfaces
        logical_name = converter.state.interface_ns_to_junos[route.interface]
        assert any(logical_name in line for line in output)

    assert (
        "set routing-instances customer_vr interface st0.8"
        in converter.state.converted_config
    )
    assert (
        "set protocols bgp group transit_peers local-address 203.0.113.2"
        in converter.state.converted_config
    )


def test_bgp_authentication_secret_is_omitted_and_redacted(tmp_path: Path) -> None:
    secrets = (
        "distinctive-bgp-secret",
        "unquoted-bgp-secret",
        "unterminated-bgp-secret",
    )
    input_path = tmp_path / "bgp-secret.screenos"
    output_path = tmp_path / "bgp-secret.junos"
    input_path.write_text(
        "\n".join(
            [
                "set vrouter trust-vr protocol bgp 64500",
                "set vrouter trust-vr protocol bgp enable",
                (
                    'set vrouter trust-vr protocol bgp neighbor peer-group "External" '
                    "remote-as 64501"
                ),
                (
                    'set vrouter trust-vr protocol bgp neighbor peer-group "External" '
                    f'md5-authentication "{secrets[0]}"'
                ),
                (
                    "set vrouter trust-vr protocol bgp neighbor 198.51.100.1 "
                    'peer-group "External"'
                ),
                "set vrouter trust-vr protocol bgp neighbor 198.51.100.1 enable",
                (
                    "set vrouter trust-vr protocol bgp neighbor 198.51.100.1 "
                    f"md5-authentication {secrets[1]}"
                ),
                (
                    "set vrouter trust-vr protocol bgp neighbor 198.51.100.2 "
                    f'md5-authentication "{secrets[2]}'
                ),
            ]
        )
        + "\n",
        encoding="utf-8",
    )

    converter = Converter(progress_interval=9999)
    converter.read_file(input_path)
    converter.converted_config_output(output_path)

    persisted_state = output_path.read_text(encoding="utf-8") + repr(converter.state)
    assert all(secret not in persisted_state for secret in secrets)
    authentication_diagnostics = [
        diagnostic
        for diagnostic in converter.state.diagnostics
        if diagnostic.reason
        == (
            "BGP MD5 authentication secret omitted; configure a Junos "
            "authentication key manually"
        )
    ]
    assert len(authentication_diagnostics) == 2
    assert all(
        diagnostic.line.endswith("md5-authentication <redacted>")
        for diagnostic in authentication_diagnostics
    )
    assert any(
        diagnostic.line.endswith("md5-authentication <redacted>")
        and diagnostic.reason == "malformed virtual-router definition"
        for diagnostic in converter.state.diagnostics
    )
    assert (
        "set protocols bgp group external neighbor 198.51.100.1"
        in converter.state.converted_config
    )


def test_nat_models_preserve_precedence_and_policy_linkage() -> None:
    converter = Converter(progress_interval=9999)
    converter.read_file(FIXTURE_ROOT / "features" / "nat.screenos")

    assert converter.state.failed == 0
    assert all(isinstance(mip, MipModel) for mip in converter.state.mips)
    assert all(
        isinstance(pool, DipPoolModel) for pool in converter.state.dip_pools.values()
    )
    assert all(
        isinstance(rule, SourceNatRuleModel)
        for rule in converter.state.source_nat_rules
    )
    assert [rule.policy_id for rule in converter.state.source_nat_rules] == [
        "10",
        "20",
    ]

    output = converter.state.converted_config
    static_rule_index = next(
        index
        for index, line in enumerate(output)
        if line.startswith("set security nat static rule-set")
    )
    source_rule_index = next(
        index
        for index, line in enumerate(output)
        if line.startswith("set security nat source rule-set")
    )
    assert static_rule_index < source_rule_index

    assert (
        "set security policies from-zone Untrust to-zone Trust policy mip_web "
        "match destination-address mip_203_0_113_10" in output
    )
    assert (
        "set security nat source rule-set screenos_trust_to_untrust "
        "rule policy_dip_traffic_10 then source-nat pool screenos_dip_5" in output
    )
    assert (
        "set security nat source rule-set screenos_trust_to_untrust "
        "rule policy_interface_traffic_20 then source-nat interface" in output
    )
