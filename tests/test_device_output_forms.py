"""Coverage for the ScreenOS command forms a device writes when saving config."""

from __future__ import annotations

from packages.convert_service import (
    convert_service_in_file,
    is_supported_service_definition,
)
from packages.converter_core import Converter


def test_blank_lines_and_comments_are_ignored_entirely(write_input_file) -> None:
    input_path = write_input_file(
        "\n".join(
            [
                "# saved configuration banner",
                "",
                "! alternate comment marker",
                'set address "Trust" "Host" 192.0.2.1 255.255.255.255',
                "   ",
            ],
        ),
    )
    converter = Converter()

    converter.read_file(input_path)

    assert converter.state.failed == 0
    assert converter.state.diagnostics == []
    assert (
        "set security zones security-zone Trust address-book address host 192.0.2.1"
        in converter.state.converted_config
    )


def test_policy_context_block_applies_continuations_and_flags(write_input_file) -> None:
    input_path = write_input_file(
        "\n".join(
            [
                'set address "Trust" "Source" 192.0.2.1 255.255.255.255',
                'set address "Untrust" "Target" 198.51.100.1 255.255.255.255',
                'set address "Untrust" "Target Two" 198.51.100.2 255.255.255.255',
                'set policy id 5 from "Trust" to "Untrust" "Source" "Target" "HTTP" permit',
                "set policy id 5",
                'set dst-address "Target Two"',
                'set service "HTTPS"',
                "set log session-init",
                "set count",
                "exit",
            ],
        ),
    )
    converter = Converter()

    converter.read_file(input_path)

    prefix = "set security policies from-zone Trust to-zone Untrust policy 5"
    assert converter.state.failed == 0
    assert f"{prefix} match destination-address target_two" in (
        converter.state.converted_config
    )
    assert f"{prefix} match application junos-https" in converter.state.converted_config
    assert f"{prefix} then log session-init" in converter.state.converted_config
    assert f"{prefix} then count" in converter.state.converted_config


def test_exit_closes_the_policy_context(write_input_file) -> None:
    input_path = write_input_file(
        "\n".join(
            [
                'set address "Trust" "Source" 192.0.2.1 255.255.255.255',
                'set address "Untrust" "Target" 198.51.100.1 255.255.255.255',
                'set policy id 5 from "Trust" to "Untrust" "Source" "Target" "HTTP" permit',
                "set policy id 5",
                "exit",
                'set dst-address "Target"',
            ],
        ),
    )
    converter = Converter()

    converter.read_file(input_path)

    assert [
        (diagnostic.line_number, diagnostic.reason)
        for diagnostic in converter.state.diagnostics
    ] == [
        (6, "policy continuation has no resolvable base policy or object"),
    ]


def test_interface_accepts_dotted_netmask_and_combined_tag_zone(
    write_input_file,
) -> None:
    input_path = write_input_file(
        "\n".join(
            [
                'set interface ethernet0/0 zone "Untrust"',
                "set interface ethernet0/0 ip 198.51.100.1 255.255.255.0",
                'set interface ethernet0/1.100 tag 100 zone "Trust"',
                "set interface ethernet0/1.100 ip 192.0.2.1 255.255.255.128",
            ],
        ),
    )
    converter = Converter()

    converter.read_file(input_path)

    assert converter.state.failed == 0
    assert "set interfaces ge-0/0/0 unit 0 family inet address 198.51.100.1/24" in (
        converter.state.converted_config
    )
    assert "set interfaces ge-0/0/1 vlan-tagging" in converter.state.converted_config
    assert "set interfaces ge-0/0/1 unit 100 vlan-id 100" in (
        converter.state.converted_config
    )
    assert "set security zones security-zone Trust interfaces ge-0/0/1.100" in (
        converter.state.converted_config
    )


def test_mip_accepts_the_abbreviated_vr_keyword(write_input_file) -> None:
    input_path = write_input_file(
        "\n".join(
            [
                'set interface ethernet0/0 zone "Untrust"',
                "set interface ethernet0/0 ip 198.51.100.1 255.255.255.0",
                "set interface ethernet0/0 mip 198.51.100.20 host 192.0.2.20 "
                "netmask 255.255.255.255 vr trust-vr",
            ],
        ),
    )
    converter = Converter()

    converter.read_file(input_path)

    assert converter.state.failed == 0
    assert (
        "set security address-book global address mip_198_51_100_20 192.0.2.20/32"
        in (converter.state.converted_config)
    )


def test_icmp_and_protocol_services_convert() -> None:
    assert is_supported_service_definition(
        'set service "Echo" protocol icmp type 8 code 0',
    )
    assert convert_service_in_file(
        'set service "Echo" protocol icmp type 8 code 0'
    ) == (
        "icmp_8_0",
        "set applications application icmp_8_0 protocol icmp icmp-type 8 icmp-code 0",
    )
    assert convert_service_in_file('set service "Unreach" protocol icmp type 3') == (
        "icmp_3",
        "set applications application icmp_3 protocol icmp icmp-type 3",
    )
    assert convert_service_in_file(
        'set service "GRE" protocol 47 src-port 0-65535 dst-port 0-65535',
    ) == (
        "protocol_47",
        "set applications application protocol_47 protocol 47",
    )


def test_ported_protocol_numbers_are_rejected() -> None:
    for protocol_number in (1, 6, 17):
        try:
            convert_service_in_file(f'set service "Bad" protocol {protocol_number}')
        except ValueError as error:
            assert "requires the named tcp, udp, or icmp service form" in str(error)
        else:  # pragma: no cover - guards a silently widened rule
            raise AssertionError(
                f"protocol {protocol_number} must not convert without ports",
            )


def test_group_comments_become_descriptions_after_the_first_member(
    write_input_file,
) -> None:
    input_path = write_input_file(
        "\n".join(
            [
                'set address "Trust" "Host" 192.0.2.1 255.255.255.255',
                'set group address "Trust" "Group" comment "Internal ranges"',
                'set group address "Trust" "Group" add "Host"',
                'set service "Alt" protocol tcp src-port 0-65535 dst-port 8080-8080',
                'set group service "Suite" comment "Alternate web"',
                'set group service "Suite" add "Alt"',
            ],
        ),
    )
    converter = Converter()

    converter.read_file(input_path)

    converted = converter.state.converted_config
    assert converter.state.failed == 0
    member_line = (
        "set security zones security-zone Trust address-book address-set group "
        "address host"
    )
    description_line = (
        "set security zones security-zone Trust address-book address-set group "
        'description "Internal ranges"'
    )
    assert converted.index(member_line) < converted.index(description_line)
    assert 'set applications application-set suite description "Alternate web"' in (
        converted
    )


def test_scheduled_policies_are_omitted_rather_than_made_always_on(
    write_input_file,
) -> None:
    input_path = write_input_file(
        "\n".join(
            [
                'set address "Trust" "Source" 192.0.2.1 255.255.255.255',
                'set address "Untrust" "Target" 198.51.100.1 255.255.255.255',
                'set policy id 7 from "Trust" to "Untrust" "Source" "Target" "HTTP" permit',
                'set policy id 7 schedule "Weekends"',
            ],
        ),
    )
    converter = Converter()

    converter.read_file(input_path)

    assert not any(
        line.startswith("set security policies from-zone Trust")
        for line in converter.state.converted_config
    )
    assert [diagnostic.reason for diagnostic in converter.state.diagnostics] == [
        "scheduled zone policy 7 omitted from output; convert the ScreenOS "
        "scheduler to a Junos scheduler and reattach the policy manually",
    ]


def test_count_alarm_and_traffic_shaping_keep_the_policy(write_input_file) -> None:
    input_path = write_input_file(
        "\n".join(
            [
                'set address "Trust" "Source" 192.0.2.1 255.255.255.255',
                'set address "Untrust" "Target" 198.51.100.1 255.255.255.255',
                'set policy id 8 from "Trust" to "Untrust" "Source" "Target" "HTTP" '
                "permit log count alarm 1000 100",
                "set policy id 8 traffic priority 3",
            ],
        ),
    )
    converter = Converter()

    converter.read_file(input_path)

    prefix = "set security policies from-zone Trust to-zone Untrust policy 8"
    assert f"{prefix} then permit" in converter.state.converted_config
    assert f"{prefix} then count" in converter.state.converted_config
    assert [diagnostic.reason for diagnostic in converter.state.diagnostics] == [
        "policy count alarm thresholds are unsupported; the policy and its "
        "counter are converted without them",
        "policy traffic shaping is unsupported; the policy is converted "
        "without it, configure Junos CoS manually",
    ]
