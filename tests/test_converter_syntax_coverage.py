from __future__ import annotations

from packages.converter_core import Converter


def test_converter_supports_quoted_group_names_and_service_timeout(
    write_input_file,
) -> None:
    input_path = write_input_file(
        "\n".join(
            [
                'set service "Web Service" protocol tcp src-port 0-65535 dst-port 80-80 timeout 180',
                'set group service "Web Applications" add "Web Service"',
                'set address "Trust" "Source Host" 192.0.2.1 255.255.255.255',
                'set address "Untrust" "Target Host" 198.51.100.1 255.255.255.255',
                'set group address "Trust" "Source Group" add "Source Host"',
                'set policy id 1 from "Trust" to "Untrust" "Source Group" "Target Host" "Web Applications" permit',
            ],
        ),
    )
    converter = Converter()

    converter.read_file(input_path)

    assert "set applications application tcp_80 protocol tcp destination-port 80" in (
        converter.state.converted_config
    )
    assert (
        "set applications application-set web_applications application tcp_80"
        in converter.state.converted_config
    )
    assert (
        "set security zones security-zone Trust address-book address-set source_group "
        "address source_host" in converter.state.converted_config
    )
    assert (
        "set security policies from-zone Trust to-zone Untrust policy 1 "
        "match application web_applications" in converter.state.converted_config
    )
    assert converter.state.failed == 0


def test_converter_supports_multiline_policy_matches(write_input_file) -> None:
    input_path = write_input_file(
        "\n".join(
            [
                'set service "TCP/80" protocol tcp src-port 0-65535 dst-port 80-80',
                'set address "Trust" "SRC1" 192.0.2.1 255.255.255.255',
                'set address "Trust" "SRC2" 192.0.2.2 255.255.255.255',
                'set address "Untrust" "DST1" 198.51.100.1 255.255.255.255',
                'set address "Untrust" "DST2" 198.51.100.2 255.255.255.255',
                'set policy id 1 from "Trust" to "Untrust" "SRC1" "DST1" "TCP/80" permit',
                'set src-address "SRC2"',
                'set dst-address "DST2"',
                'set service "TCP/80"',
            ],
        ),
    )
    converter = Converter()

    converter.read_file(input_path)

    assert (
        "set security policies from-zone Trust to-zone Untrust policy 1 "
        "match source-address src2" in converter.state.converted_config
    )
    assert (
        "set security policies from-zone Trust to-zone Untrust policy 1 "
        "match destination-address dst2" in converter.state.converted_config
    )
    assert (
        "set security policies from-zone Trust to-zone Untrust policy 1 "
        "match application tcp_80" in converter.state.converted_config
    )
    assert converter.state.failed == 0


def test_converter_omits_disabled_policies(write_input_file) -> None:
    input_path = write_input_file(
        "\n".join(
            [
                'set service "TCP/80" protocol tcp src-port 0-65535 dst-port 80-80',
                'set address "Trust" "SRC1" 192.0.2.1 255.255.255.255',
                'set address "Untrust" "DST1" 198.51.100.1 255.255.255.255',
                'set policy id 1 from "Trust" to "Untrust" "SRC1" "DST1" "TCP/80" permit',
                "set policy id 1 disable",
            ],
        ),
    )
    converter = Converter()

    converter.read_file(input_path)
    converter.disabled_rule_cleanup()

    assert not any("policy 1" in line for line in converter.state.converted_config)
    assert converter.state.failed == 1
