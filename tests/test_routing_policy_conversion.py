"""Coverage for ScreenOS BGP routing-policy conversion."""

from __future__ import annotations

import pytest

from packages.converter_core import Converter


@pytest.mark.parametrize(
    ("screenos_pattern", "junos_pattern"),
    [
        ("^64512$", "64512"),
        ("_64520_", ".* 64520 .*"),
        ("_65100$", ".* 65100"),
        ("^64512_", "64512 .*"),
        ("^64512 64513$", "64512 64513"),
        (".*", ".*"),
        ("^$", "()"),
    ],
)
def test_supported_as_path_expressions_translate(
    screenos_pattern: str,
    junos_pattern: str,
) -> None:
    assert Converter.translate_as_path_regex(screenos_pattern) == junos_pattern


@pytest.mark.parametrize(
    "screenos_pattern",
    ["64512{2,3}", "^(64512|64513)$", "64512", "^6451[0-9]$", "^_$"],
)
def test_unverified_as_path_expressions_are_not_guessed(screenos_pattern: str) -> None:
    assert Converter.translate_as_path_regex(screenos_pattern) is None


@pytest.mark.parametrize(
    ("value", "expected"),
    [
        ("65001:100", "65001:100"),
        ("no-export", "no-export"),
        ("internet", "internet"),
        ("65001", None),
        ("65001:70000", None),
        ("not-a-community", None),
    ],
)
def test_community_values_are_validated(value: str, expected: str | None) -> None:
    assert Converter.normalize_community(value) == expected


def test_access_list_becomes_an_ordered_subroutine_policy(write_input_file) -> None:
    input_path = write_input_file(
        "\n".join(
            [
                'set vrouter "trust-vr" access-list 10 permit ip 192.0.2.0/24 10',
                'set vrouter "trust-vr" access-list 10 deny ip 0.0.0.0/0 20',
            ],
        ),
    )
    converter = Converter()

    converter.read_file(input_path)

    prefix = "set policy-options policy-statement screenos_acl_trust_vr_10"
    assert converter.state.failed == 0
    assert converter.state.converted_config[-5:] == [
        f"{prefix} term t10 from route-filter 192.0.2.0/24 orlonger",
        f"{prefix} term t10 then accept",
        f"{prefix} term t20 from route-filter 0.0.0.0/0 orlonger",
        f"{prefix} term t20 then reject",
        f"{prefix} term screenos_implicit_deny then reject",
    ]


def test_route_map_terms_render_in_sequence_order(write_input_file) -> None:
    input_path = write_input_file(
        "\n".join(
            [
                'set vrouter "trust-vr" access-list 10 permit ip 192.0.2.0/24 10',
                'set vrouter "trust-vr" route-map name "RM" permit 30 match ip 10',
                'set vrouter "trust-vr" route-map name "RM" deny 10 match ip 10',
                'set vrouter "trust-vr" route-map name "RM" permit 20 match ip 10',
            ],
        ),
    )
    converter = Converter()

    converter.read_file(input_path)

    sequences = [
        line.split(" term ")[1].split()[0]
        for line in converter.state.converted_config
        if line.startswith("set policy-options policy-statement rm term ")
    ]
    assert sequences == [
        "t10",
        "t10",
        "t20",
        "t20",
        "t30",
        "t30",
        "screenos_implicit_deny",
    ]


def test_unresolved_filter_withholds_the_whole_route_map(write_input_file) -> None:
    input_path = write_input_file(
        "\n".join(
            [
                'set vrouter "trust-vr" access-list 10 permit ip 192.0.2.0/24 10',
                'set vrouter "trust-vr" route-map name "RM" deny 10 match ip 99',
                'set vrouter "trust-vr" route-map name "RM" permit 20 match ip 10',
            ],
        ),
    )
    converter = Converter()

    converter.read_file(input_path)

    assert not any(
        line.startswith("set policy-options policy-statement rm ")
        for line in converter.state.converted_config
    )
    assert any(
        'route map "RM" was not converted' in warning
        for warning in converter.state.manual_review_warnings
    )


def test_unrepresentable_match_withholds_the_whole_route_map(write_input_file) -> None:
    input_path = write_input_file(
        "\n".join(
            [
                'set vrouter "trust-vr" access-list 10 permit ip 192.0.2.0/24 10',
                'set vrouter "trust-vr" route-map name "RM" permit 10 '
                "match interface ethernet0/0",
                'set vrouter "trust-vr" route-map name "RM" deny 20 match ip 10',
            ],
        ),
    )
    converter = Converter()

    converter.read_file(input_path)

    # An unrepresented match would otherwise leave term 10 accepting every
    # route, so the policy must not be emitted at all.
    assert not any(
        line.startswith("set policy-options policy-statement rm ")
        for line in converter.state.converted_config
    )


def test_lost_set_clause_keeps_the_policy_but_is_diagnosed(write_input_file) -> None:
    input_path = write_input_file(
        "\n".join(
            [
                'set vrouter "trust-vr" access-list 10 permit ip 192.0.2.0/24 10',
                'set vrouter "trust-vr" route-map name "RM" permit 10 match ip 10',
                'set vrouter "trust-vr" route-map name "RM" permit 10 set weight 100',
            ],
        ),
    )
    converter = Converter()

    converter.read_file(input_path)

    # Weight changes best-path preference, not which routes the term matches,
    # so the policy still converts.
    assert (
        "set policy-options policy-statement rm term t10 then accept"
        in converter.state.converted_config
    )
    assert [diagnostic.reason for diagnostic in converter.state.diagnostics] == [
        "BGP weight is Cisco/ScreenOS local and has no Junos equivalent; "
        "express the preference with local-preference or a Junos policy manually",
    ]


def test_route_map_names_match_the_bgp_import_reference(write_input_file) -> None:
    input_path = write_input_file(
        "\n".join(
            [
                'set interface ethernet0/0 zone "Untrust"',
                "set interface ethernet0/0 ip 198.51.100.1/24",
                'set vrouter "trust-vr" access-list 10 permit ip 192.0.2.0/24 10',
                'set vrouter "trust-vr" route-map name "RM-IN" permit 10 match ip 10',
                'set vrouter "trust-vr" protocol bgp 65001',
                'set vrouter "trust-vr" protocol bgp enable',
                'set vrouter "trust-vr" protocol bgp neighbor 198.51.100.2 remote-as 64512',
                'set vrouter "trust-vr" protocol bgp neighbor 198.51.100.2 enable',
                'set vrouter "trust-vr" protocol bgp neighbor 198.51.100.2 '
                'route-map "RM-IN" in',
            ],
        ),
    )
    converter = Converter()

    converter.read_file(input_path)

    imports = [
        line
        for line in converter.state.converted_config
        if line.endswith("import rm_in")
    ]
    definitions = [
        line
        for line in converter.state.converted_config
        if line.startswith("set policy-options policy-statement rm_in ")
    ]
    assert imports and definitions
