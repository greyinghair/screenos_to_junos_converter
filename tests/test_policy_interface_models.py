from __future__ import annotations

from pathlib import Path

import pytest

from packages.conversion_models import (
    InterfaceMapping,
    PolicyModel,
    map_screenos_interface,
)
from packages.converter_core import Converter

FIXTURE_ROOT = Path(__file__).parent / "fixtures"


@pytest.mark.parametrize(
    ("screenos_name", "expected"),
    [
        (
            "ethernet0/3",
            InterfaceMapping(kind="ethernet", physical_name="ge-0/0/3", unit=0),
        ),
        (
            "ethernet1/2.40",
            InterfaceMapping(kind="ethernet", physical_name="ge-1/0/2", unit=40),
        ),
        (
            "mgt",
            InterfaceMapping(kind="management", physical_name="fxp0", unit=0),
        ),
        (
            "tunnel.8",
            InterfaceMapping(kind="tunnel", physical_name="st0", unit=8),
        ),
        (
            "vlan300",
            InterfaceMapping(kind="vlan", physical_name="irb", unit=300),
        ),
    ],
)
def test_screenos_interface_mapping_is_stable(
    screenos_name: str,
    expected: InterfaceMapping,
) -> None:
    assert map_screenos_interface(screenos_name) == expected


def test_unsupported_interface_mapping_is_explicit() -> None:
    with pytest.raises(
        ValueError,
        match='unsupported ScreenOS interface type: "serial0/0"',
    ):
        map_screenos_interface("serial0/0")


def test_global_and_zone_policies_share_one_model_and_ordering_pipeline() -> None:
    converter = Converter(progress_interval=9999)
    converter.read_file(FIXTURE_ROOT / "features" / "global_policies.screenos")

    assert converter.state.failed == 0
    assert all(isinstance(policy, PolicyModel) for policy in converter.state.policies)
    assert [policy.scope for policy in converter.state.policies] == [
        "zone",
        "global",
        "global",
        "global",
    ]

    policy_lines = [
        line
        for line in converter.state.converted_config
        if line.startswith("set security policies ")
    ]
    first_global = next(
        index
        for index, line in enumerate(policy_lines)
        if line.startswith("set security policies global ")
    )
    assert all(
        line.startswith("set security policies from-zone ")
        for line in policy_lines[:first_global]
    )
    assert [
        line.split(" policy ", maxsplit=1)[1].split()[0]
        for line in policy_lines
        if " match source-address " in line and " policies global " in line
    ] == ["global_first", "global_middle", "global_web", "global_web"]


def test_disable_directive_is_retained_on_the_normalized_policy_model() -> None:
    converter = Converter(progress_interval=9999)
    converter.read_file(FIXTURE_ROOT / "negative" / "policies.screenos")

    disabled = next(
        policy for policy in converter.state.policies if policy.policy_id == "20"
    )
    assert disabled.scope == "global"
    assert disabled.disabled is True
    assert not any(" policy 20 " in line for line in converter.state.converted_config)


def test_interface_references_resolve_to_rendered_logical_units() -> None:
    converter = Converter(progress_interval=9999)
    converter.read_file(FIXTURE_ROOT / "features" / "interfaces.screenos")

    assert converter.state.failed == 0
    output = converter.state.converted_config
    for screenos_name, logical_name in converter.state.interface_ns_to_junos.items():
        model = converter.state.interfaces[screenos_name]
        if model.zone is None:
            continue
        zone_reference = (
            f"set security zones security-zone {model.zone} interfaces {logical_name}"
        )
        assert zone_reference in output
        assert any(
            line.startswith(
                f"set interfaces {model.mapping.physical_name} "
                f"unit {model.mapping.unit} "
            )
            for line in output
        )
