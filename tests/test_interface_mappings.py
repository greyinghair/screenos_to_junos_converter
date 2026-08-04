from __future__ import annotations

import json
from pathlib import Path

import pytest

from packages.conversion_models import (
    InterfaceMapping,
    InterfaceMappingError,
    InterfaceMappingRequest,
    resolve_interface_mappings,
)
from packages.conversion_service import ConversionInputError, convert_configuration
from packages.converter_core import Converter

FIXTURE_ROOT = Path(__file__).parent / "fixtures"


def load_requests(path: Path) -> list[InterfaceMappingRequest]:
    return [
        InterfaceMappingRequest(**entry)
        for entry in json.loads(path.read_text(encoding="utf-8"))
    ]


def run_mapped_fixture(stem: str, directory: str) -> Converter:
    requests = load_requests(FIXTURE_ROOT / directory / f"{stem}.mappings.json")
    converter = Converter(
        progress_interval=9999,
        interface_mappings=resolve_interface_mappings(requests),
    )
    converter.read_file(FIXTURE_ROOT / directory / f"{stem}.screenos")
    converter.disabled_rule_cleanup()
    return converter


def test_resolver_accepts_tagged_and_untagged_destinations() -> None:
    resolved = resolve_interface_mappings(
        [
            InterfaceMappingRequest(
                screenos_name="ethernet0/1.100",
                physical_name="xe-2/0/1",
                unit=7,
                vlan_mode="tagged",
                vlan_id=100,
            ),
            InterfaceMappingRequest(
                screenos_name="ethernet0/0",
                physical_name="ge-0/0/9",
            ),
        ]
    )

    # Sorted by ScreenOS name so submission order cannot change the output.
    assert list(resolved) == ["ethernet0/0", "ethernet0/1.100"]
    assert resolved["ethernet0/0"].mapping == InterfaceMapping(
        kind="ethernet",
        physical_name="ge-0/0/9",
        unit=0,
    )
    assert resolved["ethernet0/0"].summary == "ge-0/0/9.0 (untagged)"
    assert resolved["ethernet0/1.100"].summary == "xe-2/0/1.7 (tagged, vlan-id 100)"


@pytest.mark.parametrize(
    ("requests", "message"),
    [
        (
            [InterfaceMappingRequest("serial0/0", "ge-0/0/1")],
            'unsupported ScreenOS interface type: "serial0/0"',
        ),
        (
            [InterfaceMappingRequest("ethernet0/0", "gigabit0")],
            'unsupported Junos interface name: "gigabit0"',
        ),
        (
            [InterfaceMappingRequest("ethernet0/0", "ge-0/0/1", unit=3)],
            "is untagged, so it must use unit 0",
        ),
        (
            [
                InterfaceMappingRequest(
                    "ethernet0/0", "ge-0/0/1", unit=3, vlan_mode="access", vlan_id=10
                )
            ],
            "must not carry a VLAN ID",
        ),
        (
            [
                InterfaceMappingRequest(
                    "ethernet0/0", "ge-0/0/1", unit=3, vlan_mode="tagged"
                )
            ],
            "tagged VLAN ID must be between 1 and 4094",
        ),
        (
            [
                InterfaceMappingRequest(
                    "ethernet0/0", "ge-0/0/1", vlan_mode="tagged", vlan_id=10
                )
            ],
            "tagged mappings require a logical unit other than 0",
        ),
        (
            [
                InterfaceMappingRequest(
                    "tunnel.1", "st0", unit=1, vlan_mode="tagged", vlan_id=10
                )
            ],
            "does not accept a VLAN tag",
        ),
        (
            [InterfaceMappingRequest("mgt", "fxp0", unit=2)],
            "only supports unit 0",
        ),
        (
            [InterfaceMappingRequest("ethernet0/0", "ge-0/0/1", unit=99999)],
            "unit must be between 0 and 16385",
        ),
        (
            [
                InterfaceMappingRequest("ethernet0/0", "ge-0/0/1"),
                InterfaceMappingRequest("ethernet0/0", "ge-0/0/2"),
            ],
            'duplicate mapping for ScreenOS interface "ethernet0/0"',
        ),
        (
            [
                InterfaceMappingRequest("ethernet0/0", "ge-0/0/1"),
                InterfaceMappingRequest("ethernet0/2", "ge-0/0/1"),
            ],
            "both map to ge-0/0/1.0",
        ),
        (
            [
                InterfaceMappingRequest("ethernet0/0", "ge-0/0/1"),
                InterfaceMappingRequest(
                    "ethernet0/2.5", "ge-0/0/1", unit=5, vlan_mode="tagged", vlan_id=5
                ),
            ],
            "mix tagged and untagged units on ge-0/0/1",
        ),
        (
            [InterfaceMappingRequest("ethernet0/0", "ge-0/0/1", vlan_mode="trunk")],
            "unsupported VLAN mode",
        ),
    ],
)
def test_invalid_mappings_are_rejected_before_rendering(
    requests: list[InterfaceMappingRequest],
    message: str,
) -> None:
    with pytest.raises(InterfaceMappingError) as error:
        resolve_interface_mappings(requests)

    assert message in str(error.value)


def test_mapped_fixture_is_exact_and_deterministic() -> None:
    expected = (
        (FIXTURE_ROOT / "features" / "interface_mapping.junos")
        .read_text(encoding="utf-8")
        .splitlines()
    )

    first = run_mapped_fixture("interface_mapping", "features")
    second = run_mapped_fixture("interface_mapping", "features")

    assert first.state.converted_config == expected
    assert second.state.converted_config == expected
    assert first.state.failed == 0
    assert first.state.diagnostics == []
    # The two annotation comments describe the run; they are not converted input.
    assert first.state.succeeded == len(expected) - 2


def test_every_supported_reference_follows_the_applied_mapping() -> None:
    converter = run_mapped_fixture("interface_mapping", "features")
    output = converter.state.converted_config

    assert converter.state.interface_ns_to_junos == {
        "ethernet0/0": "ge-0/0/9.0",
        "ethernet0/1.100": "xe-2/0/1.7",
        "ethernet0/2": "ge-0/0/2.0",
    }
    for stale in ("ge-0/0/0", "ge-0/0/1", "ethernet0/"):
        assert not any(stale in line for line in output if not line.startswith("#"))
    for expected_line in (
        "set security zones security-zone Untrust interfaces ge-0/0/9.0",
        "set interfaces xe-2/0/1 vlan-tagging",
        "set interfaces xe-2/0/1 unit 7 vlan-id 100",
        "set security nat static rule-set screenos_mip_ge_0_0_9_0 "
        "from interface ge-0/0/9.0",
        "set security nat proxy-arp interface ge-0/0/9.0 address 198.51.100.40/32",
    ):
        assert expected_line in output


def test_unmapped_conversion_of_the_same_source_keeps_default_names() -> None:
    converter = Converter(progress_interval=9999)
    converter.read_file(FIXTURE_ROOT / "features" / "interface_mapping.screenos")
    converter.disabled_rule_cleanup()

    assert converter.state.failed == 0
    assert converter.state.applied_interface_mappings == {}
    assert not any(
        line.startswith("# Applied interface mapping")
        for line in converter.state.converted_config
    )
    assert converter.state.interface_ns_to_junos == {
        "ethernet0/0": "ge-0/0/0.0",
        "ethernet0/1.100": "ge-0/0/1.100",
        "ethernet0/2": "ge-0/0/2.0",
    }


def test_conflicting_and_lossy_mappings_are_diagnosed_with_source_lines() -> None:
    expected_diagnostics = (
        (FIXTURE_ROOT / "negative" / "interface_mapping.diagnostics")
        .read_text(encoding="utf-8")
        .splitlines()
    )

    converter = run_mapped_fixture("interface_mapping", "negative")

    assert [
        f"{diagnostic.line_number}|{diagnostic.reason}"
        for diagnostic in converter.state.diagnostics
    ] == expected_diagnostics
    assert converter.state.failed == len(expected_diagnostics)
    assert not any("ge-0/0/5" in line for line in converter.state.converted_config)


def test_retagging_an_interface_raises_a_manual_review_warning() -> None:
    result = convert_configuration(
        "\n".join(
            [
                "set interface ethernet0/1.100 tag 100",
                'set interface ethernet0/1.100 zone "Trust"',
                "set interface ethernet0/1.100 ip 192.0.2.1/24",
            ]
        ),
        interface_mappings=[
            InterfaceMappingRequest(
                screenos_name="ethernet0/1.100",
                physical_name="ge-0/0/4",
                unit=100,
                vlan_mode="tagged",
                vlan_id=250,
            )
        ],
    )

    assert "set interfaces ge-0/0/4 unit 100 vlan-id 250" in result.output
    assert result.unsupported_count == 0
    assert result.manual_review_warnings == (
        'interface "ethernet0/1.100" is retagged from ScreenOS VLAN 100 to VLAN 250 '
        "on ge-0/0/4.100; confirm the adjacent switch port",
    )


def test_service_rejects_invalid_mappings_as_input_errors() -> None:
    with pytest.raises(ConversionInputError, match="Invalid interface mapping"):
        convert_configuration(
            'set interface ethernet0/0 zone "Trust"',
            interface_mappings=[
                InterfaceMappingRequest("ethernet0/0", "not-an-interface")
            ],
        )


def test_service_reports_the_applied_mapping_for_downloads() -> None:
    source = (FIXTURE_ROOT / "features" / "interface_mapping.screenos").read_text(
        encoding="utf-8"
    )

    result = convert_configuration(
        source,
        interface_mappings=load_requests(
            FIXTURE_ROOT / "features" / "interface_mapping.mappings.json"
        ),
    )

    assert [applied.screenos_name for applied in result.applied_interface_mappings] == [
        "ethernet0/0",
        "ethernet0/1.100",
    ]
    assert result.output.startswith(
        "# Applied interface mapping: ethernet0/0 -> ge-0/0/9.0 (untagged)\n"
    )
