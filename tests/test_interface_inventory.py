from __future__ import annotations

import json
from pathlib import Path

from packages.conversion_models import InterfaceMappingRequest
from packages.conversion_service import convert_configuration
from packages.converter_core import Converter
from packages.interface_inventory import (
    InterfaceInventory,
    build_interface_inventory,
)

FIXTURE_ROOT = Path(__file__).parent / "fixtures"
INVENTORY_FIXTURE = FIXTURE_ROOT / "features" / "interface_inventory.screenos"


def run_inventory(path: Path) -> InterfaceInventory:
    converter = Converter(progress_interval=9999)
    converter.read_file(path)
    converter.disabled_rule_cleanup()
    return build_interface_inventory(converter.state)


def binding_identifiers(
    inventory: InterfaceInventory,
    screenos_name: str,
    category: str,
) -> list[str]:
    entry = inventory.entry(screenos_name)
    assert entry is not None
    return [
        binding.identifier for binding in entry.bindings if binding.category == category
    ]


def test_inventory_lists_every_defined_interface_in_a_stable_order() -> None:
    inventory = run_inventory(INVENTORY_FIXTURE)

    assert [entry.screenos_name for entry in inventory.interfaces] == [
        "ethernet0/0",
        "ethernet0/1.100",
        "ethernet0/4",
        "ethernet0/5",
        "tunnel.10",
    ]
    entry = inventory.entry("ethernet0/1.100")
    assert entry is not None
    assert entry.junos_name == "ge-0/0/1.100"
    assert entry.physical_name == "ge-0/0/1"
    assert entry.unit == 100
    assert entry.vlan_id == 100
    assert entry.zone == "Trust"
    assert entry.ipv4_addresses == ("192.0.2.1/24",)
    assert entry.rendered is True
    assert entry.mapped is False


def test_inventory_records_every_migration_relevant_binding() -> None:
    inventory = run_inventory(INVENTORY_FIXTURE)
    entry = inventory.entry("ethernet0/0")
    assert entry is not None

    assert dict(entry.binding_counts) == {
        "address": 1,
        "policy": 2,
        "route": 1,
        "source-nat": 2,
        "static-nat": 1,
        "unnumbered": 1,
        "vpn": 1,
        "zone": 1,
    }
    assert entry.binding_total == 10
    assert binding_identifiers(inventory, "ethernet0/0", "policy") == [
        "zone:10",
        "zone:20",
    ]
    assert binding_identifiers(inventory, "ethernet0/0", "source-nat") == [
        "dip-6",
        "policy:10",
    ]
    assert binding_identifiers(inventory, "ethernet0/0", "static-nat") == [
        "198.51.100.30/32"
    ]
    assert binding_identifiers(inventory, "ethernet0/0", "vpn") == ["branch_gateway"]
    assert binding_identifiers(inventory, "tunnel.10", "routing-instance") == [
        "customer-vr"
    ]
    assert binding_identifiers(inventory, "tunnel.10", "vpn") == ["route_vpn"]


def test_address_bindings_require_containment_in_the_interface_network() -> None:
    inventory = run_inventory(INVENTORY_FIXTURE)

    # USER1 (192.0.2.10/32) is inside the Trust interface network; OFFSITE is a
    # Trust object outside it and must not be reported as a binding.
    assert binding_identifiers(inventory, "ethernet0/1.100", "address") == ["USER1"]
    assert binding_identifiers(inventory, "ethernet0/0", "address") == ["PARTNER"]


def test_unnumbered_donors_are_recorded_on_both_interfaces() -> None:
    inventory = run_inventory(INVENTORY_FIXTURE)

    assert binding_identifiers(inventory, "tunnel.10", "unnumbered") == ["ethernet0/0"]
    assert binding_identifiers(inventory, "ethernet0/0", "unnumbered") == ["tunnel.10"]


def test_interfaces_without_bindings_have_an_explicit_empty_state() -> None:
    inventory = run_inventory(INVENTORY_FIXTURE)
    entry = inventory.entry("ethernet0/5")
    assert entry is not None

    assert entry.bindings == ()
    assert entry.binding_counts == ()
    assert entry.binding_total == 0
    assert entry.has_bindings is False
    assert entry.rendered is False


def test_every_binding_carries_traceable_source_context() -> None:
    source_lines = INVENTORY_FIXTURE.read_text(encoding="utf-8").splitlines()
    inventory = run_inventory(INVENTORY_FIXTURE)

    for entry in inventory.interfaces:
        for binding in entry.bindings:
            assert binding.summary
            assert binding.line_number is not None
            source_line = source_lines[binding.line_number - 1]
            # Secrets stay redacted on their way into the inventory, so a
            # binding quotes the first tokens of its source rather than all of
            # it.
            assert binding.source_line.split()[:4] == source_line.split()[:4]
            assert "fixture-only-secret" not in binding.source_line


def test_unsupported_and_undefined_references_are_reported_with_context() -> None:
    inventory = run_inventory(FIXTURE_ROOT / "negative" / "interfaces.screenos")

    unresolved = {
        (reference.screenos_name, reference.category, reference.line_number)
        for reference in inventory.unresolved
    }
    assert ("serial0/0", "unsupported", 1) in unresolved
    assert ("ethernet0/9", "unnumbered", 7) in unresolved
    assert binding_identifiers(inventory, "ethernet0/3", "unsupported") == ["line-10"]
    entry = inventory.entry("ethernet0/3")
    assert entry is not None
    assert entry.bindings[0].summary == "unsupported interface attribute: monitor link"
    assert entry.rendered is False


def test_inventory_is_deterministic_and_json_serializable() -> None:
    first = run_inventory(INVENTORY_FIXTURE)
    second = run_inventory(INVENTORY_FIXTURE)

    assert first == second
    document = json.dumps(first.as_dict(), sort_keys=False)
    assert json.loads(document) == json.loads(json.dumps(second.as_dict()))
    assert json.loads(document)["interfaces"][0]["screenos_name"] == "ethernet0/0"


def test_pasted_and_uploaded_configuration_yield_the_same_inventory() -> None:
    source = INVENTORY_FIXTURE.read_text(encoding="utf-8")

    pasted = convert_configuration(source)
    uploaded = convert_configuration(source.encode("utf-8"))

    assert pasted.interface_inventory == uploaded.interface_inventory
    assert pasted.interface_inventory == run_inventory(INVENTORY_FIXTURE)


def test_inventory_reports_the_mapped_destination_after_a_mapping_is_applied() -> None:
    result = convert_configuration(
        INVENTORY_FIXTURE.read_text(encoding="utf-8"),
        interface_mappings=[
            InterfaceMappingRequest(
                screenos_name="ethernet0/0",
                physical_name="ge-3/0/1",
            )
        ],
    )

    entry = result.interface_inventory.entry("ethernet0/0")
    assert entry is not None
    assert entry.junos_name == "ge-3/0/1.0"
    assert entry.mapped is True
    assert result.interface_inventory.entry("ethernet0/4").junos_name == "ge-0/0/4.0"
