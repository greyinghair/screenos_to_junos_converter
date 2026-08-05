from __future__ import annotations

import json
from pathlib import Path

import pytest

from packages.conversion_service import convert_configuration
from packages.interface_inventory import InterfaceInventory
from packages.mapping_workspace import (
    DETAILED_ROW_LIMIT,
    MAX_WORKSPACE_ROWS,
    MappingSelection,
    build_workspace,
    conversion_flow,
    has_mapping_form,
    parse_mapping_form,
    read_selections,
)

FIXTURE_ROOT = Path(__file__).parent / "fixtures"


def inventory_for(stem: str, directory: str = "features") -> InterfaceInventory:
    source = (FIXTURE_ROOT / directory / f"{stem}.screenos").read_text(encoding="utf-8")
    return convert_configuration(source).interface_inventory


def form_for(stem: str, directory: str = "features") -> dict[str, str]:
    return json.loads(
        (FIXTURE_ROOT / directory / f"{stem}.form.json").read_text(encoding="utf-8")
    )


def test_an_untouched_workspace_maps_nothing_and_stays_valid() -> None:
    workspace = build_workspace(inventory_for("mapping_workspace"))

    assert [row.screenos_name for row in workspace.rows] == [
        "ethernet0/0",
        "ethernet0/1.100",
        "tunnel.1",
    ]
    assert workspace.mapped_count == 0
    assert workspace.requests == ()
    assert workspace.is_valid
    # Every row starts on the converter default and says which one it is.
    assert [row.current_target for row in workspace.rows] == [
        "ge-0/0/0.0",
        "ge-0/0/1.100",
        "st0.1",
    ]
    assert [row.status_label for row in workspace.rows] == ["Default mapping"] * 3


def test_the_workspace_shows_bindings_before_a_mapping_is_committed() -> None:
    workspace = build_workspace(inventory_for("interface_inventory"))

    row = next(row for row in workspace.rows if row.screenos_name == "ethernet0/0")
    categories = {category for category, _count, _icon, _label in row.binding_chips}

    assert {"policy", "route", "static-nat", "source-nat", "vpn", "zone"} <= categories
    assert row.binding_total > len(row.visible_bindings)
    assert row.hidden_binding_count == row.binding_total - len(row.visible_bindings)
    assert any(
        "address object" in label
        for _category, _count, _icon, label in row.binding_chips
    )
    assert all(binding.source_line for binding in row.visible_bindings)
    assert row.zone == "Untrust"
    assert row.addresses == ("198.51.100.1/24",)


def test_submitted_selections_become_validated_mapping_requests() -> None:
    workspace = parse_mapping_form(
        inventory_for("mapping_workspace"),
        form_for("mapping_workspace"),
    )

    assert workspace.is_valid
    assert workspace.mapped_count == 3
    assert [
        (request.screenos_name, request.physical_name, request.unit, request.vlan_mode)
        for request in workspace.requests
    ] == [
        ("ethernet0/0", "ge-0/0/9", 0, "access"),
        ("ethernet0/1.100", "xe-2/0/1", 7, "tagged"),
        ("tunnel.1", "st0", 5, "access"),
    ]


def test_preserved_vlan_treatment_comes_from_the_discovered_interface() -> None:
    inventory = inventory_for("mapping_workspace")
    workspace = build_workspace(
        inventory,
        selections={
            # "preserve" carries the ScreenOS tag across without the operator
            # having to retype it, and stays untagged when there is no tag.
            "ethernet0/1.100": MappingSelection(
                screenos_name="ethernet0/1.100",
                physical_name="ge-0/0/4",
                unit="12",
                vlan_choice="preserve",
            ),
            "ethernet0/0": MappingSelection(
                screenos_name="ethernet0/0",
                physical_name="ge-0/0/5",
                unit="0",
                vlan_choice="preserve",
            ),
        },
    )

    assert workspace.is_valid
    assert [
        (request.screenos_name, request.vlan_mode, request.vlan_id)
        for request in workspace.requests
    ] == [
        ("ethernet0/0", "access", None),
        ("ethernet0/1.100", "tagged", 100),
    ]


def test_every_invalid_row_is_reported_at_the_field_that_caused_it() -> None:
    expected = [
        line.split("|", 2)
        for line in (FIXTURE_ROOT / "negative" / "mapping_workspace.errors")
        .read_text(encoding="utf-8")
        .splitlines()
    ]

    workspace = parse_mapping_form(
        inventory_for("mapping_workspace", "negative"),
        form_for("mapping_workspace", "negative"),
    )

    actual = [
        [str(row.index), field, message]
        for row in workspace.rows
        for field, message in sorted(row.errors.items())
    ]

    assert actual == expected
    assert not workspace.is_valid
    assert workspace.invalid_count == 3
    # A rejected row claims no destination, so the first valid row keeps its own.
    assert workspace.rows[0].status == "mapped"
    assert workspace.requests == ()


def test_a_mapping_for_an_undefined_interface_is_shown_not_dropped() -> None:
    workspace = build_workspace(
        inventory_for("mapping_workspace"),
        selections={
            "ethernet0/7": MappingSelection(
                screenos_name="ethernet0/7",
                physical_name="ge-0/0/7",
            )
        },
        submitted=True,
    )

    stale = workspace.rows[-1]

    assert stale.screenos_name == "ethernet0/7"
    assert stale.current_target == "not discovered"
    assert "not defined in the submitted configuration" in stale.errors["destination"]
    assert not workspace.is_valid


@pytest.mark.parametrize(
    ("selection", "field", "message"),
    [
        (
            MappingSelection("ethernet0/0", physical_name="ge-0/0/2", unit="seven"),
            "unit",
            "Unit must be a whole number between 0 and 16385.",
        ),
        (
            MappingSelection(
                "ethernet0/0",
                physical_name="ge-0/0/2",
                unit="3",
                vlan_choice="tagged",
                vlan_id="",
            ),
            "vlan_id",
            "Enter the VLAN ID to tag this unit with, between 1 and 4094.",
        ),
        (
            MappingSelection(
                "ethernet0/0",
                physical_name="ge-0/0/2",
                unit="0",
                vlan_choice="tagged",
                vlan_id="4095",
            ),
            "vlan_id",
            "tagged VLAN ID must be between 1 and 4094",
        ),
        (
            MappingSelection("ethernet0/0", physical_name="switch0"),
            "destination",
            'unsupported Junos interface name: "switch0"',
        ),
    ],
)
def test_field_level_errors_name_the_control_to_correct(
    selection: MappingSelection,
    field: str,
    message: str,
) -> None:
    workspace = build_workspace(
        inventory_for("mapping_workspace"),
        selections={selection.screenos_name: selection},
        submitted=True,
    )

    assert message in workspace.rows[0].errors[field]
    assert workspace.rows[0].status == "invalid"


def test_tampered_vlan_treatment_falls_back_to_preserving_the_source() -> None:
    selections, overflowed = read_selections(
        {
            "mapping-source-0": "ethernet0/1.100",
            "mapping-destination-0": "ge-0/0/4",
            "mapping-unit-0": "12",
            "mapping-vlan-0": "trunk-native",
        }
    )

    assert overflowed is False
    assert selections["ethernet0/1.100"].vlan_choice == "preserve"


def test_submitted_rows_are_bounded() -> None:
    form = {"mapping-count": str(MAX_WORKSPACE_ROWS + 5)}
    for index in range(MAX_WORKSPACE_ROWS + 5):
        form[f"mapping-source-{index}"] = f"ethernet0/{index}"
        form[f"mapping-destination-{index}"] = "ge-0/0/1"

    selections, overflowed = read_selections(form)

    assert overflowed is True
    assert len(selections) == MAX_WORKSPACE_ROWS
    assert has_mapping_form(form) is True
    assert has_mapping_form(
        {"config_text": "set interface ethernet0/0 zone Trust"}
    ) is (False)


def test_rendered_rows_are_bounded_and_the_remainder_is_disclosed() -> None:
    source = "\n".join(
        f'set interface ethernet{slot}/{port} zone "Trust"'
        for slot in range(9)
        for port in range(50)
    )
    inventory = convert_configuration(source).interface_inventory

    workspace = build_workspace(inventory)

    assert len(inventory.interfaces) == 450
    assert workspace.total == MAX_WORKSPACE_ROWS
    assert any(
        "50 further interfaces are not shown" in note for note in workspace.notices
    )


def test_the_flow_graphic_tracks_the_server_side_stage() -> None:
    empty = conversion_flow()
    discovered = conversion_flow(
        workspace=build_workspace(inventory_for("mapping_workspace"))
    )
    invalid = conversion_flow(
        workspace=parse_mapping_form(
            inventory_for("mapping_workspace", "negative"),
            form_for("mapping_workspace", "negative"),
        )
    )
    finished = conversion_flow(
        workspace=build_workspace(inventory_for("mapping_workspace")),
        result=object(),
    )

    assert [step.status for step in empty] == [
        "active",
        "pending",
        "pending",
        "pending",
    ]
    assert [step.status for step in discovered] == ["done", "done", "active", "pending"]
    assert [step.status for step in invalid] == ["done", "done", "attention", "pending"]
    assert [step.status for step in finished] == ["done", "done", "done", "done"]
    assert discovered[1].detail == "3 interfaces, 6 bindings"
    assert invalid[2].detail == "3 mappings need correcting"
    # Status is never carried by colour alone.
    assert [step.status_label for step in invalid] == [
        "Done",
        "Done",
        "Needs attention",
        "Waiting",
    ]


def test_an_empty_inventory_still_produces_a_usable_workspace() -> None:
    inventory = convert_configuration(
        'set address "Trust" "SERVER" 192.0.2.10 255.255.255.255'
    ).interface_inventory

    workspace = build_workspace(inventory)
    flow = conversion_flow(workspace=workspace)

    assert workspace.is_empty
    assert workspace.is_valid
    assert workspace.requests == ()
    assert flow[1].detail == "No interfaces discovered"
    assert flow[2].detail == "Nothing to map"


def test_binding_detail_collapses_for_large_configurations() -> None:
    source = "\n".join(
        f'set interface ethernet0/{port} zone "Trust"'
        for port in range(DETAILED_ROW_LIMIT + 1)
    )
    inventory = convert_configuration(source).interface_inventory

    workspace = build_workspace(inventory)

    assert workspace.total == DETAILED_ROW_LIMIT + 1
    # The counted summary survives; only the per-row list of source lines goes.
    assert all(row.visible_bindings == () for row in workspace.rows)
    assert all(row.binding_chips for row in workspace.rows)
    assert any("Binding details are collapsed" in note for note in workspace.notices)
