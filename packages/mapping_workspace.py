"""Interface-mapping workspace state shared by the web form and its template.

The workspace is the review step between a discovered ScreenOS configuration
and a converted Junos one: one row per discovered source interface, the
destination an operator selected for it, and the inline errors that block
conversion. It holds no configuration of its own and persists nothing. Every
row is built from a finished `InterfaceInventory` plus the submitted form, and
every mapping rule comes from `review_interface_mappings`, so the browser form
and the CLI mapping file are validated by exactly the same code.
"""

from __future__ import annotations

from collections.abc import Iterable, Mapping
from dataclasses import dataclass
from dataclasses import field as dataclass_field
from typing import Literal

from .conversion_models import (
    MAX_JUNOS_LOGICAL_UNIT,
    MAX_VLAN_ID,
    InterfaceMappingField,
    InterfaceMappingRequest,
    VlanMode,
    review_interface_mappings,
)
from .interface_inventory import (
    BindingCategory,
    InterfaceBinding,
    InterfaceInventory,
    InterfaceInventoryEntry,
    UnresolvedInterfaceReference,
)

VlanChoice = Literal["preserve", "untagged", "tagged"]
FormField = Literal["source", "destination", "unit", "vlan", "vlan_id"]
FlowStatus = Literal["done", "active", "attention", "pending"]

VLAN_CHOICES: tuple[tuple[VlanChoice, str], ...] = (
    ("preserve", "Preserve source tag"),
    ("untagged", "No VLAN tag"),
    ("tagged", "Tagged VLAN"),
)
VALID_VLAN_CHOICES = frozenset(choice for choice, _label in VLAN_CHOICES)

# One row per discovered interface is rendered up to this bound. A larger
# configuration keeps its remaining interfaces on the default mapping and says
# so, which keeps the page, the submitted form, and the DOM bounded.
MAX_WORKSPACE_ROWS = 400
# Binding detail is summarized per row; the full list stays available through
# the CLI `--interface-inventory` export.
MAX_ROW_BINDINGS = 6
# Above this many rows the per-row binding lists collapse to their counted
# summary, so a large configuration cannot grow the page without bound.
DETAILED_ROW_LIMIT = 60
MAX_FIELD_LENGTH = 64

FORM_PREFIX = "mapping"
COUNT_FIELD = f"{FORM_PREFIX}-count"

# Destinations offered as type-ahead suggestions. The field accepts any name
# `junos_interface_kind` recognizes; this list only saves typing.
SUGGESTED_PHYSICAL_INTERFACES: tuple[str, ...] = (
    "ge-0/0/0",
    "ge-0/0/1",
    "ge-0/0/2",
    "ge-0/0/3",
    "ge-0/0/4",
    "ge-0/0/5",
    "ge-0/0/6",
    "ge-0/0/7",
    "xe-0/0/0",
    "xe-0/0/1",
    "ae0",
    "ae1",
    "reth0",
    "reth1",
    "fxp0",
    "st0",
    "irb",
)

BINDING_ICONS: dict[BindingCategory, str] = {
    "address": "address",
    "policy": "policy",
    "route": "route",
    "routing-instance": "route",
    "source-nat": "nat",
    "static-nat": "nat",
    "unnumbered": "interface",
    "unsupported": "warning",
    "vpn": "vpn",
    "zone": "zone",
}
BINDING_LABELS: dict[BindingCategory, tuple[str, str]] = {
    "address": ("address object", "address objects"),
    "policy": ("policy", "policies"),
    "route": ("route", "routes"),
    "routing-instance": ("routing instance", "routing instances"),
    "source-nat": ("source NAT rule", "source NAT rules"),
    "static-nat": ("static NAT rule", "static NAT rules"),
    "unnumbered": ("unnumbered link", "unnumbered links"),
    "unsupported": ("unsupported attribute", "unsupported attributes"),
    "vpn": ("VPN binding", "VPN bindings"),
    "zone": ("zone", "zones"),
}
# Model-level fields map onto the control an operator has to correct.
FIELD_FOR_ISSUE: dict[InterfaceMappingField, FormField] = {
    "screenos_name": "destination",
    "physical_name": "destination",
    "unit": "unit",
    "vlan_mode": "vlan",
    "vlan_id": "vlan_id",
}


def form_field(kind: FormField, index: int) -> str:
    """The form name and element id of one control in row `index`."""

    return f"{FORM_PREFIX}-{kind}-{index}"


def _binding_noun(category: BindingCategory, count: int) -> str:
    singular, plural = BINDING_LABELS.get(category, (category, category))
    return singular if count == 1 else plural


@dataclass(frozen=True, slots=True)
class MappingSelection:
    """One operator selection, kept exactly as submitted so it can be echoed."""

    screenos_name: str
    physical_name: str = ""
    unit: str = ""
    vlan_choice: VlanChoice = "preserve"
    vlan_id: str = ""

    @property
    def is_mapped(self) -> bool:
        return bool(self.physical_name)


@dataclass(frozen=True, slots=True)
class MappingRow:
    """One discovered interface, its selected destination, and its errors."""

    index: int
    screenos_name: str
    selection: MappingSelection
    entry: InterfaceInventoryEntry | None = None
    errors: dict[FormField, str] = dataclass_field(default_factory=dict)
    detailed: bool = True

    @property
    def has_errors(self) -> bool:
        return bool(self.errors)

    @property
    def status(self) -> Literal["invalid", "mapped", "default"]:
        if self.errors:
            return "invalid"
        return "mapped" if self.selection.is_mapped else "default"

    @property
    def status_label(self) -> str:
        return {
            "invalid": "Needs attention",
            "mapped": "Mapped",
            "default": "Default mapping",
        }[self.status]

    @property
    def error_messages(self) -> tuple[str, ...]:
        return tuple(self.errors[name] for name in sorted(self.errors))

    @property
    def current_target(self) -> str:
        return self.entry.junos_name if self.entry is not None else "not discovered"

    @property
    def zone(self) -> str:
        if self.entry is None or self.entry.zone is None:
            return "unbound"
        return self.entry.zone

    @property
    def source_vlan_id(self) -> int | None:
        return self.entry.vlan_id if self.entry is not None else None

    @property
    def addresses(self) -> tuple[str, ...]:
        if self.entry is None:
            return ()
        return self.entry.ipv4_addresses + self.entry.ipv6_addresses

    @property
    def binding_total(self) -> int:
        return self.entry.binding_total if self.entry is not None else 0

    @property
    def binding_chips(self) -> tuple[tuple[str, int, str, str], ...]:
        """(category, count, icon, accessible label) for the row summary."""

        if self.entry is None:
            return ()
        return tuple(
            (
                category,
                count,
                BINDING_ICONS.get(category, "interface"),
                f"{count} {_binding_noun(category, count)}",
            )
            for category, count in self.entry.binding_counts
        )

    @property
    def visible_bindings(self) -> tuple[InterfaceBinding, ...]:
        if self.entry is None or not self.detailed:
            return ()
        return self.entry.bindings[:MAX_ROW_BINDINGS]

    @property
    def hidden_binding_count(self) -> int:
        return max(0, self.binding_total - len(self.visible_bindings))

    def field(self, kind: FormField) -> str:
        return form_field(kind, self.index)


@dataclass(frozen=True, slots=True)
class MappingWorkspace:
    """Every mapping row plus the requests a valid workspace would convert."""

    rows: tuple[MappingRow, ...] = ()
    requests: tuple[InterfaceMappingRequest, ...] = ()
    unresolved: tuple[UnresolvedInterfaceReference, ...] = ()
    suggestions: tuple[str, ...] = ()
    notices: tuple[str, ...] = ()
    submitted: bool = False

    @property
    def total(self) -> int:
        return len(self.rows)

    @property
    def is_empty(self) -> bool:
        return not self.rows

    @property
    def mapped_count(self) -> int:
        return sum(1 for row in self.rows if row.selection.is_mapped)

    @property
    def invalid_count(self) -> int:
        return sum(1 for row in self.rows if row.has_errors)

    @property
    def binding_total(self) -> int:
        return sum(row.binding_total for row in self.rows)

    @property
    def is_valid(self) -> bool:
        return self.invalid_count == 0

    @property
    def error_messages(self) -> tuple[str, ...]:
        return tuple(message for row in self.rows for message in row.error_messages)

    @property
    def selections(self) -> dict[str, MappingSelection]:
        """The submitted choices, so a later pass can rebuild the same rows."""

        return {row.screenos_name: row.selection for row in self.rows}


def default_selection(entry: InterfaceInventoryEntry) -> MappingSelection:
    """Start every row unmapped so an untouched workspace converts as before."""

    return MappingSelection(
        screenos_name=entry.screenos_name,
        physical_name="",
        unit=str(entry.unit),
        vlan_choice="preserve",
        vlan_id="" if entry.vlan_id is None else str(entry.vlan_id),
    )


def _clean(value: str | None) -> str:
    return (value or "").strip()[:MAX_FIELD_LENGTH]


def _vlan_choice(value: str | None) -> VlanChoice:
    candidate = _clean(value)
    if candidate in VALID_VLAN_CHOICES:
        return candidate  # type: ignore[return-value]
    return "preserve"


def read_selections(
    form: Mapping[str, str],
) -> tuple[dict[str, MappingSelection], bool]:
    """Read submitted rows. Returns the selections and whether rows were dropped."""

    selections: dict[str, MappingSelection] = {}
    index = 0
    while True:
        raw_name = form.get(form_field("source", index))
        if raw_name is None:
            return selections, False
        if index >= MAX_WORKSPACE_ROWS:
            return selections, True
        name = _clean(raw_name)
        if name:
            selections[name] = MappingSelection(
                screenos_name=name,
                physical_name=_clean(form.get(form_field("destination", index))),
                unit=_clean(form.get(form_field("unit", index))),
                vlan_choice=_vlan_choice(form.get(form_field("vlan", index))),
                vlan_id=_clean(form.get(form_field("vlan_id", index))),
            )
        index += 1


def _whole_number(raw: str) -> int | None:
    return int(raw) if raw.isdigit() and len(raw) <= 8 else None


def _requested_vlan(
    selection: MappingSelection,
    entry: InterfaceInventoryEntry | None,
) -> tuple[VlanMode, int | None, dict[FormField, str]]:
    """Resolve the selected VLAN treatment into a validated mode and tag."""

    if selection.vlan_choice == "untagged":
        return "access", None, {}
    if selection.vlan_choice == "tagged":
        vlan_id = _whole_number(selection.vlan_id)
        if vlan_id is None:
            return (
                "tagged",
                None,
                {
                    "vlan_id": (
                        "Enter the VLAN ID to tag this unit with, between 1 and "
                        f"{MAX_VLAN_ID}."
                    )
                },
            )
        return "tagged", vlan_id, {}
    # "preserve" derives the treatment from the discovered source interface,
    # which is the only place a safe answer exists.
    source_vlan_id = entry.vlan_id if entry is not None else None
    if source_vlan_id is None:
        return "access", None, {}
    return "tagged", source_vlan_id, {}


def _row_request(
    selection: MappingSelection,
    entry: InterfaceInventoryEntry | None,
) -> tuple[InterfaceMappingRequest | None, dict[FormField, str]]:
    if not selection.is_mapped:
        return None, {}
    if entry is None:
        return None, {
            "destination": (
                f'"{selection.screenos_name}" is not defined in the submitted '
                "configuration; clear this destination to continue."
            )
        }

    errors: dict[FormField, str] = {}
    unit = _whole_number(selection.unit) if selection.unit else 0
    if unit is None:
        errors["unit"] = (
            f"Unit must be a whole number between 0 and {MAX_JUNOS_LOGICAL_UNIT}."
        )
    vlan_mode, vlan_id, vlan_errors = _requested_vlan(selection, entry)
    errors.update(vlan_errors)
    if errors or unit is None:
        return None, errors

    return (
        InterfaceMappingRequest(
            screenos_name=selection.screenos_name,
            physical_name=selection.physical_name,
            unit=unit,
            vlan_mode=vlan_mode,
            vlan_id=vlan_id,
        ),
        {},
    )


def _suggestions(entries: Iterable[InterfaceInventoryEntry]) -> tuple[str, ...]:
    discovered = {entry.physical_name for entry in entries}
    return tuple(sorted(discovered | set(SUGGESTED_PHYSICAL_INTERFACES)))


def build_workspace(
    inventory: InterfaceInventory,
    *,
    selections: Mapping[str, MappingSelection] | None = None,
    submitted: bool = False,
    notices: Iterable[str] = (),
) -> MappingWorkspace:
    """Build the reviewable workspace for one discovered configuration."""

    chosen = dict(selections or {})
    entries = inventory.interfaces[:MAX_WORKSPACE_ROWS]
    dropped = len(inventory.interfaces) - len(entries)
    known = {entry.screenos_name for entry in entries}

    # A destination selected for an interface the current configuration does not
    # define stays visible with its own error instead of being dropped silently.
    stale = [
        name
        for name, selection in chosen.items()
        if name not in known and selection.is_mapped
    ]
    planned: list[tuple[str, InterfaceInventoryEntry | None]] = [
        *((entry.screenos_name, entry) for entry in entries),
        *((name, None) for name in stale),
    ]

    selected: list[MappingSelection] = []
    row_errors: list[dict[FormField, str]] = []
    requests: list[InterfaceMappingRequest] = []
    row_for_request: list[int] = []
    for index, (screenos_name, entry) in enumerate(planned):
        selection = chosen.get(screenos_name)
        if selection is None:
            selection = (
                default_selection(entry)
                if entry is not None
                else MappingSelection(screenos_name=screenos_name)
            )
        request, errors = _row_request(selection, entry)
        if request is not None:
            requests.append(request)
            row_for_request.append(index)
        selected.append(selection)
        row_errors.append(errors)

    review = review_interface_mappings(requests)
    for issue in review.issues:
        row_errors[row_for_request[issue.index]].setdefault(
            FIELD_FOR_ISSUE[issue.field],
            issue.message,
        )

    detailed = len(planned) <= DETAILED_ROW_LIMIT
    rows = tuple(
        MappingRow(
            index=index,
            screenos_name=screenos_name,
            selection=selected[index],
            entry=entry,
            errors=row_errors[index],
            detailed=detailed,
        )
        for index, (screenos_name, entry) in enumerate(planned)
    )

    messages = list(notices)
    if not detailed:
        messages.append(
            "Binding details are collapsed to their counts because this "
            f"configuration defines more than {DETAILED_ROW_LIMIT} interfaces. "
            "Every binding stays available in the inventory below the converted "
            "output and in the command line --interface-inventory export."
        )
    if dropped > 0:
        messages.append(
            f"{dropped} further interfaces are not shown. This workspace maps the "
            f"first {MAX_WORKSPACE_ROWS} discovered interfaces; the rest keep their "
            "default mapping. Use the command line --interface-map for the full set."
        )

    return MappingWorkspace(
        rows=rows,
        requests=tuple(requests) if all(not errors for errors in row_errors) else (),
        unresolved=inventory.unresolved,
        suggestions=_suggestions(entries),
        notices=tuple(messages),
        submitted=submitted,
    )


def parse_mapping_form(
    inventory: InterfaceInventory,
    form: Mapping[str, str],
) -> MappingWorkspace:
    """Build the workspace from untrusted submitted form data."""

    selections, overflowed = read_selections(form)
    notices: list[str] = []
    if overflowed:
        notices.append(
            f"Only the first {MAX_WORKSPACE_ROWS} submitted mappings were read; "
            "the remaining rows keep their default mapping."
        )
    return build_workspace(
        inventory,
        selections=selections,
        submitted=True,
        notices=notices,
    )


def has_mapping_form(form: Mapping[str, str]) -> bool:
    """Whether this submission carried the mapping workspace."""

    return COUNT_FIELD in form


@dataclass(frozen=True, slots=True)
class FlowStep:
    """One stage of the conversion flow graphic, with its text equivalent."""

    key: str
    label: str
    icon: str
    detail: str
    status: FlowStatus

    @property
    def status_label(self) -> str:
        return {
            "done": "Done",
            "active": "In progress",
            "attention": "Needs attention",
            "pending": "Waiting",
        }[self.status]


def conversion_flow(
    *,
    workspace: MappingWorkspace | None = None,
    result: object | None = None,
    error: str | None = None,
) -> tuple[FlowStep, ...]:
    """Describe the four conversion stages for the flow graphic.

    The state is computed here, not in the browser, so the graphic is accurate
    with JavaScript disabled and can be asserted in a template test.
    """

    discovered = workspace is not None
    converted = result is not None

    if error is not None and not discovered and not converted:
        input_status: FlowStatus = "attention"
        input_detail = "Check the submitted configuration"
    elif discovered or converted:
        input_status, input_detail = "done", "Configuration received"
    else:
        input_status, input_detail = "active", "Paste or upload a configuration"

    if workspace is None:
        discovery_status: FlowStatus = "pending"
        discovery_detail = "Interfaces are listed after the configuration is read"
    elif workspace.is_empty:
        discovery_status, discovery_detail = "done", "No interfaces discovered"
    else:
        discovery_status = "done"
        discovery_detail = (
            f"{workspace.total} interfaces, {workspace.binding_total} bindings"
        )

    if workspace is None:
        mapping_status: FlowStatus = "pending"
        mapping_detail = "Choose Junos destinations after discovery"
    elif not workspace.is_valid:
        mapping_status = "attention"
        mapping_detail = f"{workspace.invalid_count} mappings need correcting"
    elif workspace.is_empty:
        mapping_status = "done"
        mapping_detail = "Nothing to map"
    elif converted:
        mapping_status = "done"
        mapping_detail = f"{workspace.mapped_count} of {workspace.total} remapped"
    else:
        mapping_status = "active"
        mapping_detail = f"{workspace.mapped_count} of {workspace.total} remapped"

    if converted:
        output_status: FlowStatus = "done"
        output_detail = "Junos configuration ready"
    elif error is not None:
        output_status, output_detail = "attention", "No configuration generated"
    else:
        output_status, output_detail = "pending", "Generated after conversion"

    return (
        FlowStep(
            key="input",
            label="ScreenOS input",
            icon="upload",
            detail=input_detail,
            status=input_status,
        ),
        FlowStep(
            key="discovery",
            label="Interfaces discovered",
            icon="search",
            detail=discovery_detail,
            status=discovery_status,
        ),
        FlowStep(
            key="mapping",
            label="Mapping approved",
            icon="mapping",
            detail=mapping_detail,
            status=mapping_status,
        ),
        FlowStep(
            key="output",
            label="Junos SRX output",
            icon="output",
            detail=output_detail,
            status=output_status,
        ),
    )
