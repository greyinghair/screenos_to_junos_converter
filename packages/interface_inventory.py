"""Interface binding inventory derived from one completed conversion run.

The inventory answers a single migration question: for each ScreenOS source
interface, what else in the submitted configuration depends on it? Every entry
is derived from a normalized model or a recorded diagnostic, so nothing here is
inferred from raw text a second time.
"""

from __future__ import annotations

import ipaddress
import re
from collections import defaultdict
from dataclasses import dataclass
from typing import TYPE_CHECKING, Any, Literal

from .conversion_models import InterfaceKind, InterfaceModel

if TYPE_CHECKING:  # pragma: no cover - import cycle guard for type checkers only
    from .converter_core import ConversionState

BindingCategory = Literal[
    "address",
    "policy",
    "route",
    "routing-instance",
    "source-nat",
    "static-nat",
    "unnumbered",
    "unsupported",
    "vpn",
    "zone",
]

_NUMERIC_RUN = re.compile(r"(\d+)")


@dataclass(frozen=True, slots=True)
class InterfaceBinding:
    """One configuration object that depends on a ScreenOS interface."""

    category: BindingCategory
    identifier: str
    summary: str
    line_number: int | None
    source_line: str

    def as_dict(self) -> dict[str, Any]:
        return {
            "category": self.category,
            "identifier": self.identifier,
            "summary": self.summary,
            "line_number": self.line_number,
            "source_line": self.source_line,
        }


@dataclass(frozen=True, slots=True)
class UnresolvedInterfaceReference:
    """A reference to an interface the configuration never defines."""

    screenos_name: str
    category: BindingCategory
    summary: str
    line_number: int | None
    source_line: str

    def as_dict(self) -> dict[str, Any]:
        return {
            "screenos_name": self.screenos_name,
            "category": self.category,
            "summary": self.summary,
            "line_number": self.line_number,
            "source_line": self.source_line,
        }


@dataclass(frozen=True, slots=True)
class InterfaceInventoryEntry:
    """Every migration-relevant fact known about one ScreenOS interface."""

    screenos_name: str
    kind: InterfaceKind
    junos_name: str
    physical_name: str
    unit: int
    vlan_id: int | None
    zone: str | None
    ipv4_addresses: tuple[str, ...]
    ipv6_addresses: tuple[str, ...]
    disabled: bool
    rendered: bool
    mapped: bool
    line_number: int
    bindings: tuple[InterfaceBinding, ...]
    binding_counts: tuple[tuple[BindingCategory, int], ...]

    @property
    def binding_total(self) -> int:
        return len(self.bindings)

    @property
    def has_bindings(self) -> bool:
        return bool(self.bindings)

    def as_dict(self) -> dict[str, Any]:
        return {
            "screenos_name": self.screenos_name,
            "kind": self.kind,
            "junos_name": self.junos_name,
            "physical_name": self.physical_name,
            "unit": self.unit,
            "vlan_id": self.vlan_id,
            "zone": self.zone,
            "ipv4_addresses": list(self.ipv4_addresses),
            "ipv6_addresses": list(self.ipv6_addresses),
            "disabled": self.disabled,
            "rendered": self.rendered,
            "mapped": self.mapped,
            "line_number": self.line_number,
            "binding_total": self.binding_total,
            "binding_counts": dict(self.binding_counts),
            "bindings": [binding.as_dict() for binding in self.bindings],
        }


@dataclass(frozen=True, slots=True)
class InterfaceInventory:
    """Deterministic inventory of interfaces and their discovered bindings."""

    interfaces: tuple[InterfaceInventoryEntry, ...]
    unresolved: tuple[UnresolvedInterfaceReference, ...]

    def entry(self, screenos_name: str) -> InterfaceInventoryEntry | None:
        for entry in self.interfaces:
            if entry.screenos_name == screenos_name:
                return entry
        return None

    def as_dict(self) -> dict[str, Any]:
        return {
            "interfaces": [entry.as_dict() for entry in self.interfaces],
            "unresolved": [reference.as_dict() for reference in self.unresolved],
        }


def _sort_key(name: str) -> tuple[object, ...]:
    """Order interface names so ethernet0/2 sorts before ethernet0/10."""

    return tuple(
        (1, int(part), "") if part.isdigit() else (0, 0, part)
        for part in _NUMERIC_RUN.split(name.lower())
        if part
    )


class _BindingCollector:
    """Accumulates bindings for defined interfaces and unresolved references."""

    def __init__(self, defined: dict[str, InterfaceModel]) -> None:
        self._defined = defined
        self.bindings: defaultdict[str, list[InterfaceBinding]] = defaultdict(list)
        self.unresolved: list[UnresolvedInterfaceReference] = []
        self._seen: set[tuple[str, BindingCategory, str]] = set()

    def add(
        self,
        screenos_name: str,
        category: BindingCategory,
        identifier: str,
        summary: str,
        line_number: int | None,
        source_line: str,
    ) -> None:
        key = (screenos_name, category, identifier)
        if key in self._seen:
            return
        self._seen.add(key)
        if screenos_name in self._defined:
            self.bindings[screenos_name].append(
                InterfaceBinding(
                    category=category,
                    identifier=identifier,
                    summary=summary,
                    line_number=line_number,
                    source_line=source_line,
                )
            )
            return
        self.unresolved.append(
            UnresolvedInterfaceReference(
                screenos_name=screenos_name,
                category=category,
                summary=summary,
                line_number=line_number,
                source_line=source_line,
            )
        )


def _collect_interface_attributes(
    collector: _BindingCollector,
    interfaces: dict[str, InterfaceModel],
) -> None:
    for name, model in interfaces.items():
        if model.zone is not None:
            line_number, source_line = model.attribute_sources.get(
                "zone",
                (model.line_number, model.source_line),
            )
            collector.add(
                name,
                "zone",
                model.zone,
                f"bound to security zone {model.zone}",
                line_number,
                source_line,
            )
        if model.unnumbered_from is None:
            continue
        collector.add(
            name,
            "unnumbered",
            model.unnumbered_from,
            f'borrows its IPv4 address from "{model.unnumbered_from}"',
            model.unnumbered_line_number,
            model.unnumbered_source_line or model.source_line,
        )
        collector.add(
            model.unnumbered_from,
            "unnumbered",
            name,
            f'lends its IPv4 address to "{name}"',
            model.unnumbered_line_number,
            model.unnumbered_source_line or model.source_line,
        )


def _collect_policy_bindings(
    collector: _BindingCollector,
    state: ConversionState,
) -> None:
    interfaces_by_zone: defaultdict[str, list[str]] = defaultdict(list)
    for name, model in state.interfaces.items():
        if model.zone is not None:
            interfaces_by_zone[model.zone].append(name)

    for policy in state.policies:
        # A global policy names no zone, so moving an interface cannot change
        # which traffic it matches. Only zone policies bind to an interface,
        # and they bind through the zone the interface is a member of.
        if policy.scope == "global":
            continue
        zones = [
            zone
            for zone in (policy.source_zone, policy.destination_zone)
            if zone is not None
        ]
        context = f"{policy.source_zone} to {policy.destination_zone}"
        state_note = " (disabled)" if policy.disabled else ""
        for zone in dict.fromkeys(zones):
            for name in interfaces_by_zone.get(zone, []):
                collector.add(
                    name,
                    "policy",
                    f"{policy.scope}:{policy.policy_id}",
                    f"zone policy {policy.policy_id} {context}{state_note}",
                    policy.line_number,
                    policy.source_line,
                )


def _collect_routing_bindings(
    collector: _BindingCollector,
    state: ConversionState,
) -> None:
    for route in state.static_routes:
        if route.interface is None or route.interface.lower() == "null":
            continue
        collector.add(
            route.interface,
            "route",
            route.destination,
            f"static route {route.destination} in {route.vrouter}",
            route.line_number,
            route.source_line,
        )
        if route.vrouter.lower() != "trust-vr":
            collector.add(
                route.interface,
                "routing-instance",
                route.vrouter,
                f"attached to virtual router {route.vrouter}",
                route.line_number,
                route.source_line,
            )


def _collect_nat_bindings(
    collector: _BindingCollector,
    state: ConversionState,
) -> None:
    for mip in state.mips:
        collector.add(
            mip.interface,
            "static-nat",
            mip.mapped_prefix,
            f"MIP {mip.mapped_prefix} to host {mip.host_prefix}",
            mip.line_number,
            mip.source_line,
        )
    for pool in state.dip_pools.values():
        collector.add(
            pool.interface,
            "source-nat",
            f"dip-{pool.pool_id}",
            (f"DIP pool {pool.pool_id} ({pool.start_address} to {pool.end_address})"),
            pool.line_number,
            pool.source_line,
        )

    policies = {(policy.scope, policy.policy_id): policy for policy in state.policies}
    for rule in state.source_nat_rules:
        policy = policies.get((rule.policy_scope, rule.policy_id))
        if rule.kind == "pool":
            pool = state.dip_pools.get(rule.dip_id) if rule.dip_id else None
            if pool is None:
                continue
            collector.add(
                pool.interface,
                "source-nat",
                f"policy:{rule.policy_id}",
                f"policy {rule.policy_id} translates through DIP {rule.dip_id}",
                rule.line_number,
                rule.source_line,
            )
            continue
        if policy is None or policy.destination_zone is None:
            continue
        for name, model in state.interfaces.items():
            if model.zone != policy.destination_zone:
                continue
            collector.add(
                name,
                "source-nat",
                f"policy:{rule.policy_id}",
                (
                    f"policy {rule.policy_id} translates to the egress interface "
                    f"of zone {policy.destination_zone}"
                ),
                rule.line_number,
                rule.source_line,
            )


def _collect_vpn_bindings(
    collector: _BindingCollector,
    state: ConversionState,
) -> None:
    for gateway in state.ike_gateways.values():
        collector.add(
            gateway.outgoing_interface,
            "vpn",
            gateway.name,
            f"IKE gateway {gateway.name} egress interface",
            gateway.line_number,
            gateway.source_line,
        )
    for vpn in state.ipsec_vpns.values():
        if vpn.bind_interface is None:
            continue
        collector.add(
            vpn.bind_interface,
            "vpn",
            vpn.name,
            f"route-based VPN {vpn.name} bind interface",
            vpn.line_number,
            vpn.source_line,
        )


def _collect_address_bindings(
    collector: _BindingCollector,
    state: ConversionState,
) -> None:
    networks_by_zone: defaultdict[str, list[tuple[str, ipaddress.IPv4Network]]] = (
        defaultdict(list)
    )
    for name, model in state.interfaces.items():
        if model.zone is None:
            continue
        for address in model.ipv4_addresses:
            network = ipaddress.ip_interface(address).network
            if isinstance(network, ipaddress.IPv4Network):
                networks_by_zone[model.zone.lower()].append((name, network))
    if not networks_by_zone:
        return

    for (zone, object_name), prefixes in state.address_prefixes_by_zone.items():
        candidates = networks_by_zone.get(zone)
        if not candidates:
            continue
        for prefix in prefixes:
            parsed = ipaddress.ip_network(prefix)
            if not isinstance(parsed, ipaddress.IPv4Network):
                continue
            for name, network in candidates:
                if not parsed.subnet_of(network):
                    continue
                line_number, source_line = state.address_sources.get(
                    (zone, object_name),
                    (None, f'set address "{zone}" "{object_name}"'),
                )
                collector.add(
                    name,
                    "address",
                    object_name,
                    (f'address object "{object_name}" ({prefix}) is inside {network}'),
                    line_number,
                    source_line,
                )


def _collect_diagnostic_bindings(
    collector: _BindingCollector,
    state: ConversionState,
) -> None:
    for diagnostic in state.diagnostics:
        tokens = diagnostic.line.split()
        if len(tokens) < 3 or tokens[0] != "set" or tokens[1] != "interface":
            continue
        collector.add(
            tokens[2],
            "unsupported",
            f"line-{diagnostic.line_number}",
            diagnostic.reason,
            diagnostic.line_number,
            diagnostic.line,
        )


def build_interface_inventory(state: ConversionState) -> InterfaceInventory:
    """Build the deterministic interface inventory for a completed conversion."""

    collector = _BindingCollector(state.interfaces)
    _collect_interface_attributes(collector, state.interfaces)
    _collect_policy_bindings(collector, state)
    _collect_routing_bindings(collector, state)
    _collect_nat_bindings(collector, state)
    _collect_vpn_bindings(collector, state)
    _collect_address_bindings(collector, state)
    _collect_diagnostic_bindings(collector, state)

    entries: list[InterfaceInventoryEntry] = []
    for name in sorted(state.interfaces, key=_sort_key):
        model = state.interfaces[name]
        bindings = tuple(
            sorted(
                collector.bindings.get(name, []),
                key=lambda binding: (
                    binding.category,
                    binding.line_number is None,
                    binding.line_number or 0,
                    binding.identifier,
                ),
            )
        )
        counts: defaultdict[str, int] = defaultdict(int)
        for binding in bindings:
            counts[binding.category] += 1
        entries.append(
            InterfaceInventoryEntry(
                screenos_name=name,
                kind=model.mapping.kind,
                junos_name=model.mapping.logical_name,
                physical_name=model.mapping.physical_name,
                unit=model.mapping.unit,
                vlan_id=model.effective_vlan_id,
                zone=model.zone,
                ipv4_addresses=tuple(model.ipv4_addresses),
                ipv6_addresses=tuple(model.ipv6_addresses),
                disabled=model.disabled,
                rendered=name in state.rendered_interfaces,
                mapped=model.applied_mapping is not None,
                line_number=model.line_number,
                bindings=bindings,
                binding_counts=tuple(
                    (category, counts[category])  # type: ignore[misc]
                    for category in sorted(counts)
                ),
            )
        )

    unresolved = tuple(
        sorted(
            collector.unresolved,
            key=lambda reference: (
                _sort_key(reference.screenos_name),
                reference.line_number is None,
                reference.line_number or 0,
                reference.category,
            ),
        )
    )
    return InterfaceInventory(interfaces=tuple(entries), unresolved=unresolved)
