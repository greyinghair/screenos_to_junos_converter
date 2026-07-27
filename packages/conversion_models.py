"""Normalized records shared by ScreenOS parsers and Junos renderers."""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Literal

InterfaceKind = Literal["ethernet", "management", "tunnel", "vlan"]
PolicyScope = Literal["zone", "global"]
PolicyPlacement = Literal["append", "top", "before"]
PolicyMatchKind = Literal["source-address", "destination-address", "application"]

_ETHERNET_INTERFACE = re.compile(
    r"^ethernet(?P<slot>\d+)/(?P<port>\d+)(?:\.(?P<unit>\d+))?$",
    re.IGNORECASE,
)
_TUNNEL_INTERFACE = re.compile(r"^tunnel\.(?P<unit>\d+)$", re.IGNORECASE)
_VLAN_INTERFACE = re.compile(r"^vlan\.?(?P<unit>\d+)$", re.IGNORECASE)


@dataclass(frozen=True, slots=True)
class InterfaceMapping:
    """Deterministic ScreenOS-to-Junos interface-name mapping."""

    kind: InterfaceKind
    physical_name: str
    unit: int

    @property
    def logical_name(self) -> str:
        return f"{self.physical_name}.{self.unit}"


def map_screenos_interface(name: str) -> InterfaceMapping:
    """Map the supported, platform-neutral ScreenOS interface name forms."""

    ethernet = _ETHERNET_INTERFACE.fullmatch(name)
    if ethernet is not None:
        unit = int(ethernet["unit"] or 0)
        return InterfaceMapping(
            kind="ethernet",
            physical_name=f"ge-{ethernet['slot']}/0/{ethernet['port']}",
            unit=unit,
        )

    if name.lower() == "mgt":
        return InterfaceMapping(kind="management", physical_name="fxp0", unit=0)

    tunnel = _TUNNEL_INTERFACE.fullmatch(name)
    if tunnel is not None:
        return InterfaceMapping(
            kind="tunnel",
            physical_name="st0",
            unit=int(tunnel["unit"]),
        )

    vlan = _VLAN_INTERFACE.fullmatch(name)
    if vlan is not None:
        return InterfaceMapping(
            kind="vlan",
            physical_name="irb",
            unit=int(vlan["unit"]),
        )

    raise ValueError(f'unsupported ScreenOS interface type: "{name}"')


@dataclass(slots=True)
class InterfaceModel:
    """ScreenOS interface properties collected before Junos rendering."""

    screenos_name: str
    mapping: InterfaceMapping
    line_number: int
    source_line: str
    zone: str | None = None
    description: str | None = None
    mtu: int | None = None
    vlan_id: int | None = None
    ipv4_addresses: list[str] = field(default_factory=list)
    ipv6_addresses: list[str] = field(default_factory=list)
    unnumbered_from: str | None = None
    unnumbered_line_number: int | None = None
    unnumbered_source_line: str | None = None
    disabled: bool = False
    configured: bool = False


@dataclass(frozen=True, slots=True)
class PolicyReference:
    """One policy match reference and the source line that introduced it."""

    name: str
    line_number: int
    source_line: str


@dataclass(slots=True)
class PolicyModel:
    """Normalized representation used for both zone and global policies."""

    scope: PolicyScope
    policy_id: str
    policy_name: str
    line_number: int
    source_line: str
    source_zone: str | None
    destination_zone: str | None
    source_addresses: list[PolicyReference]
    destination_addresses: list[PolicyReference]
    services: list[PolicyReference]
    action: Literal["permit", "deny", "reject"]
    continuations: list[tuple[PolicyMatchKind, PolicyReference]] = field(
        default_factory=list
    )
    placement: PolicyPlacement = "append"
    before_policy_id: str | None = None
    log: bool = False
    count: bool = False
    disabled: bool = False

    @property
    def context(self) -> tuple[str, str, str]:
        if self.scope == "global":
            return ("global", "", "")
        return (
            "zone",
            self.source_zone or "",
            self.destination_zone or "",
        )
