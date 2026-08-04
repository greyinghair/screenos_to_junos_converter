"""Normalized records shared by ScreenOS parsers and Junos renderers."""

from __future__ import annotations

import re
from collections.abc import Iterable
from dataclasses import dataclass, field
from typing import Final, Literal

InterfaceKind = Literal["ethernet", "management", "tunnel", "vlan"]
VlanMode = Literal["access", "tagged"]
PolicyScope = Literal["zone", "global"]
PolicyPlacement = Literal["append", "top", "before"]
PolicyMatchKind = Literal["source-address", "destination-address", "application"]
BgpAddressFamily = Literal["inet", "inet6"]
SourceNatKind = Literal["pool", "interface"]
IkeEndpointKind = Literal["address", "dynamic"]
IkeExchangeMode = Literal["main", "aggressive"]
IdpAction = Literal[
    "close-client",
    "close-client-and-server",
    "close-server",
    "drop-connection",
]

_ETHERNET_INTERFACE = re.compile(
    r"^ethernet(?P<slot>\d+)/(?P<port>\d+)(?:\.(?P<unit>\d+))?$",
    re.IGNORECASE,
)
_TUNNEL_INTERFACE = re.compile(r"^tunnel\.(?P<unit>\d+)$", re.IGNORECASE)
_VLAN_INTERFACE = re.compile(r"^vlan\.?(?P<unit>\d+)$", re.IGNORECASE)

_JUNOS_ETHERNET_PORT = re.compile(r"^(?:ge|xe|et|fe|em|xle)-\d{1,3}/\d{1,3}/\d{1,3}$")
_JUNOS_ETHERNET_BUNDLE = re.compile(r"^(?:ae|reth)\d{1,4}$")
MAX_JUNOS_LOGICAL_UNIT: Final[int] = 16385
MAX_VLAN_ID: Final[int] = 4094


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


class InterfaceMappingError(ValueError):
    """Raised when a requested interface mapping cannot be applied safely."""


@dataclass(frozen=True, slots=True)
class InterfaceMappingRequest:
    """One operator-selected ScreenOS-to-Junos interface destination."""

    screenos_name: str
    physical_name: str
    unit: int = 0
    vlan_mode: VlanMode = "access"
    vlan_id: int | None = None


@dataclass(frozen=True, slots=True)
class ResolvedInterfaceMapping:
    """A validated mapping request that renderers may apply without rechecking."""

    screenos_name: str
    mapping: InterfaceMapping
    vlan_mode: VlanMode
    vlan_id: int | None

    @property
    def logical_name(self) -> str:
        return self.mapping.logical_name

    @property
    def summary(self) -> str:
        if self.vlan_mode == "tagged":
            return f"{self.logical_name} (tagged, vlan-id {self.vlan_id})"
        return f"{self.logical_name} (untagged)"


def junos_interface_kind(physical_name: str) -> InterfaceKind:
    """Classify a Junos physical interface name the converter can render."""

    if _JUNOS_ETHERNET_PORT.fullmatch(
        physical_name
    ) or _JUNOS_ETHERNET_BUNDLE.fullmatch(physical_name):
        return "ethernet"
    if physical_name == "fxp0":
        return "management"
    if physical_name == "st0":
        return "tunnel"
    if physical_name == "irb":
        return "vlan"
    raise InterfaceMappingError(
        f'unsupported Junos interface name: "{physical_name}"',
    )


def _validate_unit(request: InterfaceMappingRequest, kind: InterfaceKind) -> None:
    if not 0 <= request.unit <= MAX_JUNOS_LOGICAL_UNIT:
        raise InterfaceMappingError(
            f'"{request.screenos_name}" unit must be between 0 and '
            f"{MAX_JUNOS_LOGICAL_UNIT}",
        )
    if kind == "management" and request.unit != 0:
        raise InterfaceMappingError(
            f'"{request.screenos_name}" maps to fxp0, which only supports unit 0',
        )
    if kind == "ethernet" and request.vlan_mode == "access" and request.unit != 0:
        raise InterfaceMappingError(
            f'"{request.screenos_name}" is untagged, so it must use unit 0 on '
            f"{request.physical_name}",
        )


def _validate_vlan(request: InterfaceMappingRequest, kind: InterfaceKind) -> None:
    if request.vlan_mode not in ("access", "tagged"):
        raise InterfaceMappingError(
            f'"{request.screenos_name}" has an unsupported VLAN mode: '
            f'"{request.vlan_mode}"',
        )
    if request.vlan_mode == "access":
        if request.vlan_id is not None:
            raise InterfaceMappingError(
                f'"{request.screenos_name}" is untagged, so it must not carry a '
                "VLAN ID",
            )
        return
    if kind not in ("ethernet", "vlan"):
        raise InterfaceMappingError(
            f'"{request.screenos_name}" maps to {request.physical_name}, which '
            "does not accept a VLAN tag",
        )
    if request.vlan_id is None or not 1 <= request.vlan_id <= MAX_VLAN_ID:
        raise InterfaceMappingError(
            f'"{request.screenos_name}" tagged VLAN ID must be between 1 and '
            f"{MAX_VLAN_ID}",
        )
    if kind == "ethernet" and request.unit == 0:
        raise InterfaceMappingError(
            f'"{request.screenos_name}" tagged mappings require a logical unit '
            "other than 0",
        )


def resolve_interface_mappings(
    requests: Iterable[InterfaceMappingRequest],
) -> dict[str, ResolvedInterfaceMapping]:
    """Validate operator-selected mappings before any Junos output is rendered.

    The result is keyed by ScreenOS source name in sorted order so generated
    configuration and annotations stay deterministic regardless of the order in
    which a client submitted the mappings.
    """

    resolved: dict[str, ResolvedInterfaceMapping] = {}
    destinations: dict[tuple[str, int], str] = {}
    tagging_modes: dict[str, tuple[VlanMode, str]] = {}

    for request in requests:
        if request.screenos_name in resolved:
            raise InterfaceMappingError(
                f'duplicate mapping for ScreenOS interface "{request.screenos_name}"',
            )
        try:
            map_screenos_interface(request.screenos_name)
        except ValueError as exc:
            raise InterfaceMappingError(str(exc)) from exc

        kind = junos_interface_kind(request.physical_name)
        _validate_vlan(request, kind)
        _validate_unit(request, kind)

        destination = (request.physical_name, request.unit)
        owner = destinations.get(destination)
        if owner is not None:
            raise InterfaceMappingError(
                f'"{request.screenos_name}" and "{owner}" both map to '
                f"{request.physical_name}.{request.unit}",
            )
        destinations[destination] = request.screenos_name

        if kind == "ethernet":
            # Junos enables VLAN tagging on the physical interface, so every
            # logical unit carved out of it must agree on the mode.
            existing_mode = tagging_modes.get(request.physical_name)
            if existing_mode is not None and existing_mode[0] != request.vlan_mode:
                raise InterfaceMappingError(
                    f'"{request.screenos_name}" and "{existing_mode[1]}" mix tagged '
                    f"and untagged units on {request.physical_name}",
                )
            tagging_modes[request.physical_name] = (
                request.vlan_mode,
                request.screenos_name,
            )

        resolved[request.screenos_name] = ResolvedInterfaceMapping(
            screenos_name=request.screenos_name,
            mapping=InterfaceMapping(
                kind=kind,
                physical_name=request.physical_name,
                unit=request.unit,
            ),
            vlan_mode=request.vlan_mode,
            vlan_id=request.vlan_id,
        )

    return {name: resolved[name] for name in sorted(resolved)}


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
    applied_mapping: ResolvedInterfaceMapping | None = None
    # Attribute key ("zone", "tag", "ip:PREFIX", ...) to the source line that
    # last set it, so every inventory reference stays traceable.
    attribute_sources: dict[str, tuple[int, str]] = field(default_factory=dict)

    @property
    def effective_vlan_id(self) -> int | None:
        """The VLAN ID to render, preferring an approved interface mapping."""

        if self.applied_mapping is not None:
            return self.applied_mapping.vlan_id
        return self.vlan_id


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
    tunnel_vpn: str | None = None
    pair_policy_id: str | None = None
    idp_rules: list[IdpRuleModel] = field(default_factory=list)
    idp_invalid: bool = False

    @property
    def context(self) -> tuple[str, str, str]:
        if self.scope == "global":
            return ("global", "", "")
        return (
            "zone",
            self.source_zone or "",
            self.destination_zone or "",
        )


@dataclass(frozen=True, slots=True)
class StaticRouteModel:
    """One destination-based ScreenOS static route."""

    vrouter: str
    destination: str
    line_number: int
    source_line: str
    interface: str | None = None
    gateway: str | None = None
    preference: int | None = None
    metric: int | None = None
    tag: int | None = None
    description: str | None = None
    permanent: bool = False


@dataclass(slots=True)
class BgpOptions:
    """Settings shared by ScreenOS BGP peer groups and individual peers."""

    remote_as: int | None = None
    hold_time: int | None = None
    keepalive: int | None = None
    import_policy: str | None = None
    export_policy: str | None = None
    source_interface: str | None = None
    local_address: str | None = None
    option_sources: dict[str, tuple[int, str]] = field(default_factory=dict)


@dataclass(slots=True)
class BgpPeerGroupModel:
    """A named ScreenOS BGP peer group."""

    name: str
    line_number: int
    source_line: str
    options: BgpOptions = field(default_factory=BgpOptions)


@dataclass(slots=True)
class BgpPeerModel:
    """One ScreenOS BGP neighbor."""

    address: str
    family: BgpAddressFamily
    line_number: int
    source_line: str
    peer_group: str | None = None
    enabled: bool = False
    options: BgpOptions = field(default_factory=BgpOptions)


@dataclass(slots=True)
class BgpInstanceModel:
    """BGP configuration collected for one ScreenOS virtual router."""

    vrouter: str
    line_number: int
    source_line: str
    local_as: int | None = None
    router_id: str | None = None
    enabled: bool = False
    peer_groups: dict[str, BgpPeerGroupModel] = field(default_factory=dict)
    peers: dict[str, BgpPeerModel] = field(default_factory=dict)


@dataclass(frozen=True, slots=True)
class MipModel:
    """A ScreenOS mapped-IP definition normalized as a static NAT mapping."""

    interface: str
    mapped_prefix: str
    host_prefix: str
    vrouter: str
    line_number: int
    source_line: str


@dataclass(frozen=True, slots=True)
class DipPoolModel:
    """A ScreenOS dynamic-IP pool normalized for Junos source NAT."""

    interface: str
    pool_id: int
    start_address: str
    end_address: str
    fixed_port: bool
    line_number: int
    source_line: str


@dataclass(frozen=True, slots=True)
class SourceNatRuleModel:
    """NAT-src semantics attached to a normalized firewall policy."""

    policy_scope: PolicyScope
    policy_id: str
    kind: SourceNatKind
    dip_id: int | None
    line_number: int
    source_line: str


@dataclass(frozen=True, slots=True)
class IkeProposalModel:
    """One ScreenOS Phase 1 proposal mapped to Junos IKE algorithms."""

    name: str
    authentication_method: str
    dh_group: str
    authentication_algorithm: str
    encryption_algorithm: str
    lifetime_seconds: int
    line_number: int
    source_line: str


@dataclass(slots=True)
class IkeGatewayModel:
    """A ScreenOS IKE peer and the Phase 1 policy it references."""

    name: str
    endpoint_kind: IkeEndpointKind
    endpoint: str
    exchange_mode: IkeExchangeMode
    outgoing_interface: str
    proposal_name: str
    line_number: int
    source_line: str
    local_id: str | None = None
    preshared_key_omitted: bool = False
    nat_traversal: bool = False


@dataclass(frozen=True, slots=True)
class IpsecProposalModel:
    """One ScreenOS Phase 2 proposal mapped to Junos IPsec algorithms."""

    name: str
    protocol: Literal["esp"]
    authentication_algorithm: str
    encryption_algorithm: str
    lifetime_seconds: int
    pfs_group: str | None
    line_number: int
    source_line: str


@dataclass(slots=True)
class IpsecVpnModel:
    """Linked ScreenOS VPN definition for route- or policy-based rendering."""

    name: str
    gateway_name: str
    proposal_name: str
    line_number: int
    source_line: str
    anti_replay: bool = True
    bind_interface: str | None = None
    proxy_local: str | None = None
    proxy_remote: str | None = None
    proxy_service: str | None = None


@dataclass(frozen=True, slots=True)
class IdpRuleModel:
    """A ScreenOS Deep Inspection attachment normalized for a Junos IDP rule."""

    attack_group: str
    dynamic_group_name: str
    service: str
    severity: str
    attack_type: Literal["anomaly", "signature"]
    action: IdpAction
    log_attacks: bool
    line_number: int
    source_line: str
