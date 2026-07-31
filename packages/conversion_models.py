"""Normalized records shared by ScreenOS parsers and Junos renderers."""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Literal

InterfaceKind = Literal["ethernet", "management", "tunnel", "vlan"]
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
