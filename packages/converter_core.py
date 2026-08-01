"""Core conversion engine for ScreenOS to Junos transformation."""

from __future__ import annotations

import ipaddress
import logging
import re
import shlex
from collections import Counter
from collections.abc import Iterable
from dataclasses import dataclass, field
from pathlib import Path
from typing import Final

from .conversion_models import (
    BgpInstanceModel,
    BgpOptions,
    BgpPeerGroupModel,
    BgpPeerModel,
    DipPoolModel,
    IdpRuleModel,
    IkeGatewayModel,
    IkeProposalModel,
    InterfaceModel,
    IpsecProposalModel,
    IpsecVpnModel,
    MipModel,
    PolicyModel,
    PolicyReference,
    SourceNatRuleModel,
    StaticRouteModel,
    map_screenos_interface,
)
from .convert_service import convert_service_in_file, is_supported_service_definition
from .ipy import IP
from .sanity_check_naming import sanity_check_naming

LOGGER = logging.getLogger(__name__)

DEFAULT_APP_MAP: Final[dict[str, str]] = {
    "ANY": "any",
    "BGP": "junos-bgp",
    "CHARGEN": "junos-chargen",
    "DHCP-Relay": "junos-dhcp-relay",
    "DISCARD": "junos-discard",
    "DNS": "junos-dns",
    "ECHO": "junos-echo",
    "FINGER": "junos-finger",
    "FTP": "junos-ftp",
    "GRE": "junos-gre",
    "GTP": "junos-gtp",
    "H.323": "junos-h323",
    "HTTP": "junos-http",
    "HTTP-EXT": "junos-http-ext",
    "HTTPS": "junos-https",
    "ICMP-ANY": "junos-icmp-all",
    "IDENT": "junos-ident",
    "IKE": "junos-ike",
    "IKE-NAT": "junos-ike-nat",
    "IMAP": "junos-imap",
    "Internet Locator Service": "junos-internet-locator-service",
    "IRC": "junos-irc",
    "L2TP": "junos-l2tp",
    "LDAP": "junos-ldap",
    "LPR": "junos-lpr",
    "MAIL": "junos-mail",
    "MGCP-CA": "junos-mgcp-ca",
    "MGCP-UA": "junos-mgcp-ua",
    "MS-EXCHANGE-DIRECTORY": "junos-ms-rpc-msexchange",
    "MS-EXCHANGE-INFO-STORE": "junos-ms-rpc-msexchange",
    "MS-EXCHANGE-STORE": "junos-ms-rpc-msexchange",
    "MS-IIS-COM": "junos-ms-rpc-iis-com",
    "MS-RPC-ANY": "junos-ms-rpc-any",
    "MS-RPC-EPM": "junos-ms-rpc-epm",
    "MS-SQL": "junos-ms-sql",
    "MSN": "junos-msn",
    "NBDS": "junos-nbds",
    "NBNAME": "junos-nbname",
    "NFS": "junos-nfs",
    "NNTP": "junos-nntp",
    "NS Global": "junos-ns-global",
    "NS Global PRO": "junos-ns-global-pro",
    "NSM": "junos-nsm",
    "NTP": "junos-ntp",
    "OSPF": "junos-ospf",
    "PC-Anywhere": "junos-pc-anywhere",
    "PING": "junos-ping",
    "POP3": "junos-pop3",
    "PPTP": "junos-pptp",
    "RADIUS": "junos-radius",
    "Real Media": "junos-realaudio",
    "RIP": "junos-rip",
    "RSH": "junos-rsh",
    "RTSP": "junos-rstp",
    "SCCP": "junos-sccp",
    "SCTP-ANY": "junos-sctp-any",
    "SIP": "junos-sip",
    "SMB": "junos-smb",
    "SMTP": "junos-mail",
    "SNMP": "udp_161",
    "SQL Monitor": "junos-sql-monitor",
    "SQL*Net V1": "junos-sqlnet-v1",
    "SQL*Net V2": "junos-sqlnet-v2",
    "SSH": "junos-ssh",
    "SYSLOG": "junos-syslog",
    "TALK": "junos-talk",
    "TCP-ANY": "junos-tcp-any",
    "TELNET": "junos-telnet",
    "TFTP": "junos-tftp",
    "UDP-ANY": "junos-udp-any",
    "UUCP": "junos-uucp",
    "VDO Live": "junos-vdo-live",
    "VNC": "junos-vnc",
    "WAIS": "junos-wais",
    "WHOIS": "junos-whois",
    "WINFRAME": "junos-winframe",
    "X-WINDOWS": "junos-x-windows",
    "YMSG": "junos-ymsg",
}

DEFAULT_ADDRESS_MAP: Final[dict[str, str]] = {
    "Any": "any",
    "ANY": "any",
    "any": "any",
}
MISSING_CONFIG_LINES: Final[list[str]] = [
    "set applications application udp_161 protocol udp destination-port 161",
    "set applications application-set junos-dns application junos-dns-udp",
    "set applications application-set junos-dns application junos-dns-tcp",
]

RE_MULTI_DST: Final[re.Pattern[str]] = re.compile(r'^set dst-address\s+".+"$')
RE_MULTI_SRC: Final[re.Pattern[str]] = re.compile(r'^set src-address\s+".+"$')
RE_MULTI_SVC: Final[re.Pattern[str]] = re.compile(r'^set service\s+".+"$')
RE_GROUP_SERVICE: Final[re.Pattern[str]] = re.compile(
    r'^set group service\s+"[^"]+"\s+add\s+"[^"]+"\s*$',
)
RE_ADDRESS_LINE: Final[re.Pattern[str]] = re.compile(r"^set address")
RE_GROUP_ADDRESS: Final[re.Pattern[str]] = re.compile(
    r'^set group address\s+"[^"]+"\s+"[^"]+"\s+add\s+"[^"]+"\s*$',
)
RE_POLICY: Final[re.Pattern[str]] = re.compile(r"^set policy(?:\s|$)")
RE_INTERFACE: Final[re.Pattern[str]] = re.compile(r"^set interface(?:\s|$)")
RE_VROUTER: Final[re.Pattern[str]] = re.compile(r"^set vrouter(?:\s|$)")
RE_IKE: Final[re.Pattern[str]] = re.compile(r"^set ike(?:\s|$)")
RE_VPN: Final[re.Pattern[str]] = re.compile(r"^set vpn(?:\s|$)")
RE_ATTACK: Final[re.Pattern[str]] = re.compile(r"^set attack(?:\s|$)")
RE_BGP_AUTHENTICATION: Final[re.Pattern[str]] = re.compile(
    r"(\bmd5-authentication)(?:\s+.*)?$",
    re.IGNORECASE,
)
RE_ADDRESS: Final[re.Pattern[str]] = re.compile(
    r'^set address\s+"(?P<zone>[^"]+)"\s+"(?P<name>[^"]+)"\s+'
    r"(?P<value>\S+)(?:\s+(?P<mask>\d{1,3}(?:\.\d{1,3}){3}))?"
    r'(?:\s+"[^"]*")?\s*$',
)


@dataclass(frozen=True, slots=True)
class ConversionDiagnostic:
    """A source line that could not be represented in the generated config."""

    line_number: int | None
    line: str
    reason: str


@dataclass(slots=True)
class ConversionState:
    """Mutable conversion state held during a single conversion run."""

    succeeded: int = 0
    failed: int = 0

    default_app: dict[str, str] = field(default_factory=lambda: DEFAULT_APP_MAP.copy())
    default_addr: dict[str, str] = field(
        default_factory=lambda: DEFAULT_ADDRESS_MAP.copy()
    )

    service_ns_to_junos: dict[str, str] = field(default_factory=dict)
    service_grp_to_app_set: dict[str, str] = field(default_factory=dict)
    service_dicts: dict[str, str] = field(default_factory=dict)

    list_of_zones: list[str] = field(default_factory=list)
    addresses_ns_to_junos: dict[str, str] = field(default_factory=dict)
    address_name_owners: dict[tuple[str, str], str] = field(default_factory=dict)
    address_group_ns_to_junos_address_set: dict[str, str] = field(default_factory=dict)
    address_and_set_dicts: dict[str, str] = field(default_factory=dict)
    address_objects_by_zone: dict[tuple[str, str], str] = field(default_factory=dict)
    address_prefixes_by_zone: dict[tuple[str, str], list[str]] = field(
        default_factory=dict
    )
    non_ip_address_keys: set[tuple[str, str]] = field(default_factory=set)
    address_set_keys: set[tuple[str, str]] = field(default_factory=set)

    interfaces: dict[str, InterfaceModel] = field(default_factory=dict)
    interface_ns_to_junos: dict[str, str] = field(default_factory=dict)
    rendered_interfaces: set[str] = field(default_factory=set)
    policies: list[PolicyModel] = field(default_factory=list)
    current_policy: PolicyModel | None = None
    disabled_policy_keys: set[tuple[str, str]] = field(default_factory=set)
    disabled_policy_sources: dict[tuple[str, str], tuple[int, str]] = field(
        default_factory=dict
    )
    policy_moves: list[tuple[str, str, str, str, int, str]] = field(
        default_factory=list
    )
    reported_disabled_policy_keys: set[tuple[str, str]] = field(default_factory=set)

    static_routes: list[StaticRouteModel] = field(default_factory=list)
    bgp_instances: dict[str, BgpInstanceModel] = field(default_factory=dict)
    routing_instance_interfaces: dict[str, set[str]] = field(default_factory=dict)

    mips: list[MipModel] = field(default_factory=list)
    dip_pools: dict[int, DipPoolModel] = field(default_factory=dict)
    source_nat_rules: list[SourceNatRuleModel] = field(default_factory=list)

    ike_proposals: dict[str, IkeProposalModel] = field(default_factory=dict)
    ike_gateways: dict[str, IkeGatewayModel] = field(default_factory=dict)
    ipsec_proposals: dict[str, IpsecProposalModel] = field(default_factory=dict)
    ipsec_vpns: dict[str, IpsecVpnModel] = field(default_factory=dict)
    rendered_vpns: set[str] = field(default_factory=set)
    rendered_idp_policies: set[tuple[str, str]] = field(default_factory=set)
    manual_review_warnings: list[str] = field(default_factory=list)

    converted_config: list[str] = field(default_factory=list)
    diagnostics: list[ConversionDiagnostic] = field(default_factory=list)


class Converter:
    """Stateful converter for transforming ScreenOS lines into Junos lines."""

    def __init__(self, progress_interval: int = 100) -> None:
        self.state = ConversionState()
        self.progress_interval = max(progress_interval, 1)

    def combine_dicts(self, kind: str) -> None:
        if kind == "service":
            self.state.service_dicts = {
                **self.state.default_app,
                **self.state.service_ns_to_junos,
                **self.state.service_grp_to_app_set,
            }
        elif kind == "address":
            self.state.address_and_set_dicts = {
                **self.state.addresses_ns_to_junos,
                **self.state.address_group_ns_to_junos_address_set,
                **self.state.default_addr,
            }

    def convert_config(self, line: str) -> None:
        self.state.converted_config.append(line)
        self.state.succeeded += 1

    def record_failure(
        self,
        line: str,
        reason: str,
        line_number: int | None = None,
    ) -> None:
        self.state.failed += 1
        self.state.diagnostics.append(
            ConversionDiagnostic(
                line_number=line_number,
                line=line,
                reason=reason,
            ),
        )

    def converted_config_output(self, output_path: Path) -> None:
        output_path.parent.mkdir(parents=True, exist_ok=True)
        output_path.write_text(
            "\n".join(self.state.converted_config) + "\n",
            encoding="utf-8",
        )

    def read_file(self, input_path: Path) -> None:
        with input_path.open("r", encoding="utf-8", errors="replace") as input_file:
            self.read_lines(input_file)

    def read_text(self, source_text: str) -> None:
        """Convert an in-memory ScreenOS configuration without temporary files."""

        self.read_lines(source_text.splitlines())

    def read_lines(self, source_lines: Iterable[str]) -> None:
        """Convert one request-scoped iterable of ScreenOS configuration lines."""

        self.combine_dicts("service")
        self.combine_dicts("address")

        for line in MISSING_CONFIG_LINES:
            self.convert_config(line)

        for linecount, raw_line in enumerate(source_lines, start=1):
            line = raw_line.rstrip("\n")

            if linecount % self.progress_interval == 0:
                LOGGER.info("Parsing line %s", linecount)

            if RE_MULTI_DST.search(line):
                self.multi_line_rule(line, "destination-address", linecount)
            elif RE_MULTI_SRC.search(line):
                self.multi_line_rule(line, "source-address", linecount)
            elif RE_MULTI_SVC.search(line):
                self.multi_line_rule(line, "application", linecount)
            elif RE_ATTACK.search(line):
                self.parse_idp_continuation(line, linecount)
            elif RE_POLICY.search(line):
                self.parse_policy_line(line, linecount)
            else:
                self.state.current_policy = None
                if RE_INTERFACE.search(line):
                    self.parse_interface_line(line, linecount)
                elif RE_VROUTER.search(line):
                    self.parse_vrouter_line(line, linecount)
                elif RE_IKE.search(line):
                    self.parse_ike_line(line, linecount)
                elif RE_VPN.search(line):
                    self.parse_vpn_line(line, linecount)
                elif is_supported_service_definition(line):
                    self._parse_service_line(line, linecount)
                elif RE_GROUP_SERVICE.search(line):
                    self.create_app_set(line, linecount)
                elif RE_ADDRESS_LINE.search(line):
                    self.create_address_book(line, linecount)
                elif RE_GROUP_ADDRESS.search(line):
                    self.create_address_set(line, linecount)
                else:
                    self.record_failure(
                        line,
                        "unsupported or unrecognized syntax",
                        linecount,
                    )

        self.render_interfaces()
        self.render_vpns()
        self.render_routing()
        ordered_policies = self._ordered_policies()
        self.render_nat(ordered_policies)
        self.render_idp(ordered_policies)
        self.render_policies(ordered_policies)
        self.state.diagnostics.sort(
            key=lambda diagnostic: (
                diagnostic.line_number is None,
                diagnostic.line_number or 0,
            )
        )

    def _parse_service_line(self, line: str, line_number: int | None = None) -> None:
        try:
            junos_app_name, converted_line = convert_service_in_file(line)
        except ValueError as exc:
            self.record_failure(line, str(exc), line_number)
            return

        ns_service = re.findall(r'"([^"]*)"', line)[0]

        if "+" in line:
            self.multi_server_app_set(ns_service, junos_app_name)
        elif ns_service not in self.state.service_ns_to_junos:
            self.state.service_ns_to_junos[ns_service] = junos_app_name

        self.convert_config(converted_line)
        self.combine_dicts("service")

    def multi_server_app_set(self, ns_service: str, junos_app_name: str) -> None:
        app_set_name = sanity_check_naming(ns_service)
        app_set_key = f"{app_set_name}_group".lower()

        converted_line = (
            f"set applications application-set {app_set_key} application {junos_app_name}"
        ).lower()
        self.state.service_grp_to_app_set[ns_service] = app_set_key

        delete_from_dict = False
        for ns_key, junos_value in list(self.state.service_ns_to_junos.items()):
            if ns_service in ns_key:
                first_line_of_grp = (
                    f"set applications application-set {app_set_key} application {junos_value}"
                ).lower()
                self.convert_config(first_line_of_grp)
                delete_from_dict = True

        if delete_from_dict:
            del self.state.service_ns_to_junos[ns_service]

        self.convert_config(converted_line)

    def create_app_set(self, line: str, line_number: int | None = None) -> None:
        ns_group_name = re.findall(r'"([^"]*)"', line)[0]
        junos_app_set_name = sanity_check_naming(ns_group_name)
        ns_service_member = re.findall(r'"([^"]*)"', line)[1]

        junos_app_name = self.state.service_dicts.get(ns_service_member)
        if junos_app_name is None:
            self.record_failure(
                line,
                f'undefined service-group member: "{ns_service_member}"',
                line_number,
            )
            return

        converted_line = (
            f"set applications application-set {junos_app_set_name} application {junos_app_name}"
        ).lower()

        self.state.service_dicts[ns_group_name] = junos_app_set_name.lower()
        self.convert_config(converted_line)

    @staticmethod
    def normalize_zone(zone: str) -> str:
        if zone.lower() == "management":
            return "System-Management"
        return zone

    def remember_zone(self, zone: str) -> str:
        zone = self.normalize_zone(zone)
        if zone not in self.state.list_of_zones:
            self.state.list_of_zones.append(zone)
        return zone

    def zone_name(self, line: str) -> str:
        return self.remember_zone(re.findall(r'"([^"]*)"', line)[0])

    def create_address_book(
        self,
        original_line: str,
        line_number: int | None = None,
    ) -> None:
        match = RE_ADDRESS.fullmatch(original_line)
        if match is None:
            self.record_failure(
                original_line,
                "malformed or unsupported address definition",
                line_number,
            )
            return

        zone = self.remember_zone(match.group("zone"))

        ns_address = match.group("name")
        junos_address_name = sanity_check_naming(ns_address)
        existing_owner = self.state.address_name_owners.get((zone, junos_address_name))
        if existing_owner is not None and existing_owner != ns_address:
            self.record_failure(
                original_line,
                (
                    f'ambiguous address name: "{ns_address}" and '
                    f'"{existing_owner}" both normalize to "{junos_address_name}" '
                    f"in zone {zone}"
                ),
                line_number,
            )
            return

        value = match.group("value")
        mask = match.group("mask")

        if mask is not None:
            try:
                prefix_cidr = IP(f"{value}/{mask}", make_net=True)
                normalized_prefix = str(
                    ipaddress.ip_network(f"{value}/{mask}", strict=False)
                )
                if zone.lower() == "global":
                    converted_line = (
                        f"set security address-book global address "
                        f"{junos_address_name} {prefix_cidr}"
                    )
                else:
                    converted_line = (
                        f"set security zones security-zone {zone} address-book address "
                        f"{junos_address_name} {prefix_cidr}"
                    )
            except ValueError:
                self.record_failure(
                    original_line,
                    "invalid IPv4 address or netmask",
                    line_number,
                )
                return
        else:
            normalized_prefix = None
            try:
                IP(value, make_net=False)
            except ValueError:
                if zone.lower() == "global":
                    converted_line = (
                        f"set security address-book global address "
                        f"{junos_address_name} dns-name {value}"
                    )
                else:
                    converted_line = (
                        f"set security zones security-zone {zone} address-book address "
                        f"{junos_address_name} dns-name {value}"
                    )
            else:
                self.record_failure(
                    original_line,
                    "IPv4 address requires a dotted netmask",
                    line_number,
                )
                return

        self.state.addresses_ns_to_junos[ns_address] = junos_address_name
        self.state.address_name_owners[(zone, junos_address_name)] = ns_address
        self.state.address_objects_by_zone[(zone.lower(), ns_address)] = (
            junos_address_name
        )
        self.state.address_prefixes_by_zone[(zone.lower(), ns_address)] = (
            [normalized_prefix] if normalized_prefix is not None else []
        )
        if normalized_prefix is None:
            self.state.non_ip_address_keys.add((zone.lower(), ns_address))
        self.combine_dicts("address")
        self.convert_config(converted_line)

    def create_address_set(self, line: str, line_number: int | None = None) -> None:
        zone = self.zone_name(line)

        ns_address = re.findall(r'"([^"]*)"', line)[2]
        ns_address_grp = re.findall(r'"([^"]*)"', line)[1]

        junos_address_set = sanity_check_naming(ns_address_grp)
        junos_address_name = self.state.address_objects_by_zone.get(
            (zone.lower(), ns_address)
        )
        if junos_address_name is None:
            junos_address_name = self.state.default_addr.get(ns_address)
        if junos_address_name is None:
            self.record_failure(
                line,
                f'undefined address-group member: "{ns_address}"',
                line_number,
            )
            return

        self.state.address_group_ns_to_junos_address_set[ns_address_grp] = (
            junos_address_set
        )
        self.state.address_objects_by_zone[(zone.lower(), ns_address_grp)] = (
            junos_address_set
        )
        member_prefixes = self.state.address_prefixes_by_zone.get(
            (zone.lower(), ns_address),
            [],
        )
        group_prefixes = self.state.address_prefixes_by_zone.setdefault(
            (zone.lower(), ns_address_grp),
            [],
        )
        group_prefixes.extend(
            prefix for prefix in member_prefixes if prefix not in group_prefixes
        )
        if (zone.lower(), ns_address) in self.state.non_ip_address_keys:
            self.state.non_ip_address_keys.add((zone.lower(), ns_address_grp))
        self.combine_dicts("address")

        member_kind = (
            "address-set"
            if (zone.lower(), ns_address) in self.state.address_set_keys
            else "address"
        )
        self.state.address_set_keys.add((zone.lower(), ns_address_grp))
        if zone.lower() == "global":
            converted_line = (
                f"set security address-book global address-set {junos_address_set} "
                f"{member_kind} {junos_address_name}"
            )
        else:
            converted_line = (
                f"set security zones security-zone {zone} address-book address-set "
                f"{junos_address_set} {member_kind} {junos_address_name}"
            )

        self.convert_config(converted_line)

    def parse_interface_line(self, line: str, line_number: int) -> None:
        try:
            tokens = shlex.split(line)
        except ValueError:
            self.record_failure(
                line,
                "malformed interface definition",
                line_number,
            )
            return

        if len(tokens) < 4 or tokens[:2] != ["set", "interface"]:
            self.record_failure(line, "malformed interface definition", line_number)
            return

        screenos_name = tokens[2]
        try:
            mapping = map_screenos_interface(screenos_name)
        except ValueError as exc:
            self.record_failure(line, str(exc), line_number)
            return

        model = self.state.interfaces.get(screenos_name)
        if model is None:
            model = InterfaceModel(
                screenos_name=screenos_name,
                mapping=mapping,
                line_number=line_number,
                source_line=line,
                zone=("System-Management" if mapping.kind == "management" else None),
            )
            self.state.interfaces[screenos_name] = model
            self.state.interface_ns_to_junos[screenos_name] = mapping.logical_name

        attributes = tokens[3:]
        if attributes and attributes[0].lower() == "mip":
            self.parse_mip_definition(
                screenos_name,
                attributes,
                line,
                line_number,
            )
            return
        if attributes and attributes[0].lower() == "dip":
            self.parse_dip_definition(
                screenos_name,
                attributes,
                line,
                line_number,
            )
            return
        if [attribute.lower() for attribute in attributes] == ["nat"]:
            self.record_failure(
                line,
                (
                    "interface NAT mode has no explicit destination context; "
                    "use policy NAT-src for a lossless conversion"
                ),
                line_number,
            )
            return

        if len(attributes) == 2 and attributes[0].lower() == "zone":
            model.zone = self.remember_zone(attributes[1])
        elif len(attributes) == 2 and attributes[0].lower() == "description":
            model.description = attributes[1]
        elif len(attributes) == 2 and attributes[0].lower() == "mtu":
            if mapping.kind == "management":
                self.record_failure(
                    line,
                    "management-interface MTU is not portable to Junos fxp0",
                    line_number,
                )
                return
            try:
                mtu = int(attributes[1])
            except ValueError:
                mtu = 0
            if not 256 <= mtu <= 9216:
                self.record_failure(
                    line,
                    "interface MTU must be between 256 and 9216",
                    line_number,
                )
                return
            model.mtu = mtu
        elif len(attributes) == 2 and attributes[0].lower() == "tag":
            try:
                vlan_id = int(attributes[1])
            except ValueError:
                vlan_id = -1
            if not 1 <= vlan_id <= 4094:
                self.record_failure(
                    line,
                    "interface VLAN tag must be between 1 and 4094",
                    line_number,
                )
                return
            if mapping.kind not in ("ethernet", "vlan") or (
                mapping.kind == "ethernet" and mapping.unit == 0
            ):
                self.record_failure(
                    line,
                    "VLAN tags require an Ethernet subinterface or VLAN interface",
                    line_number,
                )
                return
            model.vlan_id = vlan_id
        elif (
            len(attributes) == 2
            and attributes[0].lower() == "phy"
            and attributes[1].lower() == "link-down"
        ):
            model.disabled = True
        elif len(attributes) == 2 and attributes[0].lower() == "ip":
            try:
                address = ipaddress.ip_interface(attributes[1])
            except ValueError:
                self.record_failure(
                    line,
                    "invalid interface IPv4 prefix",
                    line_number,
                )
                return
            if address.version != 4:
                self.record_failure(
                    line,
                    "IPv6 interface prefixes require the 'ipv6 ip' form",
                    line_number,
                )
                return
            normalized = str(address)
            if normalized not in model.ipv4_addresses:
                model.ipv4_addresses.append(normalized)
        elif (
            len(attributes) == 4
            and attributes[0].lower() == "ip"
            and attributes[1].lower() == "unnumbered"
            and attributes[2].lower() == "interface"
        ):
            model.unnumbered_from = attributes[3]
            model.unnumbered_line_number = line_number
            model.unnumbered_source_line = line
        elif (
            len(attributes) == 3
            and attributes[0].lower() == "ipv6"
            and attributes[1].lower() == "ip"
        ):
            try:
                address = ipaddress.ip_interface(attributes[2])
            except ValueError:
                self.record_failure(
                    line,
                    "invalid interface IPv6 prefix",
                    line_number,
                )
                return
            if address.version != 6:
                self.record_failure(
                    line,
                    "IPv4 interface prefixes require the 'ip' form",
                    line_number,
                )
                return
            normalized = str(address)
            if normalized not in model.ipv6_addresses:
                model.ipv6_addresses.append(normalized)
        else:
            self.record_failure(
                line,
                f"unsupported interface attribute: {' '.join(attributes)}",
                line_number,
            )
            return

        model.configured = True

    def parse_mip_definition(
        self,
        interface: str,
        attributes: list[str],
        line: str,
        line_number: int,
    ) -> None:
        if (
            len(attributes) < 4
            or attributes[0].lower() != "mip"
            or attributes[2].lower() != "host"
        ):
            self.record_failure(line, "malformed MIP definition", line_number)
            return

        mapped_address = attributes[1]
        host_address = attributes[3]
        netmask = "255.255.255.255"
        vrouter = "trust-vr"
        index = 4
        while index < len(attributes):
            option = attributes[index].lower()
            if option == "netmask" and index + 1 < len(attributes):
                netmask = attributes[index + 1]
                index += 2
            elif option == "vrouter" and index + 1 < len(attributes):
                vrouter = attributes[index + 1]
                index += 2
            else:
                self.record_failure(
                    line,
                    f"unsupported MIP option: {' '.join(attributes[index:])}",
                    line_number,
                )
                return

        try:
            parsed_mapped_address = ipaddress.ip_address(mapped_address)
            parsed_host_address = ipaddress.ip_address(host_address)
            mapped_prefix = ipaddress.ip_network(
                f"{mapped_address}/{netmask}",
                strict=False,
            )
            host_prefix = ipaddress.ip_network(
                f"{host_address}/{netmask}",
                strict=False,
            )
        except ValueError:
            self.record_failure(
                line,
                "invalid MIP address or netmask",
                line_number,
            )
            return
        if mapped_prefix.version != 4 or host_prefix.version != 4:
            self.record_failure(line, "MIP conversion supports IPv4 only", line_number)
            return
        if (
            parsed_mapped_address != mapped_prefix.network_address
            or parsed_host_address != host_prefix.network_address
        ):
            self.record_failure(
                line,
                "MIP ranges must begin on their netmask boundary",
                line_number,
            )
            return
        if any(mip.mapped_prefix == str(mapped_prefix) for mip in self.state.mips):
            self.record_failure(
                line,
                f"duplicate MIP prefix {mapped_prefix}",
                line_number,
            )
            return

        self.state.mips.append(
            MipModel(
                interface=interface,
                mapped_prefix=str(mapped_prefix),
                host_prefix=str(host_prefix),
                vrouter=vrouter,
                line_number=line_number,
                source_line=line,
            )
        )

    def parse_dip_definition(
        self,
        interface: str,
        attributes: list[str],
        line: str,
        line_number: int,
    ) -> None:
        if len(attributes) < 3 or attributes[0].lower() != "dip":
            self.record_failure(line, "malformed DIP definition", line_number)
            return

        try:
            pool_id = int(attributes[1])
        except ValueError:
            pool_id = -1
        if not 4 <= pool_id <= 1023:
            self.record_failure(
                line,
                "DIP pool id must be between 4 and 1023",
                line_number,
            )
            return

        option_names = {"fix-port", "incoming", "random-port", "shift-from"}
        address_tokens: list[str] = []
        index = 2
        while index < len(attributes) and attributes[index].lower() not in option_names:
            address_tokens.append(attributes[index])
            index += 1
        if not 1 <= len(address_tokens) <= 2:
            self.record_failure(line, "malformed DIP address range", line_number)
            return

        options = [option.lower() for option in attributes[index:]]
        if any(
            option in options for option in ("incoming", "random-port", "shift-from")
        ):
            self.record_failure(
                line,
                f"unsupported DIP variant: {' '.join(attributes[index:])}",
                line_number,
            )
            return
        if options not in ([], ["fix-port"]):
            self.record_failure(
                line,
                f"unsupported DIP option: {' '.join(attributes[index:])}",
                line_number,
            )
            return

        try:
            start = ipaddress.ip_address(address_tokens[0])
            end = ipaddress.ip_address(address_tokens[-1])
        except ValueError:
            self.record_failure(line, "invalid DIP address range", line_number)
            return
        if start.version != 4 or end.version != 4:
            self.record_failure(line, "DIP conversion supports IPv4 only", line_number)
            return
        if int(end) < int(start):
            self.record_failure(
                line,
                "DIP range end must not precede its start",
                line_number,
            )
            return
        if pool_id in self.state.dip_pools:
            self.record_failure(
                line,
                f"duplicate DIP pool id {pool_id}",
                line_number,
            )
            return

        self.state.dip_pools[pool_id] = DipPoolModel(
            interface=interface,
            pool_id=pool_id,
            start_address=str(start),
            end_address=str(end),
            fixed_port=options == ["fix-port"],
            line_number=line_number,
            source_line=line,
        )

    def render_interfaces(self) -> None:
        renderable: dict[str, InterfaceModel] = {}
        for name, model in self.state.interfaces.items():
            if not model.configured:
                continue
            if (
                model.mapping.kind == "ethernet"
                and model.mapping.unit != 0
                and model.vlan_id is None
            ):
                self.record_failure(
                    model.source_line,
                    (f'ethernet subinterface "{name}" requires an explicit VLAN tag'),
                    model.line_number,
                )
                continue
            if model.ipv4_addresses and model.unnumbered_from is not None:
                self.record_failure(
                    model.unnumbered_source_line or model.source_line,
                    f'interface "{name}" cannot be numbered and unnumbered',
                    model.unnumbered_line_number or model.line_number,
                )
                continue
            renderable[name] = model

        for name, model in list(renderable.items()):
            if model.unnumbered_from is None:
                continue
            donor = renderable.get(model.unnumbered_from)
            if donor is not None and donor.ipv4_addresses:
                continue
            self.record_failure(
                model.unnumbered_source_line or model.source_line,
                (
                    f'unnumbered donor interface "{model.unnumbered_from}" '
                    "is undefined or has no IPv4 address"
                ),
                model.unnumbered_line_number or model.line_number,
            )
            del renderable[name]

        tagged_physical_interfaces: set[str] = set()
        for model in renderable.values():
            mapping = model.mapping
            physical = mapping.physical_name
            unit_prefix = f"set interfaces {physical} unit {mapping.unit}"
            output_start = len(self.state.converted_config)

            if mapping.kind == "ethernet" and mapping.unit != 0:
                if physical not in tagged_physical_interfaces:
                    self.convert_config(f"set interfaces {physical} vlan-tagging")
                    tagged_physical_interfaces.add(physical)
                self.convert_config(f"{unit_prefix} vlan-id {model.vlan_id}")
            elif mapping.kind == "vlan":
                vlan_id = model.vlan_id or mapping.unit
                vlan_name = f"screenos_vlan_{vlan_id}"
                self.convert_config(f"set vlans {vlan_name} vlan-id {vlan_id}")
                self.convert_config(
                    f"set vlans {vlan_name} l3-interface {mapping.logical_name}"
                )

            if model.description is not None:
                description = model.description.replace("\\", "\\\\").replace(
                    '"', '\\"'
                )
                if mapping.kind in ("tunnel", "vlan") or mapping.unit != 0:
                    self.convert_config(f'{unit_prefix} description "{description}"')
                else:
                    self.convert_config(
                        f'set interfaces {physical} description "{description}"'
                    )

            if model.disabled:
                if mapping.kind in ("tunnel", "vlan") or mapping.unit != 0:
                    self.convert_config(f"{unit_prefix} disable")
                else:
                    self.convert_config(f"set interfaces {physical} disable")

            if (
                model.mtu is not None
                and mapping.kind == "ethernet"
                and mapping.unit == 0
            ):
                self.convert_config(f"set interfaces {physical} mtu {model.mtu}")

            for address in model.ipv4_addresses:
                self.convert_config(f"{unit_prefix} family inet address {address}")
            for address in model.ipv6_addresses:
                self.convert_config(f"{unit_prefix} family inet6 address {address}")

            if model.unnumbered_from is not None:
                donor = renderable[model.unnumbered_from]
                self.convert_config(
                    f"{unit_prefix} family inet unnumbered-address "
                    f"{donor.mapping.logical_name}"
                )

            needs_empty_inet_family = (
                not model.ipv4_addresses
                and not model.ipv6_addresses
                and model.unnumbered_from is None
                and model.zone is not None
            )
            if needs_empty_inet_family:
                self.convert_config(f"{unit_prefix} family inet")

            if model.mtu is not None and not (
                mapping.kind == "ethernet" and mapping.unit == 0
            ):
                families = []
                if model.ipv4_addresses or model.unnumbered_from or model.zone:
                    families.append("inet")
                if model.ipv6_addresses:
                    families.append("inet6")
                if not families:
                    families.append("inet")
                for family in dict.fromkeys(families):
                    self.convert_config(
                        f"{unit_prefix} family {family} mtu {model.mtu}"
                    )

            if model.zone is not None:
                self.convert_config(
                    f"set security zones security-zone {model.zone} interfaces "
                    f"{mapping.logical_name}"
                )

            if any(
                output_line.startswith(unit_prefix)
                for output_line in self.state.converted_config[output_start:]
            ):
                self.state.rendered_interfaces.add(model.screenos_name)

    @staticmethod
    def junos_vrouter_name(vrouter: str) -> str | None:
        """Map the ScreenOS default VR to Junos' primary routing instance."""

        if vrouter.lower() == "trust-vr":
            return None
        return sanity_check_naming(vrouter)

    def parse_vrouter_line(self, line: str, line_number: int) -> None:
        diagnostic_line = RE_BGP_AUTHENTICATION.sub(
            lambda match: f"{match.group(1)} <redacted>",
            line,
        )
        try:
            tokens = shlex.split(line)
        except ValueError:
            self.record_failure(
                diagnostic_line,
                "malformed virtual-router definition",
                line_number,
            )
            return

        if len(tokens) < 5 or tokens[:2] != ["set", "vrouter"]:
            self.record_failure(
                diagnostic_line,
                "malformed virtual-router definition",
                line_number,
            )
            return

        vrouter = tokens[2]
        command = tokens[3].lower()
        if command == "route":
            self.parse_static_route(vrouter, tokens[4:], line, line_number)
        elif command == "protocol" and len(tokens) >= 6:
            if tokens[4].lower() != "bgp":
                self.record_failure(
                    diagnostic_line,
                    f"unsupported routing protocol: {tokens[4]}",
                    line_number,
                )
                return
            self.parse_bgp_line(
                vrouter,
                tokens[5:],
                diagnostic_line,
                line_number,
            )
        else:
            self.record_failure(
                diagnostic_line,
                f"unsupported virtual-router command: {' '.join(tokens[3:])}",
                line_number,
            )

    def parse_static_route(
        self,
        vrouter: str,
        tokens: list[str],
        line: str,
        line_number: int,
    ) -> None:
        if not tokens or tokens[0].lower() in ("source", "in-interface"):
            self.record_failure(
                line,
                "source-based and source-interface routes are unsupported",
                line_number,
            )
            return

        try:
            destination = ipaddress.ip_network(tokens[0], strict=False)
        except ValueError:
            self.record_failure(line, "invalid static-route prefix", line_number)
            return

        interface = None
        gateway = None
        preference = None
        metric = None
        tag = None
        description = None
        permanent = False
        index = 1
        while index < len(tokens):
            option = tokens[index].lower()
            if option == "interface" and index + 1 < len(tokens):
                interface = tokens[index + 1]
                index += 2
            elif option == "gateway" and index + 1 < len(tokens):
                try:
                    parsed_gateway = ipaddress.ip_address(tokens[index + 1])
                except ValueError:
                    self.record_failure(
                        line,
                        "invalid static-route gateway",
                        line_number,
                    )
                    return
                if parsed_gateway.version != destination.version:
                    self.record_failure(
                        line,
                        "static-route gateway and prefix use different IP families",
                        line_number,
                    )
                    return
                gateway = str(parsed_gateway)
                index += 2
            elif option in ("preference", "metric", "tag") and index + 1 < len(tokens):
                try:
                    value = int(tokens[index + 1])
                except ValueError:
                    self.record_failure(
                        line,
                        f"static-route {option} must be numeric",
                        line_number,
                    )
                    return
                if option == "preference":
                    if not 0 <= value <= 255:
                        self.record_failure(
                            line,
                            "static-route preference must be between 0 and 255",
                            line_number,
                        )
                        return
                    preference = value
                elif option == "metric":
                    if not 1 <= value <= 65535:
                        self.record_failure(
                            line,
                            "static-route metric must be between 1 and 65535",
                            line_number,
                        )
                        return
                    metric = value
                else:
                    if not 0 <= value <= 4_294_967_295:
                        self.record_failure(
                            line,
                            "static-route tag must be between 0 and 4294967295",
                            line_number,
                        )
                        return
                    tag = value
                index += 2
            elif option == "description" and index + 1 < len(tokens):
                description = tokens[index + 1]
                index += 2
            elif option == "permanent":
                permanent = True
                index += 1
            else:
                self.record_failure(
                    line,
                    f"unsupported static-route option: {' '.join(tokens[index:])}",
                    line_number,
                )
                return

        if interface is None and gateway is None:
            self.record_failure(
                line,
                "static route requires an interface or gateway",
                line_number,
            )
            return

        route = StaticRouteModel(
            vrouter=vrouter,
            destination=str(destination),
            interface=interface,
            gateway=gateway,
            preference=preference,
            metric=metric,
            tag=tag,
            description=description,
            permanent=permanent,
            line_number=line_number,
            source_line=line,
        )
        if route in self.state.static_routes:
            self.record_failure(line, "duplicate static route", line_number)
            return
        self.state.static_routes.append(route)

    def _bgp_instance(
        self,
        vrouter: str,
        line: str,
        line_number: int,
    ) -> BgpInstanceModel:
        instance = self.state.bgp_instances.get(vrouter)
        if instance is None:
            instance = BgpInstanceModel(
                vrouter=vrouter,
                line_number=line_number,
                source_line=line,
            )
            self.state.bgp_instances[vrouter] = instance
        return instance

    def parse_bgp_line(
        self,
        vrouter: str,
        tokens: list[str],
        line: str,
        line_number: int,
    ) -> None:
        line = RE_BGP_AUTHENTICATION.sub(
            lambda match: f"{match.group(1)} <redacted>",
            line,
        )
        if not tokens:
            self.record_failure(line, "malformed BGP definition", line_number)
            return

        instance = self._bgp_instance(vrouter, line, line_number)
        if len(tokens) == 1 and tokens[0].isdigit():
            local_as = int(tokens[0])
            if not 1 <= local_as <= 4_294_967_295:
                self.record_failure(line, "BGP AS number is out of range", line_number)
                return
            instance.local_as = local_as
            return
        if [token.lower() for token in tokens] == ["enable"]:
            instance.enabled = True
            return
        if len(tokens) == 2 and tokens[0].lower() == "router-id":
            try:
                router_id = ipaddress.ip_address(tokens[1])
            except ValueError:
                self.record_failure(line, "invalid BGP router id", line_number)
                return
            if router_id.version != 4:
                self.record_failure(line, "BGP router id must be IPv4", line_number)
                return
            instance.router_id = str(router_id)
            return

        family = "inet"
        if tokens[0].lower() in ("ipv4", "ipv6"):
            family = "inet" if tokens[0].lower() == "ipv4" else "inet6"
            tokens = tokens[1:]
        if len(tokens) < 3 or tokens[0].lower() != "neighbor":
            self.record_failure(
                line,
                f"unsupported BGP command: {' '.join(tokens)}",
                line_number,
            )
            return

        if tokens[1].lower() == "peer-group":
            if len(tokens) < 4:
                self.record_failure(line, "malformed BGP peer group", line_number)
                return
            group_name = tokens[2]
            group = instance.peer_groups.get(group_name)
            if group is None:
                group = BgpPeerGroupModel(
                    name=group_name,
                    line_number=line_number,
                    source_line=line,
                )
                instance.peer_groups[group_name] = group
            if not self._apply_bgp_options(
                group.options,
                tokens[3:],
                line,
                line_number,
            ):
                return
            return

        try:
            address = ipaddress.ip_address(tokens[1])
        except ValueError:
            self.record_failure(line, "invalid BGP neighbor address", line_number)
            return
        expected_family = "inet" if address.version == 4 else "inet6"
        if family != expected_family:
            self.record_failure(
                line,
                "BGP address-family keyword does not match neighbor address",
                line_number,
            )
            return

        address_text = str(address)
        peer = instance.peers.get(address_text)
        if peer is None:
            peer = BgpPeerModel(
                address=address_text,
                family=family,
                line_number=line_number,
                source_line=line,
            )
            instance.peers[address_text] = peer

        options = tokens[2:]
        option = options[0].lower()
        if option == "peer-group" and len(options) == 2:
            peer.peer_group = options[1]
            if options[1] not in instance.peer_groups:
                instance.peer_groups[options[1]] = BgpPeerGroupModel(
                    name=options[1],
                    line_number=line_number,
                    source_line=line,
                )
            return
        if option in ("enable", "activate") and len(options) == 1:
            peer.enabled = True
            return
        self._apply_bgp_options(peer.options, options, line, line_number)

    def _apply_bgp_options(
        self,
        options: BgpOptions,
        tokens: list[str],
        line: str,
        line_number: int,
    ) -> bool:
        if not tokens:
            self.record_failure(line, "missing BGP peer option", line_number)
            return False

        index = 0
        while index < len(tokens):
            option = tokens[index].lower()
            if option == "remote-as" and index + 1 < len(tokens):
                try:
                    remote_as = int(tokens[index + 1])
                except ValueError:
                    remote_as = 0
                if not 1 <= remote_as <= 4_294_967_295:
                    self.record_failure(
                        line,
                        "BGP remote AS number is out of range",
                        line_number,
                    )
                    return False
                options.remote_as = remote_as
                options.option_sources["remote-as"] = (line_number, line)
                index += 2
            elif option in ("hold-time", "keepalive") and index + 1 < len(tokens):
                try:
                    timer = int(tokens[index + 1])
                except ValueError:
                    timer = -1
                if not 0 <= timer <= 65_535:
                    self.record_failure(
                        line,
                        f"BGP {option} must be between 0 and 65535",
                        line_number,
                    )
                    return False
                if option == "hold-time":
                    options.hold_time = timer
                else:
                    options.keepalive = timer
                options.option_sources[option] = (line_number, line)
                index += 2
            elif option == "md5-authentication" and index + 1 < len(tokens):
                self.record_failure(
                    line,
                    (
                        "BGP MD5 authentication secret omitted; configure a Junos "
                        "authentication key manually"
                    ),
                    line_number,
                )
                return False
            elif option == "route-map" and index + 2 < len(tokens):
                direction = tokens[index + 2].lower()
                if direction not in ("in", "out"):
                    self.record_failure(
                        line,
                        "BGP route-map direction must be 'in' or 'out'",
                        line_number,
                    )
                    return False
                policy = sanity_check_naming(tokens[index + 1])
                if direction == "in":
                    options.import_policy = policy
                else:
                    options.export_policy = policy
                options.option_sources[f"route-map-{direction}"] = (line_number, line)
                index += 3
            elif option in ("src-interface", "outgoing-interface") and index + 1 < len(
                tokens
            ):
                options.source_interface = tokens[index + 1]
                options.option_sources["source-interface"] = (line_number, line)
                index += 2
            elif option == "local-ip" and index + 1 < len(tokens):
                try:
                    local_address = ipaddress.ip_interface(tokens[index + 1]).ip
                except ValueError:
                    self.record_failure(
                        line,
                        "invalid BGP local IP address",
                        line_number,
                    )
                    return False
                options.local_address = str(local_address)
                options.option_sources["local-address"] = (line_number, line)
                index += 2
            else:
                self.record_failure(
                    line,
                    f"unsupported BGP peer option: {' '.join(tokens[index:])}",
                    line_number,
                )
                return False
        return True

    def _ensure_routing_instance(
        self,
        vrouter: str,
        emitted_instances: set[str],
    ) -> str | None:
        junos_name = self.junos_vrouter_name(vrouter)
        if junos_name is not None and junos_name not in emitted_instances:
            self.convert_config(
                f"set routing-instances {junos_name} instance-type virtual-router"
            )
            emitted_instances.add(junos_name)
        return junos_name

    def _attach_routing_interface(
        self,
        vrouter: str,
        screenos_interface: str,
        line: str,
        line_number: int,
    ) -> bool:
        junos_name = self.junos_vrouter_name(vrouter)
        if junos_name is None:
            return True
        mapping = self.state.interface_ns_to_junos.get(screenos_interface)
        if mapping is None or screenos_interface not in self.state.rendered_interfaces:
            self.record_failure(
                line,
                f'undefined routing interface: "{screenos_interface}"',
                line_number,
            )
            return False

        for owner, interfaces in self.state.routing_instance_interfaces.items():
            if owner != junos_name and screenos_interface in interfaces:
                self.record_failure(
                    line,
                    (
                        f'interface "{screenos_interface}" is already assigned '
                        f"to routing instance {owner}"
                    ),
                    line_number,
                )
                return False

        interfaces = self.state.routing_instance_interfaces.setdefault(
            junos_name,
            set(),
        )
        if screenos_interface not in interfaces:
            self.convert_config(
                f"set routing-instances {junos_name} interface {mapping}"
            )
            interfaces.add(screenos_interface)
        return True

    @staticmethod
    def _routing_options_prefix(vrouter: str) -> str:
        junos_name = Converter.junos_vrouter_name(vrouter)
        if junos_name is None:
            return "set routing-options"
        return f"set routing-instances {junos_name} routing-options"

    @staticmethod
    def _bgp_prefix(vrouter: str) -> str:
        junos_name = Converter.junos_vrouter_name(vrouter)
        if junos_name is None:
            return "set protocols bgp"
        return f"set routing-instances {junos_name} protocols bgp"

    def render_routing(self) -> None:
        emitted_instances: set[str] = set()
        for route in self.state.static_routes:
            mapped_interface = None
            if route.interface is not None and route.interface.lower() != "null":
                mapped_interface = self.state.interface_ns_to_junos.get(route.interface)
                if (
                    mapped_interface is None
                    or route.interface not in self.state.rendered_interfaces
                ):
                    self.record_failure(
                        route.source_line,
                        f'undefined routing interface: "{route.interface}"',
                        route.line_number,
                    )
                    continue

            self._ensure_routing_instance(route.vrouter, emitted_instances)
            if (
                route.interface is not None
                and route.interface.lower() != "null"
                and not self._attach_routing_interface(
                    route.vrouter,
                    route.interface,
                    route.source_line,
                    route.line_number,
                )
            ):
                continue

            prefix = (
                f"{self._routing_options_prefix(route.vrouter)} static route "
                f"{route.destination}"
            )
            if route.interface is not None and route.interface.lower() == "null":
                self.convert_config(f"{prefix} discard")
            elif route.gateway is not None:
                self.convert_config(f"{prefix} next-hop {route.gateway}")
            elif mapped_interface is not None:
                self.convert_config(f"{prefix} next-hop {mapped_interface}")

            if route.preference is not None:
                self.convert_config(f"{prefix} preference {route.preference}")
            if route.metric is not None:
                self.convert_config(f"{prefix} metric {route.metric}")
            if route.tag is not None:
                self.convert_config(f"{prefix} tag {route.tag}")
            if route.description is not None:
                self.record_failure(
                    route.source_line,
                    (
                        "static-route description has no portable Junos "
                        "set-command mapping"
                    ),
                    route.line_number,
                )
            if route.permanent:
                self.record_failure(
                    route.source_line,
                    (
                        "ScreenOS permanent-route state has no lossless Junos "
                        "static-route mapping"
                    ),
                    route.line_number,
                )

        for instance in self.state.bgp_instances.values():
            self._render_bgp_instance(instance, emitted_instances)

    def _bgp_option_source(
        self,
        options: BgpOptions,
        name: str,
        fallback_line_number: int,
        fallback_line: str,
    ) -> tuple[int, str]:
        return options.option_sources.get(
            name,
            (fallback_line_number, fallback_line),
        )

    def _bgp_local_address(
        self,
        options: BgpOptions,
        vrouter: str,
        fallback_line_number: int,
        fallback_line: str,
    ) -> str | None:
        if options.local_address is not None:
            return options.local_address
        if options.source_interface is None:
            return None

        line_number, line = self._bgp_option_source(
            options,
            "source-interface",
            fallback_line_number,
            fallback_line,
        )
        interface = self.state.interfaces.get(options.source_interface)
        if (
            interface is None
            or options.source_interface not in self.state.rendered_interfaces
            or not interface.ipv4_addresses
        ):
            self.record_failure(
                line,
                (
                    f'BGP source interface "{options.source_interface}" '
                    "is undefined or has no IPv4 address"
                ),
                line_number,
            )
            return ""
        if not self._attach_routing_interface(
            vrouter,
            options.source_interface,
            line,
            line_number,
        ):
            return ""
        return str(ipaddress.ip_interface(interface.ipv4_addresses[0]).ip)

    def _render_bgp_options(
        self,
        prefix: str,
        options: BgpOptions,
        vrouter: str,
        fallback_line_number: int,
        fallback_line: str,
    ) -> bool:
        local_address = self._bgp_local_address(
            options,
            vrouter,
            fallback_line_number,
            fallback_line,
        )
        if local_address == "":
            return False
        if local_address is not None:
            self.convert_config(f"{prefix} local-address {local_address}")
        if options.hold_time is not None:
            self.convert_config(f"{prefix} hold-time {options.hold_time}")
        if options.keepalive is not None and (
            options.hold_time is None or options.keepalive * 3 != options.hold_time
        ):
            line_number, line = self._bgp_option_source(
                options,
                "keepalive",
                fallback_line_number,
                fallback_line,
            )
            self.record_failure(
                line,
                (
                    "explicit BGP keepalive has no independent Junos mapping; "
                    "Junos derives it from hold-time"
                ),
                line_number,
            )
        if options.import_policy is not None:
            self.convert_config(f"{prefix} import {options.import_policy}")
        if options.export_policy is not None:
            self.convert_config(f"{prefix} export {options.export_policy}")
        return True

    def _render_bgp_instance(
        self,
        instance: BgpInstanceModel,
        emitted_instances: set[str],
    ) -> None:
        if instance.local_as is None:
            self.record_failure(
                instance.source_line,
                f'BGP instance "{instance.vrouter}" has no local AS',
                instance.line_number,
            )
            return
        if not instance.enabled:
            self.record_failure(
                instance.source_line,
                f'disabled BGP instance "{instance.vrouter}" omitted from output',
                instance.line_number,
            )
            return

        self._ensure_routing_instance(instance.vrouter, emitted_instances)
        routing_prefix = self._routing_options_prefix(instance.vrouter)
        bgp_prefix = self._bgp_prefix(instance.vrouter)
        self.convert_config(f"{routing_prefix} autonomous-system {instance.local_as}")
        if instance.router_id is not None:
            self.convert_config(f"{routing_prefix} router-id {instance.router_id}")

        rendered_peer_addresses: set[str] = set()
        seen_group_names: set[str] = set()
        for screenos_group_name, group in instance.peer_groups.items():
            group_name = sanity_check_naming(screenos_group_name)
            if group_name in seen_group_names:
                self.record_failure(
                    group.source_line,
                    f'BGP peer-group name collision after normalization: "{group_name}"',
                    group.line_number,
                )
                continue
            seen_group_names.add(group_name)

            members = [
                peer
                for peer in instance.peers.values()
                if peer.peer_group == screenos_group_name
            ]
            active_members = []
            for peer in members:
                if peer.enabled:
                    active_members.append(peer)
                else:
                    self.record_failure(
                        peer.source_line,
                        f"disabled BGP neighbor {peer.address} omitted from output",
                        peer.line_number,
                    )
            if not active_members:
                self.record_failure(
                    group.source_line,
                    f'BGP peer group "{screenos_group_name}" has no enabled neighbors',
                    group.line_number,
                )
                continue

            remote_as_values = {
                peer.options.remote_as
                for peer in active_members
                if peer.options.remote_as is not None
            }
            if group.options.remote_as is not None:
                remote_as_values.add(group.options.remote_as)
            if len(remote_as_values) != 1:
                self.record_failure(
                    group.source_line,
                    (
                        f'BGP peer group "{screenos_group_name}" requires one '
                        "consistent remote AS"
                    ),
                    group.line_number,
                )
                continue
            remote_as = remote_as_values.pop()
            if any(
                peer.options.remote_as not in (None, remote_as)
                for peer in active_members
            ):
                self.record_failure(
                    group.source_line,
                    f'BGP peer group "{screenos_group_name}" has conflicting AS values',
                    group.line_number,
                )
                continue

            group_prefix = f"{bgp_prefix} group {group_name}"
            if (
                self._bgp_local_address(
                    group.options,
                    instance.vrouter,
                    group.line_number,
                    group.source_line,
                )
                == ""
            ):
                continue
            group_type = "internal" if remote_as == instance.local_as else "external"
            self.convert_config(f"{group_prefix} type {group_type}")
            self.convert_config(f"{group_prefix} peer-as {remote_as}")
            for family in dict.fromkeys(peer.family for peer in active_members):
                self.convert_config(f"{group_prefix} family {family} unicast")
            if not self._render_bgp_options(
                group_prefix,
                group.options,
                instance.vrouter,
                group.line_number,
                group.source_line,
            ):
                continue

            for peer in active_members:
                peer_prefix = f"{group_prefix} neighbor {peer.address}"
                if not self._render_bgp_options(
                    peer_prefix,
                    peer.options,
                    instance.vrouter,
                    peer.line_number,
                    peer.source_line,
                ):
                    continue
                self.convert_config(peer_prefix)
                rendered_peer_addresses.add(peer.address)

        for peer in instance.peers.values():
            if peer.address in rendered_peer_addresses or peer.peer_group is not None:
                continue
            if not peer.enabled:
                self.record_failure(
                    peer.source_line,
                    f"disabled BGP neighbor {peer.address} omitted from output",
                    peer.line_number,
                )
                continue
            if peer.options.remote_as is None:
                self.record_failure(
                    peer.source_line,
                    f"BGP neighbor {peer.address} has no remote AS",
                    peer.line_number,
                )
                continue

            group_name = sanity_check_naming(f"screenos_peer_{peer.address}")
            peer_group_prefix = f"{bgp_prefix} group {group_name}"
            if (
                self._bgp_local_address(
                    peer.options,
                    instance.vrouter,
                    peer.line_number,
                    peer.source_line,
                )
                == ""
            ):
                continue
            group_type = (
                "internal"
                if peer.options.remote_as == instance.local_as
                else "external"
            )
            self.convert_config(f"{peer_group_prefix} type {group_type}")
            self.convert_config(f"{peer_group_prefix} peer-as {peer.options.remote_as}")
            self.convert_config(f"{peer_group_prefix} family {peer.family} unicast")
            if not self._render_bgp_options(
                peer_group_prefix,
                peer.options,
                instance.vrouter,
                peer.line_number,
                peer.source_line,
            ):
                continue
            self.convert_config(f"{peer_group_prefix} neighbor {peer.address}")

    @staticmethod
    def _redact_ike_preshare(line: str) -> str:
        parts: list[str] = []
        cursor = 0
        search_start = 0
        while match := re.search(r"\bpreshare\b", line[search_start:], re.IGNORECASE):
            match_end = search_start + match.end()
            token_start = match_end
            while token_start < len(line) and line[token_start].isspace():
                token_start += 1
            if token_start == len(line):
                break

            quote = None
            index = token_start
            while index < len(line):
                character = line[index]
                if character == "\\" and quote != "'" and index + 1 < len(line):
                    index += 2
                    continue
                if character in {'"', "'"}:
                    if quote is None:
                        quote = character
                    elif character == quote:
                        quote = None
                    index += 1
                    continue
                if character.isspace() and quote is None:
                    break
                index += 1
            parts.extend((line[cursor:token_start], "<redacted>"))
            cursor = index
            search_start = index
        parts.append(line[cursor:])
        return "".join(parts)

    @staticmethod
    def _normalized_name_is_available(
        objects: dict[str, object],
        raw_name: str,
    ) -> bool:
        normalized = sanity_check_naming(raw_name)
        return not any(
            getattr(existing, "name", None) == normalized
            for existing in objects.values()
        )

    def _manual_review(self, warning: str) -> None:
        if warning not in self.state.manual_review_warnings:
            self.state.manual_review_warnings.append(warning)

    def _map_dh_group(
        self,
        value: str,
        line: str,
        line_number: int,
    ) -> str | None:
        normalized = value.lower().removeprefix("group").removeprefix("g")
        if not normalized.isdigit() or int(normalized) not in {
            1,
            2,
            5,
            14,
            15,
            16,
            19,
            20,
            21,
        }:
            self.record_failure(
                line,
                f"unsupported IKE Diffie-Hellman group: {value}",
                line_number,
            )
            return None
        group = f"group{int(normalized)}"
        if group in {"group1", "group2", "group5"}:
            self.record_failure(
                line,
                (
                    f"deprecated IKE Diffie-Hellman {group} preserved; "
                    "use group14 or stronger after peer validation"
                ),
                line_number,
            )
        return group

    def _map_encryption(
        self,
        value: str,
        line: str,
        line_number: int,
    ) -> str | None:
        normalized = value.lower().replace("-", "")
        mapped = {
            "aes128": "aes-128-cbc",
            "aes192": "aes-192-cbc",
            "aes256": "aes-256-cbc",
            "3des": "3des-cbc",
        }.get(normalized)
        if mapped is None:
            reason = (
                "DES encryption is deprecated and is not emitted"
                if normalized == "des"
                else f"unsupported IKE/IPsec encryption algorithm: {value}"
            )
            self.record_failure(line, reason, line_number)
            return None
        if mapped == "3des-cbc":
            self.record_failure(
                line,
                "deprecated 3DES encryption preserved; migrate to AES after peer validation",
                line_number,
            )
        return mapped

    def _map_authentication(
        self,
        value: str,
        phase: str,
        line: str,
        line_number: int,
    ) -> str | None:
        normalized = value.lower().replace("_", "-")
        if normalized in {"md5", "hmac-md5"}:
            self.record_failure(
                line,
                "MD5 authentication is deprecated and is not emitted",
                line_number,
            )
            return None
        if normalized in {"sha", "sha1", "sha-1"}:
            self.record_failure(
                line,
                "deprecated SHA-1 authentication preserved; migrate to SHA-256",
                line_number,
            )
            return "sha1" if phase == "ike" else "hmac-sha1-96"
        if normalized in {"sha256", "sha-256", "sha2-256"}:
            return "sha-256" if phase == "ike" else "hmac-sha-256-128"
        if normalized in {"sha384", "sha-384", "sha2-384"}:
            return "sha-384" if phase == "ike" else "hmac-sha-384"
        self.record_failure(
            line,
            f"unsupported {phase.upper()} authentication algorithm: {value}",
            line_number,
        )
        return None

    @staticmethod
    def _parse_lifetime(value: str) -> int | None:
        try:
            lifetime = int(value)
        except ValueError:
            return None
        return lifetime if 180 <= lifetime <= 86400 else None

    def parse_ike_line(self, line: str, line_number: int) -> None:
        safe_line = self._redact_ike_preshare(line)
        try:
            tokens = shlex.split(line)
        except ValueError:
            self.record_failure(safe_line, "malformed IKE definition", line_number)
            return

        if len(tokens) < 4 or tokens[:2] != ["set", "ike"]:
            self.record_failure(safe_line, "malformed IKE definition", line_number)
            return

        command = tokens[2].lower()
        if command == "p1-proposal":
            self._parse_ike_proposal(tokens, safe_line, line_number)
        elif command == "p2-proposal":
            self._parse_ipsec_proposal(tokens, safe_line, line_number)
        elif command == "gateway":
            self._parse_ike_gateway(tokens, safe_line, line_number)
        else:
            self.record_failure(
                safe_line,
                f"unsupported IKE command: {tokens[2]}",
                line_number,
            )

    def _parse_ike_proposal(
        self,
        tokens: list[str],
        line: str,
        line_number: int,
    ) -> None:
        if (
            len(tokens) != 11
            or tokens[4].lower() != "preshare"
            or tokens[6].lower() != "esp"
            or tokens[9].lower() not in {"second", "seconds"}
        ):
            self.record_failure(
                line, "malformed or unsupported Phase 1 proposal", line_number
            )
            return
        name = tokens[3]
        if name in self.state.ike_proposals:
            self.record_failure(
                line, f'duplicate Phase 1 proposal: "{name}"', line_number
            )
            return
        if not self._normalized_name_is_available(self.state.ike_proposals, name):
            self.record_failure(
                line,
                f'Phase 1 proposal name collides after Junos normalization: "{name}"',
                line_number,
            )
            return
        dh_group = self._map_dh_group(tokens[5], line, line_number)
        encryption = self._map_encryption(tokens[7], line, line_number)
        authentication = self._map_authentication(tokens[8], "ike", line, line_number)
        lifetime = self._parse_lifetime(tokens[10])
        if lifetime is None:
            self.record_failure(
                line,
                "IKE proposal lifetime must be between 180 and 86400 seconds",
                line_number,
            )
        if None in (dh_group, encryption, authentication, lifetime):
            return
        self.state.ike_proposals[name] = IkeProposalModel(
            name=sanity_check_naming(name),
            authentication_method="pre-shared-keys",
            dh_group=dh_group,
            authentication_algorithm=authentication,
            encryption_algorithm=encryption,
            lifetime_seconds=lifetime,
            line_number=line_number,
            source_line=line,
        )

    def _parse_ipsec_proposal(
        self,
        tokens: list[str],
        line: str,
        line_number: int,
    ) -> None:
        if (
            len(tokens) != 10
            or tokens[5].lower() != "esp"
            or tokens[8].lower() not in {"second", "seconds"}
        ):
            self.record_failure(
                line, "malformed or unsupported Phase 2 proposal", line_number
            )
            return
        name = tokens[3]
        if name in self.state.ipsec_proposals:
            self.record_failure(
                line, f'duplicate Phase 2 proposal: "{name}"', line_number
            )
            return
        if not self._normalized_name_is_available(self.state.ipsec_proposals, name):
            self.record_failure(
                line,
                f'Phase 2 proposal name collides after Junos normalization: "{name}"',
                line_number,
            )
            return
        pfs_token = tokens[4].lower()
        pfs_group = (
            None
            if pfs_token in {"nopfs", "no-pfs"}
            else self._map_dh_group(pfs_token, line, line_number)
        )
        encryption = self._map_encryption(tokens[6], line, line_number)
        authentication = self._map_authentication(tokens[7], "ipsec", line, line_number)
        lifetime = self._parse_lifetime(tokens[9])
        if lifetime is None:
            self.record_failure(
                line,
                "IPsec proposal lifetime must be between 180 and 86400 seconds",
                line_number,
            )
        if None in (encryption, authentication, lifetime) or (
            pfs_token not in {"nopfs", "no-pfs"} and pfs_group is None
        ):
            return
        self.state.ipsec_proposals[name] = IpsecProposalModel(
            name=sanity_check_naming(name),
            protocol="esp",
            authentication_algorithm=authentication,
            encryption_algorithm=encryption,
            lifetime_seconds=lifetime,
            pfs_group=pfs_group,
            line_number=line_number,
            source_line=line,
        )

    def _parse_ike_gateway(
        self,
        tokens: list[str],
        line: str,
        line_number: int,
    ) -> None:
        name = tokens[3]
        if len(tokens) == 5 and tokens[4].lower() == "nat-traversal":
            gateway = self.state.ike_gateways.get(name)
            if gateway is None:
                self.record_failure(
                    line,
                    f'VPN NAT traversal references undefined IKE gateway: "{name}"',
                    line_number,
                )
            else:
                gateway.nat_traversal = True
            return
        if name in self.state.ike_gateways or len(tokens) < 9:
            reason = (
                f'duplicate IKE gateway: "{name}"'
                if name in self.state.ike_gateways
                else "malformed or unsupported IKE gateway"
            )
            self.record_failure(line, reason, line_number)
            return
        if not self._normalized_name_is_available(self.state.ike_gateways, name):
            self.record_failure(
                line,
                f'IKE gateway name collides after Junos normalization: "{name}"',
                line_number,
            )
            return

        endpoint_kind = tokens[4].lower()
        if endpoint_kind not in {"address", "dynamic"}:
            self.record_failure(
                line, "IKE gateway requires an address or dynamic ID", line_number
            )
            return
        endpoint = tokens[5]
        if endpoint_kind == "address":
            try:
                ipaddress.ip_address(endpoint)
            except ValueError:
                if not re.fullmatch(
                    r"[A-Za-z0-9](?:[A-Za-z0-9.-]*[A-Za-z0-9])?", endpoint
                ):
                    self.record_failure(
                        line, "invalid IKE gateway peer address", line_number
                    )
                    return
        elif self._identity_clause(endpoint) is None:
            self.record_failure(
                line,
                "invalid dynamic IKE gateway identity",
                line_number,
            )
            return

        index = 6
        exchange_mode = "main"
        outgoing_interface = None
        proposal_name = None
        local_id = None
        preshared_key_omitted = False
        nat_traversal = False
        while index < len(tokens):
            option = tokens[index].lower()
            if option in {"main", "aggressive"}:
                exchange_mode = option
                index += 1
            elif option == "outgoing-interface" and index + 1 < len(tokens):
                outgoing_interface = tokens[index + 1]
                index += 2
            elif option == "local-id" and index + 1 < len(tokens):
                local_id = tokens[index + 1]
                index += 2
            elif option == "preshare" and index + 1 < len(tokens):
                preshared_key_omitted = True
                index += 2
            elif option == "proposal" and index + 1 < len(tokens):
                proposal_name = tokens[index + 1]
                index += 2
            elif option == "nat-traversal":
                nat_traversal = True
                index += 1
            elif option == "sec-level":
                self.record_failure(
                    line,
                    "IKE security-level bundles are ambiguous; select an explicit proposal",
                    line_number,
                )
                return
            else:
                self.record_failure(
                    line,
                    f"unsupported IKE gateway option: {' '.join(tokens[index:])}",
                    line_number,
                )
                return

        if outgoing_interface is None or proposal_name is None:
            self.record_failure(
                line,
                "IKE gateway requires outgoing-interface and proposal options",
                line_number,
            )
            return
        if local_id is not None and self._identity_clause(local_id) is None:
            self.record_failure(line, "invalid IKE local identity", line_number)
            return
        self.state.ike_gateways[name] = IkeGatewayModel(
            name=sanity_check_naming(name),
            endpoint_kind=endpoint_kind,
            endpoint=endpoint,
            exchange_mode=exchange_mode,
            outgoing_interface=outgoing_interface,
            proposal_name=proposal_name,
            line_number=line_number,
            source_line=line,
            local_id=local_id,
            preshared_key_omitted=preshared_key_omitted,
            nat_traversal=nat_traversal,
        )
        if preshared_key_omitted:
            self.record_failure(
                line,
                (
                    "IKE preshared key omitted; configure a Junos pre-shared-key "
                    "manually on the generated IKE policy"
                ),
                line_number,
            )

    def parse_vpn_line(self, line: str, line_number: int) -> None:
        try:
            tokens = shlex.split(line)
        except ValueError:
            self.record_failure(line, "malformed VPN definition", line_number)
            return
        if len(tokens) < 5 or tokens[:2] != ["set", "vpn"]:
            self.record_failure(line, "malformed VPN definition", line_number)
            return

        name = tokens[2]
        attributes = tokens[3:]
        if attributes[:2] == ["bind", "interface"] and len(attributes) == 3:
            vpn = self.state.ipsec_vpns.get(name)
            if vpn is None:
                self.record_failure(
                    line,
                    f'VPN interface binding references undefined VPN: "{name}"',
                    line_number,
                )
            else:
                vpn.bind_interface = attributes[2]
            return
        if (
            len(attributes) == 5
            and attributes[0] == "id"
            and attributes[2:4] == ["bind", "interface"]
        ):
            vpn = self.state.ipsec_vpns.get(name)
            if vpn is None:
                self.record_failure(
                    line,
                    f'VPN interface binding references undefined VPN: "{name}"',
                    line_number,
                )
            else:
                vpn.bind_interface = attributes[4]
            return
        if attributes and attributes[0] == "proxy-id":
            vpn = self.state.ipsec_vpns.get(name)
            if vpn is None:
                self.record_failure(
                    line,
                    f'proxy ID references undefined VPN: "{name}"',
                    line_number,
                )
                return
            if (
                len(attributes) != 6
                or attributes[1] != "local-ip"
                or attributes[3] != "remote-ip"
            ):
                self.record_failure(
                    line, "malformed or unsupported VPN proxy ID", line_number
                )
                return
            try:
                local = ipaddress.ip_network(attributes[2], strict=False)
                remote = ipaddress.ip_network(attributes[4], strict=False)
            except ValueError:
                self.record_failure(line, "invalid VPN proxy ID prefix", line_number)
                return
            if local.version != remote.version:
                self.record_failure(
                    line,
                    "VPN proxy ID local and remote prefixes must use the same family",
                    line_number,
                )
                return
            service = attributes[5].lower()
            if service != "any":
                self.record_failure(
                    line,
                    "VPN proxy ID services other than ANY are unsupported",
                    line_number,
                )
                return
            vpn.proxy_local = str(local)
            vpn.proxy_remote = str(remote)
            vpn.proxy_service = "any"
            return

        if name in self.state.ipsec_vpns:
            self.record_failure(
                line, f'duplicate VPN definition: "{name}"', line_number
            )
            return
        if not self._normalized_name_is_available(self.state.ipsec_vpns, name):
            self.record_failure(
                line,
                f'VPN name collides after Junos normalization: "{name}"',
                line_number,
            )
            return
        if len(attributes) < 4 or attributes[0] != "gateway":
            self.record_failure(
                line, "malformed or unsupported VPN definition", line_number
            )
            return
        gateway_name = attributes[1]
        proposal_name = None
        tunnel_mode = False
        anti_replay = True
        index = 2
        while index < len(attributes):
            option = attributes[index].lower()
            if option == "proposal" and index + 1 < len(attributes):
                proposal_name = attributes[index + 1]
                index += 2
            elif option == "replay":
                anti_replay = True
                index += 1
            elif option == "no-replay":
                anti_replay = False
                index += 1
            elif option == "tunnel":
                tunnel_mode = True
                index += 1
            elif option == "idletime" and index + 1 < len(attributes):
                if attributes[index + 1] != "0":
                    self.record_failure(
                        line,
                        "nonzero ScreenOS VPN idle time requires manual migration",
                        line_number,
                    )
                    return
                index += 2
            elif option == "sec-level":
                self.record_failure(
                    line,
                    "VPN security-level bundles are ambiguous; select an explicit proposal",
                    line_number,
                )
                return
            else:
                self.record_failure(
                    line,
                    f"unsupported VPN option: {' '.join(attributes[index:])}",
                    line_number,
                )
                return
        if proposal_name is None or not tunnel_mode:
            self.record_failure(
                line,
                "VPN requires tunnel mode and an explicit Phase 2 proposal",
                line_number,
            )
            return
        self.state.ipsec_vpns[name] = IpsecVpnModel(
            name=sanity_check_naming(name),
            gateway_name=gateway_name,
            proposal_name=proposal_name,
            line_number=line_number,
            source_line=line,
            anti_replay=anti_replay,
        )

    def _builtin_ike_proposal(
        self,
        name: str,
        gateway: IkeGatewayModel,
    ) -> IkeProposalModel | None:
        match = re.fullmatch(
            r"pre-g(?P<group>\d+)-(?P<encryption>aes(?:128|192|256)|3des|des)-"
            r"(?P<authentication>sha(?:-?1|-?256)?|md5)",
            name,
            re.IGNORECASE,
        )
        if match is None:
            return None
        group = self._map_dh_group(
            match["group"], gateway.source_line, gateway.line_number
        )
        encryption = self._map_encryption(
            match["encryption"], gateway.source_line, gateway.line_number
        )
        authentication = self._map_authentication(
            match["authentication"], "ike", gateway.source_line, gateway.line_number
        )
        if None in (group, encryption, authentication):
            return None
        return IkeProposalModel(
            name=sanity_check_naming(name),
            authentication_method="pre-shared-keys",
            dh_group=group,
            authentication_algorithm=authentication,
            encryption_algorithm=encryption,
            lifetime_seconds=28800,
            line_number=gateway.line_number,
            source_line=gateway.source_line,
        )

    def _builtin_ipsec_proposal(
        self,
        name: str,
        vpn: IpsecVpnModel,
    ) -> IpsecProposalModel | None:
        match = re.fullmatch(
            r"(?P<pfs>nopfs|g\d+)-esp-"
            r"(?P<encryption>aes(?:128|192|256)|3des|des)-"
            r"(?P<authentication>sha(?:-?1|-?256)?|md5)",
            name,
            re.IGNORECASE,
        )
        if match is None:
            return None
        pfs_group = None
        if match["pfs"].lower() != "nopfs":
            pfs_group = self._map_dh_group(
                match["pfs"], vpn.source_line, vpn.line_number
            )
            if pfs_group is None:
                return None
        encryption = self._map_encryption(
            match["encryption"], vpn.source_line, vpn.line_number
        )
        authentication = self._map_authentication(
            match["authentication"], "ipsec", vpn.source_line, vpn.line_number
        )
        if None in (encryption, authentication):
            return None
        return IpsecProposalModel(
            name=sanity_check_naming(name),
            protocol="esp",
            authentication_algorithm=authentication,
            encryption_algorithm=encryption,
            lifetime_seconds=3600,
            pfs_group=pfs_group,
            line_number=vpn.line_number,
            source_line=vpn.source_line,
        )

    @staticmethod
    def _identity_clause(value: str) -> str | None:
        try:
            address = ipaddress.ip_address(value)
        except ValueError:
            hostname = (
                r"[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?"
                r"(?:\.[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?)*"
            )
            if re.fullmatch(hostname, value):
                return "hostname"
            if re.fullmatch(rf"[A-Za-z0-9][A-Za-z0-9._+-]{{0,127}}@{hostname}", value):
                return "user-at-hostname"
            return None
        return "inet6" if address.version == 6 else "inet"

    def render_vpns(self) -> None:
        if not self.state.ike_gateways and not self.state.ipsec_vpns:
            return
        self._manual_review(
            "IPsec output requires manual validation of peer identities, routing, "
            "NAT traversal, cryptographic policy, and omitted preshared keys before deployment."
        )
        emitted_ike_proposals: dict[str, tuple[object, ...]] = {}
        emitted_ike_gateways: set[str] = set()
        emitted_ipsec_proposals: dict[str, tuple[object, ...]] = {}

        for source_vpn_name, vpn in self.state.ipsec_vpns.items():
            gateway = self.state.ike_gateways.get(vpn.gateway_name)
            if gateway is None:
                self.record_failure(
                    vpn.source_line,
                    f'VPN references undefined IKE gateway: "{vpn.gateway_name}"',
                    vpn.line_number,
                )
                continue
            ike_proposal = self.state.ike_proposals.get(gateway.proposal_name)
            if ike_proposal is None:
                ike_proposal = self._builtin_ike_proposal(
                    gateway.proposal_name, gateway
                )
            if ike_proposal is None:
                self.record_failure(
                    gateway.source_line,
                    f'undefined or unmappable Phase 1 proposal: "{gateway.proposal_name}"',
                    gateway.line_number,
                )
                continue
            ipsec_proposal = self.state.ipsec_proposals.get(vpn.proposal_name)
            if ipsec_proposal is None:
                ipsec_proposal = self._builtin_ipsec_proposal(vpn.proposal_name, vpn)
            if ipsec_proposal is None:
                self.record_failure(
                    vpn.source_line,
                    f'undefined or unmappable Phase 2 proposal: "{vpn.proposal_name}"',
                    vpn.line_number,
                )
                continue
            ike_fingerprint = (
                ike_proposal.authentication_method,
                ike_proposal.dh_group,
                ike_proposal.authentication_algorithm,
                ike_proposal.encryption_algorithm,
                ike_proposal.lifetime_seconds,
            )
            emitted_ike_fingerprint = emitted_ike_proposals.get(ike_proposal.name)
            if (
                emitted_ike_fingerprint is not None
                and emitted_ike_fingerprint != ike_fingerprint
            ):
                self.record_failure(
                    gateway.source_line,
                    (
                        "Phase 1 proposal collides after Junos normalization with "
                        f'different parameters: "{gateway.proposal_name}"'
                    ),
                    gateway.line_number,
                )
                continue
            ipsec_fingerprint = (
                ipsec_proposal.protocol,
                ipsec_proposal.authentication_algorithm,
                ipsec_proposal.encryption_algorithm,
                ipsec_proposal.lifetime_seconds,
                ipsec_proposal.pfs_group,
            )
            emitted_ipsec_fingerprint = emitted_ipsec_proposals.get(ipsec_proposal.name)
            if (
                emitted_ipsec_fingerprint is not None
                and emitted_ipsec_fingerprint != ipsec_fingerprint
            ):
                self.record_failure(
                    vpn.source_line,
                    (
                        "Phase 2 proposal collides after Junos normalization with "
                        f'different parameters: "{vpn.proposal_name}"'
                    ),
                    vpn.line_number,
                )
                continue
            logical_external = self.state.interface_ns_to_junos.get(
                gateway.outgoing_interface
            )
            if (
                logical_external is None
                or gateway.outgoing_interface not in self.state.rendered_interfaces
            ):
                self.record_failure(
                    gateway.source_line,
                    (
                        "IKE gateway outgoing interface is undefined or was not rendered: "
                        f'"{gateway.outgoing_interface}"'
                    ),
                    gateway.line_number,
                )
                continue
            logical_bind = None
            if vpn.bind_interface is not None:
                bind_model = self.state.interfaces.get(vpn.bind_interface)
                if (
                    bind_model is None
                    or bind_model.mapping.kind != "tunnel"
                    or vpn.bind_interface not in self.state.rendered_interfaces
                ):
                    self.record_failure(
                        vpn.source_line,
                        (
                            "route-based VPN bind interface must reference a rendered "
                            f'ScreenOS tunnel interface: "{vpn.bind_interface}"'
                        ),
                        vpn.line_number,
                    )
                    continue
                logical_bind = bind_model.mapping.logical_name

            if emitted_ike_fingerprint is None:
                prefix = f"set security ike proposal {ike_proposal.name}"
                self.convert_config(
                    f"{prefix} authentication-method {ike_proposal.authentication_method}"
                )
                self.convert_config(f"{prefix} dh-group {ike_proposal.dh_group}")
                self.convert_config(
                    f"{prefix} authentication-algorithm "
                    f"{ike_proposal.authentication_algorithm}"
                )
                self.convert_config(
                    f"{prefix} encryption-algorithm {ike_proposal.encryption_algorithm}"
                )
                self.convert_config(
                    f"{prefix} lifetime-seconds {ike_proposal.lifetime_seconds}"
                )
                emitted_ike_proposals[ike_proposal.name] = ike_fingerprint

            ike_policy_name = sanity_check_naming(f"{gateway.name}_ike_policy")
            if gateway.name not in emitted_ike_gateways:
                policy_prefix = f"set security ike policy {ike_policy_name}"
                self.convert_config(f"{policy_prefix} mode {gateway.exchange_mode}")
                self.convert_config(f"{policy_prefix} proposals {ike_proposal.name}")
                gateway_prefix = f"set security ike gateway {gateway.name}"
                self.convert_config(f"{gateway_prefix} ike-policy {ike_policy_name}")
                if gateway.endpoint_kind == "address":
                    self.convert_config(f"{gateway_prefix} address {gateway.endpoint}")
                else:
                    identity_type = self._identity_clause(gateway.endpoint)
                    assert identity_type is not None
                    self.convert_config(
                        f"{gateway_prefix} dynamic {identity_type} {gateway.endpoint}"
                    )
                self.convert_config(
                    f"{gateway_prefix} external-interface {logical_external}"
                )
                if gateway.local_id is not None:
                    identity_type = self._identity_clause(gateway.local_id)
                    assert identity_type is not None
                    self.convert_config(
                        f"{gateway_prefix} local-identity {identity_type} "
                        f"{gateway.local_id}"
                    )
                emitted_ike_gateways.add(gateway.name)

            if emitted_ipsec_fingerprint is None:
                prefix = f"set security ipsec proposal {ipsec_proposal.name}"
                self.convert_config(f"{prefix} protocol {ipsec_proposal.protocol}")
                self.convert_config(
                    f"{prefix} authentication-algorithm "
                    f"{ipsec_proposal.authentication_algorithm}"
                )
                self.convert_config(
                    f"{prefix} encryption-algorithm {ipsec_proposal.encryption_algorithm}"
                )
                self.convert_config(
                    f"{prefix} lifetime-seconds {ipsec_proposal.lifetime_seconds}"
                )
                emitted_ipsec_proposals[ipsec_proposal.name] = ipsec_fingerprint

            ipsec_policy_name = sanity_check_naming(f"{vpn.name}_ipsec_policy")
            policy_prefix = f"set security ipsec policy {ipsec_policy_name}"
            self.convert_config(f"{policy_prefix} proposals {ipsec_proposal.name}")
            if ipsec_proposal.pfs_group is not None:
                self.convert_config(
                    f"{policy_prefix} perfect-forward-secrecy keys "
                    f"{ipsec_proposal.pfs_group}"
                )
            vpn_prefix = f"set security ipsec vpn {vpn.name}"
            self.convert_config(f"{vpn_prefix} ike gateway {gateway.name}")
            self.convert_config(f"{vpn_prefix} ike ipsec-policy {ipsec_policy_name}")
            if not vpn.anti_replay:
                self.convert_config(f"{vpn_prefix} ike no-anti-replay")
            if logical_bind is not None:
                self.convert_config(f"{vpn_prefix} bind-interface {logical_bind}")
            if vpn.proxy_local is not None:
                self.convert_config(
                    f"{vpn_prefix} ike proxy-identity local {vpn.proxy_local}"
                )
                self.convert_config(
                    f"{vpn_prefix} ike proxy-identity remote {vpn.proxy_remote}"
                )
                self.convert_config(
                    f"{vpn_prefix} ike proxy-identity service {vpn.proxy_service}"
                )
            self.state.rendered_vpns.add(source_vpn_name)

    _IDP_GROUP_PATTERN: Final[re.Pattern[str]] = re.compile(
        r"^(?P<severity>CRITICAL|HIGH|MEDIUM|LOW|INFO):"
        r"(?:(?P<service>[A-Z0-9_-]+):(?P<kind>SIGS|ANOM))?$",
        re.IGNORECASE,
    )

    def _parse_idp_rule(
        self,
        tokens: list[str],
        index: int,
        line: str,
        line_number: int,
    ) -> tuple[IdpRuleModel, int] | None:
        if (
            index + 3 >= len(tokens)
            or tokens[index].lower() != "attack"
            or tokens[index + 2].lower() != "action"
        ):
            self.record_failure(
                line, "malformed Deep Inspection attachment", line_number
            )
            return None
        attack_group = tokens[index + 1]
        match = self._IDP_GROUP_PATTERN.fullmatch(attack_group)
        if match is None:
            self.record_failure(
                line,
                (
                    f'unmappable ScreenOS attack group: "{attack_group}"; '
                    "no Junos signature substitution was made"
                ),
                line_number,
            )
            return None
        action = {
            "close": "close-client-and-server",
            "close-client": "close-client",
            "close-server": "close-server",
            "drop": "drop-connection",
        }.get(tokens[index + 3].lower())
        if action is None:
            self.record_failure(
                line,
                f"unsupported Deep Inspection action: {tokens[index + 3]}",
                line_number,
            )
            return None
        severity = {
            "critical": "critical",
            "high": "major",
            "medium": "minor",
            "low": "warning",
            "info": "info",
        }[match["severity"].lower()]
        kind = match["kind"]
        return (
            IdpRuleModel(
                attack_group=attack_group,
                dynamic_group_name=sanity_check_naming(
                    f"screenos_{attack_group.replace(':', '_')}"
                ),
                service=match["service"].upper() if match["service"] else "",
                severity=severity,
                attack_type=(
                    "signature" if kind and kind.upper() == "SIGS" else "anomaly"
                ),
                action=action,
                log_attacks=True,
                line_number=line_number,
                source_line=line,
            ),
            index + 4,
        )

    def parse_idp_continuation(self, line: str, line_number: int) -> None:
        try:
            tokens = shlex.split(line)
        except ValueError:
            tokens = []
        policy = self.state.current_policy
        if policy is None or not tokens or tokens[0].lower() != "set":
            self.record_failure(
                line,
                "Deep Inspection attachment has no resolvable base policy",
                line_number,
            )
            return
        if policy.scope != "zone" or policy.action != "permit" or policy.tunnel_vpn:
            policy.idp_invalid = True
            self.record_failure(
                line,
                "Deep Inspection requires a zone permit policy without a VPN tunnel action",
                line_number,
            )
            return
        parsed = self._parse_idp_rule(tokens, 1, line, line_number)
        if parsed is None or parsed[1] != len(tokens):
            policy.idp_invalid = True
            if parsed is not None:
                self.record_failure(
                    line,
                    "unsupported Deep Inspection attachment options",
                    line_number,
                )
            return
        policy.idp_rules.append(parsed[0])

    @staticmethod
    def _idp_policy_name(policy: PolicyModel) -> str:
        return sanity_check_naming(
            f"screenos_{policy.source_zone}_{policy.destination_zone}_"
            f"{policy.policy_name}_idp"
        )

    def render_idp(self, ordered_policies: list[PolicyModel]) -> None:
        policies = [
            policy
            for policy in ordered_policies
            if policy.idp_rules
            and not policy.idp_invalid
            and not policy.disabled
            and (policy.scope, policy.policy_id) not in self.state.disabled_policy_keys
        ]
        if not policies:
            return
        self._manual_review(
            "IDP output requires a current Junos signature package and license review; "
            "validate dynamic group membership, actions, and policy attachment before deployment."
        )
        if len(policies) > 1:
            self.convert_config(
                f"set security idp default-policy {self._idp_policy_name(policies[0])}"
            )
        rendered_groups: set[str] = set()
        for policy in policies:
            policy_key = (policy.scope, policy.policy_id)
            idp_policy_name = self._idp_policy_name(policy)
            for index, rule in enumerate(policy.idp_rules, start=1):
                group_prefix = (
                    f"set security idp dynamic-attack-group {rule.dynamic_group_name}"
                )
                if rule.dynamic_group_name not in rendered_groups:
                    self.convert_config(
                        f"{group_prefix} filters severity values {rule.severity}"
                    )
                    if rule.service:
                        self.convert_config(
                            f"{group_prefix} filters service values {rule.service}"
                        )
                        self.convert_config(
                            f"{group_prefix} filters type values {rule.attack_type}"
                        )
                    rendered_groups.add(rule.dynamic_group_name)
                rule_prefix = (
                    f"set security idp idp-policy {idp_policy_name} "
                    f"rulebase-ips rule rule_{index:03d}"
                )
                self.convert_config(
                    f"{rule_prefix} match from-zone {policy.source_zone}"
                )
                self.convert_config(
                    f"{rule_prefix} match to-zone {policy.destination_zone}"
                )
                self.convert_config(f"{rule_prefix} match source-address any")
                self.convert_config(f"{rule_prefix} match destination-address any")
                self.convert_config(f"{rule_prefix} match application default")
                self.convert_config(
                    f"{rule_prefix} match attacks dynamic-attack-groups "
                    f"{rule.dynamic_group_name}"
                )
                self.convert_config(f"{rule_prefix} then action {rule.action}")
                if rule.log_attacks:
                    self.convert_config(f"{rule_prefix} then notification log-attacks")
                self.convert_config(f"{rule_prefix} then severity {rule.severity}")
            self.state.rendered_idp_policies.add(policy_key)

    def parse_policy_line(self, line: str, line_number: int) -> None:
        self.state.current_policy = None
        try:
            tokens = shlex.split(line)
        except ValueError:
            self.record_failure(
                line,
                "malformed or unsupported policy definition",
                line_number,
            )
            return

        if len(tokens) < 4 or tokens[:2] != ["set", "policy"]:
            self.record_failure(
                line,
                "malformed or unsupported policy definition",
                line_number,
            )
            return

        index = 2
        scope = "zone"
        if tokens[index].lower() == "global":
            scope = "global"
            index += 1

        if index < len(tokens) and tokens[index].lower() == "move":
            if (
                len(tokens[index:]) == 4
                and tokens[index + 2].lower() in ("before", "after")
                and tokens[index + 1].isdigit()
                and tokens[index + 3].isdigit()
            ):
                self.state.policy_moves.append(
                    (
                        scope,
                        tokens[index + 1],
                        tokens[index + 2].lower(),
                        tokens[index + 3],
                        line_number,
                        line,
                    )
                )
            else:
                self.record_failure(line, "malformed policy move", line_number)
            return

        if (
            index + 1 >= len(tokens)
            or tokens[index].lower() != "id"
            or not tokens[index + 1].isdigit()
        ):
            self.record_failure(
                line,
                "supported policies require a numeric id",
                line_number,
            )
            return

        policy_id = tokens[index + 1]
        index += 2
        policy_key = (scope, policy_id)

        if index == len(tokens):
            policy = next(
                (
                    candidate
                    for candidate in self.state.policies
                    if candidate.scope == scope and candidate.policy_id == policy_id
                ),
                None,
            )
            if policy is None:
                self.record_failure(
                    line,
                    f"policy context references undefined {scope} policy {policy_id}",
                    line_number,
                )
            else:
                self.state.current_policy = policy
            return

        if tokens[index].lower() == "attack":
            policy = next(
                (
                    candidate
                    for candidate in self.state.policies
                    if candidate.scope == scope and candidate.policy_id == policy_id
                ),
                None,
            )
            if policy is None:
                self.record_failure(
                    line,
                    f"Deep Inspection attachment references undefined {scope} policy {policy_id}",
                    line_number,
                )
                return
            if policy.scope != "zone" or policy.action != "permit" or policy.tunnel_vpn:
                policy.idp_invalid = True
                self.record_failure(
                    line,
                    (
                        "Deep Inspection requires a zone permit policy without "
                        "a VPN tunnel action"
                    ),
                    line_number,
                )
                return
            parsed_idp = self._parse_idp_rule(tokens, index, line, line_number)
            if parsed_idp is None or parsed_idp[1] != len(tokens):
                policy.idp_invalid = True
                if parsed_idp is not None:
                    self.record_failure(
                        line,
                        "unsupported Deep Inspection attachment options",
                        line_number,
                    )
                return
            policy.idp_rules.append(parsed_idp[0])
            self.state.current_policy = policy
            return

        if tokens[index:] == ["disable"]:
            self.state.disabled_policy_keys.add(policy_key)
            self.state.disabled_policy_sources[policy_key] = (line_number, line)
            for policy in self.state.policies:
                if policy.scope == scope and policy.policy_id == policy_id:
                    policy.disabled = True
                    break
            return

        placement = "append"
        before_policy_id = None
        policy_name = policy_id
        while index < len(tokens):
            option = tokens[index].lower()
            if option == "top":
                placement = "top"
                index += 1
            elif option == "before" and index + 1 < len(tokens):
                if not tokens[index + 1].isdigit():
                    self.record_failure(
                        line,
                        "policy 'before' target must be numeric",
                        line_number,
                    )
                    return
                placement = "before"
                before_policy_id = tokens[index + 1]
                index += 2
            elif option == "name" and index + 1 < len(tokens):
                policy_name = tokens[index + 1]
                index += 2
            else:
                break

        source_zone = None
        destination_zone = None
        if scope == "zone":
            if (
                index + 3 >= len(tokens)
                or tokens[index].lower() != "from"
                or tokens[index + 2].lower() != "to"
            ):
                self.record_failure(
                    line,
                    "malformed or unsupported policy definition",
                    line_number,
                )
                return
            source_zone = self.remember_zone(tokens[index + 1])
            destination_zone = self.remember_zone(tokens[index + 3])
            index += 4

        if index + 3 >= len(tokens):
            self.record_failure(
                line,
                "malformed or unsupported policy definition",
                line_number,
            )
            return

        source_address, destination_address, service = tokens[index : index + 3]
        index += 3

        source_nat_kind = None
        source_nat_dip_id = None
        if index < len(tokens) and tokens[index].lower() == "nat":
            if index + 1 >= len(tokens):
                self.record_failure(line, "malformed policy NAT option", line_number)
                return
            nat_direction = tokens[index + 1].lower()
            if nat_direction != "src":
                self.record_failure(
                    line,
                    (
                        "policy NAT-dst is unsupported; use MIP static NAT "
                        "or migrate the destination mapping manually"
                    ),
                    line_number,
                )
                return
            source_nat_kind = "interface"
            index += 2
            if index < len(tokens) and tokens[index].lower() == "dip-id":
                if index + 1 >= len(tokens):
                    self.record_failure(
                        line,
                        "policy DIP reference requires a numeric id",
                        line_number,
                    )
                    return
                try:
                    source_nat_dip_id = int(tokens[index + 1])
                except ValueError:
                    source_nat_dip_id = -1
                if not 4 <= source_nat_dip_id <= 1023:
                    self.record_failure(
                        line,
                        "policy DIP id must be between 4 and 1023",
                        line_number,
                    )
                    return
                source_nat_kind = "pool"
                index += 2

        if index >= len(tokens):
            self.record_failure(
                line,
                "malformed or unsupported policy definition",
                line_number,
            )
            return
        action_token = tokens[index].lower()
        tunnel_vpn = None
        pair_policy_id = None
        if action_token == "tunnel":
            if index + 2 >= len(tokens) or tokens[index + 1].lower() != "vpn":
                self.record_failure(line, "malformed policy VPN action", line_number)
                return
            action = "permit"
            tunnel_vpn = tokens[index + 2]
            index += 3
            if index < len(tokens) and tokens[index].lower() == "id":
                if index + 1 >= len(tokens):
                    self.record_failure(line, "policy VPN id is missing", line_number)
                    return
                index += 2
            if index < len(tokens) and tokens[index].lower() == "pair-policy":
                if index + 1 >= len(tokens) or not tokens[index + 1].isdigit():
                    self.record_failure(
                        line,
                        "policy VPN pair-policy target must be numeric",
                        line_number,
                    )
                    return
                pair_policy_id = tokens[index + 1]
                index += 2
        elif action_token in ("permit", "deny", "reject"):
            action = action_token
            index += 1
        else:
            self.record_failure(
                line,
                f"unsupported policy action: {tokens[index]}",
                line_number,
            )
            return
        if source_nat_kind is not None and action != "permit":
            self.record_failure(
                line,
                "policy NAT-src requires a permit action",
                line_number,
            )
            return
        if source_nat_kind is not None and tunnel_vpn is not None:
            self.record_failure(
                line,
                "policy-based VPN actions cannot be combined with policy NAT-src",
                line_number,
            )
            return

        log_enabled = False
        count_enabled = False
        idp_rules: list[IdpRuleModel] = []
        idp_invalid = False
        while index < len(tokens):
            option = tokens[index].lower()
            if option == "log":
                log_enabled = True
                index += 1
                if index < len(tokens) and tokens[index].lower() == "session-init":
                    index += 1
                elif index < len(tokens) and tokens[index].lower() == "alert":
                    self.record_failure(
                        line,
                        "policy option 'log alert' has no lossless Junos mapping",
                        line_number,
                    )
                    return
            elif option == "count":
                count_enabled = True
                index += 1
                if index < len(tokens) and tokens[index].lower() == "alarm":
                    self.record_failure(
                        line,
                        "policy count alarms are unsupported",
                        line_number,
                    )
                    return
            elif option == "attack":
                if scope != "zone" or action != "permit" or tunnel_vpn is not None:
                    self.record_failure(
                        line,
                        (
                            "Deep Inspection requires a zone permit policy without "
                            "a VPN tunnel action"
                        ),
                        line_number,
                    )
                    return
                parsed_idp = self._parse_idp_rule(tokens, index, line, line_number)
                if parsed_idp is None:
                    if (
                        index + 3 < len(tokens)
                        and tokens[index + 2].lower() == "action"
                    ):
                        idp_invalid = True
                        index += 4
                        continue
                    return
                idp_rule, index = parsed_idp
                idp_rules.append(idp_rule)
            else:
                self.record_failure(
                    line,
                    f"unsupported policy option: {' '.join(tokens[index:])}",
                    line_number,
                )
                return

        if any(
            policy.scope == scope and policy.policy_id == policy_id
            for policy in self.state.policies
        ):
            self.record_failure(
                line,
                f"duplicate {scope} policy id {policy_id}",
                line_number,
            )
            return

        def reference(name: str) -> PolicyReference:
            return PolicyReference(name, line_number, line)

        policy = PolicyModel(
            scope=scope,
            policy_id=policy_id,
            policy_name=sanity_check_naming(policy_name),
            line_number=line_number,
            source_line=line,
            source_zone=source_zone,
            destination_zone=destination_zone,
            source_addresses=[reference(source_address)],
            destination_addresses=[reference(destination_address)],
            services=[reference(service)],
            action=action,
            placement=placement,
            before_policy_id=before_policy_id,
            log=log_enabled,
            count=count_enabled,
            disabled=policy_key in self.state.disabled_policy_keys,
            tunnel_vpn=tunnel_vpn,
            pair_policy_id=pair_policy_id,
            idp_rules=idp_rules,
            idp_invalid=idp_invalid,
        )
        self.state.policies.append(policy)
        if source_nat_kind is not None:
            self.state.source_nat_rules.append(
                SourceNatRuleModel(
                    policy_scope=scope,
                    policy_id=policy_id,
                    kind=source_nat_kind,
                    dip_id=source_nat_dip_id,
                    line_number=line_number,
                    source_line=line,
                )
            )
        self.state.current_policy = policy

    def _resolve_address(self, name: str, zone: str) -> str | None:
        default = self.state.default_addr.get(name)
        if default is not None:
            return default
        zone_key = zone.lower()
        resolved = self.state.address_objects_by_zone.get((zone_key, name))
        if resolved is not None or zone_key == "global":
            return resolved
        return self.state.address_objects_by_zone.get(("global", name))

    def _resolve_service(self, name: str) -> str | None:
        resolved = self.state.service_dicts.get(name)
        if resolved is not None:
            return resolved
        lowered = name.lower()
        for screenos_name, junos_name in self.state.service_dicts.items():
            if screenos_name.lower() == lowered:
                return junos_name
        return None

    def _ordered_policies(self) -> list[PolicyModel]:
        grouped: dict[tuple[str, str, str], list[PolicyModel]] = {}
        invalid_policy_keys: set[tuple[str, str]] = set()
        for policy in self.state.policies:
            group = grouped.setdefault(policy.context, [])
            if policy.placement == "top":
                group.insert(0, policy)
            else:
                group.append(policy)

        for group in grouped.values():
            for policy in list(group):
                if policy.placement != "before":
                    continue
                target = next(
                    (
                        candidate
                        for candidate in group
                        if candidate.policy_id == policy.before_policy_id
                    ),
                    None,
                )
                if target is None:
                    self.record_failure(
                        policy.source_line,
                        (
                            f"policy {policy.policy_id} references missing before "
                            f"target {policy.before_policy_id}"
                        ),
                        policy.line_number,
                    )
                    invalid_policy_keys.add((policy.scope, policy.policy_id))
                    continue
                group.remove(policy)
                group.insert(group.index(target), policy)

        for (
            scope,
            policy_id,
            direction,
            target_id,
            line_number,
            line,
        ) in self.state.policy_moves:
            source = next(
                (
                    policy
                    for policy in self.state.policies
                    if policy.scope == scope and policy.policy_id == policy_id
                ),
                None,
            )
            target = next(
                (
                    policy
                    for policy in self.state.policies
                    if policy.scope == scope and policy.policy_id == target_id
                ),
                None,
            )
            if (
                source is None
                or target is None
                or source is target
                or source.context != target.context
            ):
                self.record_failure(
                    line,
                    "policy move references an undefined policy or different context",
                    line_number,
                )
                continue
            group = grouped[source.context]
            group.remove(source)
            target_index = group.index(target)
            if direction == "after":
                target_index += 1
            group.insert(target_index, source)

        ordered: list[PolicyModel] = []
        for scope in ("zone", "global"):
            for context, policies in grouped.items():
                if context[0] != scope:
                    continue
                ordered.extend(
                    policy
                    for policy in policies
                    if (policy.scope, policy.policy_id) not in invalid_policy_keys
                )
        return ordered

    def _resolve_address_prefixes(self, name: str, zone: str) -> list[str] | None:
        if name.lower() == "any":
            return ["0.0.0.0/0"]
        zone_key = zone.lower()
        if (zone_key, name) in self.state.non_ip_address_keys:
            return None
        prefixes = self.state.address_prefixes_by_zone.get((zone_key, name))
        if prefixes is not None:
            return prefixes or None
        if zone_key != "global":
            if ("global", name) in self.state.non_ip_address_keys:
                return None
            prefixes = self.state.address_prefixes_by_zone.get(("global", name))
        return prefixes or None

    def _register_mip_address(self, mip: MipModel) -> bool:
        mapped_address = str(ipaddress.ip_network(mip.mapped_prefix).network_address)
        alias = f"MIP({mapped_address})"
        junos_name = sanity_check_naming(f"mip_{mapped_address}")
        owner_key = ("Global", junos_name)
        existing_owner = self.state.address_name_owners.get(owner_key)
        if existing_owner is not None and existing_owner != alias:
            self.record_failure(
                mip.source_line,
                (
                    f'MIP address name "{alias}" collides with '
                    f'"{existing_owner}" after normalization'
                ),
                mip.line_number,
            )
            return False

        self.state.address_name_owners[owner_key] = alias
        self.state.address_objects_by_zone[("global", alias)] = junos_name
        self.state.address_prefixes_by_zone[("global", alias)] = [mip.host_prefix]
        self.convert_config(
            f"set security address-book global address {junos_name} {mip.host_prefix}"
        )
        return True

    def _interface_network_contains(
        self,
        screenos_interface: str,
        address: str,
    ) -> bool:
        model = self.state.interfaces.get(screenos_interface)
        if model is None:
            return False
        parsed_address = ipaddress.ip_address(address)
        return any(
            parsed_address in ipaddress.ip_interface(interface_address).network
            for interface_address in model.ipv4_addresses
        )

    def render_nat(self, ordered_policies: list[PolicyModel]) -> None:
        emitted_static_rule_sets: set[str] = set()
        for mip in self.state.mips:
            logical_interface = self.state.interface_ns_to_junos.get(mip.interface)
            if (
                logical_interface is None
                or mip.interface not in self.state.rendered_interfaces
            ):
                self.record_failure(
                    mip.source_line,
                    f'undefined MIP interface: "{mip.interface}"',
                    mip.line_number,
                )
                continue
            if not self._register_mip_address(mip):
                continue

            rule_set = sanity_check_naming(f"screenos_mip_{logical_interface}")
            mapped_address = str(
                ipaddress.ip_network(mip.mapped_prefix).network_address
            )
            rule = sanity_check_naming(f"mip_{mapped_address}")
            prefix = f"set security nat static rule-set {rule_set} rule {rule}"
            if rule_set not in emitted_static_rule_sets:
                self.convert_config(
                    f"set security nat static rule-set {rule_set} "
                    f"from interface {logical_interface}"
                )
                emitted_static_rule_sets.add(rule_set)
            self.convert_config(
                f"{prefix} match destination-address {mip.mapped_prefix}"
            )
            mapped_vrouter = self.junos_vrouter_name(mip.vrouter)
            translation = f"{prefix} then static-nat prefix {mip.host_prefix}"
            if mapped_vrouter is not None:
                declaration = (
                    f"set routing-instances {mapped_vrouter} "
                    "instance-type virtual-router"
                )
                if declaration not in self.state.converted_config:
                    self.convert_config(declaration)
                translation = f"{translation} routing-instance {mapped_vrouter}"
            self.convert_config(translation)
            mapped_network = ipaddress.ip_network(mip.mapped_prefix)
            if self._interface_network_contains(
                mip.interface,
                str(mapped_network.network_address),
            ) and self._interface_network_contains(
                mip.interface,
                str(mapped_network.broadcast_address),
            ):
                self.convert_config(
                    f"set security nat proxy-arp interface {logical_interface} "
                    f"address {mip.mapped_prefix}"
                )

        valid_pool_ids: set[int] = set()
        for pool in self.state.dip_pools.values():
            logical_interface = self.state.interface_ns_to_junos.get(pool.interface)
            if (
                logical_interface is None
                or pool.interface not in self.state.rendered_interfaces
            ):
                self.record_failure(
                    pool.source_line,
                    f'undefined DIP interface: "{pool.interface}"',
                    pool.line_number,
                )
                continue

            pool_name = f"screenos_dip_{pool.pool_id}"
            if pool.start_address == pool.end_address:
                address_value = f"{pool.start_address}/32"
            else:
                address_value = f"{pool.start_address}/32 to {pool.end_address}/32"
            self.convert_config(
                f"set security nat source pool {pool_name} address {address_value}"
            )
            if pool.fixed_port:
                self.convert_config(
                    f"set security nat source pool {pool_name} port no-translation"
                )
            if self._interface_network_contains(
                pool.interface,
                pool.start_address,
            ) and self._interface_network_contains(
                pool.interface,
                pool.end_address,
            ):
                self.convert_config(
                    f"set security nat proxy-arp interface {logical_interface} "
                    f"address {address_value}"
                )
            valid_pool_ids.add(pool.pool_id)

        rules_by_policy = {
            (rule.policy_scope, rule.policy_id): rule
            for rule in self.state.source_nat_rules
        }
        emitted_source_rule_sets: set[tuple[str, str]] = set()
        for policy in ordered_policies:
            nat_rule = rules_by_policy.get((policy.scope, policy.policy_id))
            if nat_rule is None:
                continue
            if (
                policy.disabled
                or policy.idp_invalid
                or (policy.scope, policy.policy_id) in self.state.disabled_policy_keys
            ):
                continue
            if policy.scope == "global":
                self.record_failure(
                    nat_rule.source_line,
                    (
                        "global policy NAT-src has no explicit Junos "
                        "source/destination zone context"
                    ),
                    nat_rule.line_number,
                )
                continue

            source_zone = policy.source_zone or ""
            destination_zone = policy.destination_zone or ""
            if nat_rule.kind == "pool":
                if nat_rule.dip_id is None or nat_rule.dip_id not in valid_pool_ids:
                    self.record_failure(
                        nat_rule.source_line,
                        f"undefined or unusable DIP pool id {nat_rule.dip_id}",
                        nat_rule.line_number,
                    )
                    continue
                pool = self.state.dip_pools[nat_rule.dip_id]
                pool_interface = self.state.interfaces.get(pool.interface)
                if pool_interface is None or pool_interface.zone != destination_zone:
                    self.record_failure(
                        nat_rule.source_line,
                        (
                            f"DIP pool {nat_rule.dip_id} interface zone does not "
                            f"match policy destination zone {destination_zone}"
                        ),
                        nat_rule.line_number,
                    )
                    continue

            source_prefixes: list[str] = []
            destination_prefixes: list[str] = []
            applications: list[str] = []
            unresolved = False
            for reference in policy.source_addresses:
                prefixes = self._resolve_address_prefixes(
                    reference.name,
                    source_zone,
                )
                if prefixes is None:
                    unresolved = True
                    break
                source_prefixes.extend(
                    prefix for prefix in prefixes if prefix not in source_prefixes
                )
            for reference in policy.destination_addresses:
                prefixes = self._resolve_address_prefixes(
                    reference.name,
                    destination_zone,
                )
                if prefixes is None:
                    unresolved = True
                    break
                destination_prefixes.extend(
                    prefix for prefix in prefixes if prefix not in destination_prefixes
                )
            for reference in policy.services:
                application = self._resolve_service(reference.name)
                if application is None:
                    unresolved = True
                    break
                if application not in applications:
                    applications.append(application)
            if unresolved:
                self.record_failure(
                    nat_rule.source_line,
                    "NAT rule has an unresolved or non-IP policy match",
                    nat_rule.line_number,
                )
                continue

            context = (source_zone, destination_zone)
            rule_set = sanity_check_naming(
                f"screenos_{source_zone}_to_{destination_zone}"
            )
            if context not in emitted_source_rule_sets:
                rule_set_prefix = f"set security nat source rule-set {rule_set}"
                self.convert_config(f"{rule_set_prefix} from zone {source_zone}")
                self.convert_config(f"{rule_set_prefix} to zone {destination_zone}")
                emitted_source_rule_sets.add(context)

            rule_name = sanity_check_naming(
                f"policy_{policy.policy_name}_{policy.policy_id}"
            )
            prefix = f"set security nat source rule-set {rule_set} rule {rule_name}"
            for source_prefix in source_prefixes:
                self.convert_config(f"{prefix} match source-address {source_prefix}")
            for destination_prefix in destination_prefixes:
                self.convert_config(
                    f"{prefix} match destination-address {destination_prefix}"
                )
            for application in applications:
                self.convert_config(f"{prefix} match application {application}")
            if nat_rule.kind == "pool":
                self.convert_config(
                    f"{prefix} then source-nat pool screenos_dip_{nat_rule.dip_id}"
                )
            else:
                self.convert_config(f"{prefix} then source-nat interface")

    def render_policies(
        self,
        ordered_policies: list[PolicyModel] | None = None,
    ) -> None:
        policies = (
            ordered_policies
            if ordered_policies is not None
            else self._ordered_policies()
        )
        policy_name_counts = Counter(
            (policy.context, policy.policy_name)
            for policy in policies
            if not policy.disabled
            and (policy.scope, policy.policy_id) not in self.state.disabled_policy_keys
        )

        def policy_can_render(policy: PolicyModel) -> bool:
            policy_key = (policy.scope, policy.policy_id)
            if (
                policy.disabled
                or policy_key in self.state.disabled_policy_keys
                or policy.idp_invalid
                or policy_name_counts[(policy.context, policy.policy_name)] != 1
            ):
                return False
            source_zone = (
                "global" if policy.scope == "global" else policy.source_zone or ""
            )
            destination_zone = (
                "global" if policy.scope == "global" else policy.destination_zone or ""
            )
            if (
                self._resolve_address(policy.source_addresses[0].name, source_zone)
                is None
                or self._resolve_address(
                    policy.destination_addresses[0].name, destination_zone
                )
                is None
                or self._resolve_service(policy.services[0].name) is None
            ):
                return False
            if policy.idp_rules and policy_key not in self.state.rendered_idp_policies:
                return False
            if policy.tunnel_vpn is not None:
                vpn = self.state.ipsec_vpns.get(policy.tunnel_vpn)
                if (
                    vpn is None
                    or policy.tunnel_vpn not in self.state.rendered_vpns
                    or vpn.bind_interface is not None
                ):
                    return False
            return True

        renderable_policy_keys = {
            (policy.scope, policy.policy_id)
            for policy in policies
            if policy_can_render(policy)
        }
        seen_names: set[tuple[tuple[str, str, str], str]] = set()
        rendered_policy_keys: set[tuple[str, str]] = set()
        for policy in policies:
            policy_key = (policy.scope, policy.policy_id)
            rendered_policy_keys.add(policy_key)
            if policy_key in self.state.disabled_policy_keys or policy.disabled:
                if policy_key not in self.state.reported_disabled_policy_keys:
                    line_number, line = self.state.disabled_policy_sources.get(
                        policy_key,
                        (policy.line_number, policy.source_line),
                    )
                    self.record_failure(
                        line,
                        (
                            f"disabled {policy.scope} policy {policy.policy_id} "
                            "omitted from output"
                        ),
                        line_number,
                    )
                    self.state.reported_disabled_policy_keys.add(policy_key)
                continue
            if policy.idp_invalid:
                continue

            name_key = (policy.context, policy.policy_name)
            if name_key in seen_names:
                self.record_failure(
                    policy.source_line,
                    (
                        f'policy name "{policy.policy_name}" is duplicated in '
                        "the same context"
                    ),
                    policy.line_number,
                )
                continue
            seen_names.add(name_key)

            address_zone_source = (
                "global" if policy.scope == "global" else policy.source_zone or ""
            )
            address_zone_destination = (
                "global" if policy.scope == "global" else policy.destination_zone or ""
            )

            base_source = self._resolve_address(
                policy.source_addresses[0].name,
                address_zone_source,
            )
            base_destination = self._resolve_address(
                policy.destination_addresses[0].name,
                address_zone_destination,
            )
            base_service = self._resolve_service(policy.services[0].name)
            if base_source is None or base_destination is None or base_service is None:
                self.record_failure(
                    policy.source_line,
                    "malformed policy or unresolved object reference",
                    policy.line_number,
                )
                for _, reference in policy.continuations:
                    self.record_failure(
                        reference.source_line,
                        "policy continuation has no resolvable base policy or object",
                        reference.line_number,
                    )
                continue

            if policy.scope == "global":
                prefix = f"set security policies global policy {policy.policy_name}"
            else:
                prefix = (
                    f"set security policies from-zone {policy.source_zone} "
                    f"to-zone {policy.destination_zone} policy {policy.policy_name}"
                )

            tunnel_action = None
            if policy.tunnel_vpn is not None:
                vpn = self.state.ipsec_vpns.get(policy.tunnel_vpn)
                if vpn is None or policy.tunnel_vpn not in self.state.rendered_vpns:
                    self.record_failure(
                        policy.source_line,
                        f'policy references undefined or unrendered VPN: "{policy.tunnel_vpn}"',
                        policy.line_number,
                    )
                    continue
                if vpn.bind_interface is not None:
                    self.record_failure(
                        policy.source_line,
                        "policy tunnel action cannot reference a route-based VPN",
                        policy.line_number,
                    )
                    continue
                tunnel_action = f"{prefix} then permit tunnel ipsec-vpn {vpn.name}"
                if policy.pair_policy_id is not None:
                    pair_policy = next(
                        (
                            candidate
                            for candidate in self.state.policies
                            if candidate.scope == policy.scope
                            and candidate.policy_id == policy.pair_policy_id
                        ),
                        None,
                    )
                    if (
                        pair_policy is None
                        or (pair_policy.scope, pair_policy.policy_id)
                        not in renderable_policy_keys
                        or pair_policy.tunnel_vpn != policy.tunnel_vpn
                        or pair_policy.source_zone != policy.destination_zone
                        or pair_policy.destination_zone != policy.source_zone
                        or pair_policy.pair_policy_id != policy.policy_id
                    ):
                        self.record_failure(
                            policy.source_line,
                            (
                                f"policy VPN pair-policy {policy.pair_policy_id} is "
                                "undefined, uses a different VPN, or is not reciprocal"
                            ),
                            policy.line_number,
                        )
                        continue
                    tunnel_action += f" pair-policy {pair_policy.policy_name}"
            if policy.idp_rules and policy_key not in self.state.rendered_idp_policies:
                self.record_failure(
                    policy.source_line,
                    "policy IDP attachment was not rendered",
                    policy.line_number,
                )
                continue

            self.convert_config(f"{prefix} match source-address {base_source}")
            self.convert_config(
                f"{prefix} match destination-address {base_destination}"
            )
            self.convert_config(f"{prefix} match application {base_service}")
            self.convert_config(tunnel_action or f"{prefix} then {policy.action}")
            if policy.idp_rules:
                self.convert_config(
                    f"{prefix} then permit application-services idp-policy "
                    f"{self._idp_policy_name(policy)}"
                )
            if policy.log:
                self.convert_config(f"{prefix} then log session-init")
                self.convert_config(f"{prefix} then log session-close")
            if policy.count:
                self.convert_config(f"{prefix} then count")

            for match_kind, reference in policy.continuations:
                if match_kind == "source-address":
                    resolved = self._resolve_address(
                        reference.name,
                        address_zone_source,
                    )
                elif match_kind == "destination-address":
                    resolved = self._resolve_address(
                        reference.name,
                        address_zone_destination,
                    )
                else:
                    resolved = self._resolve_service(reference.name)
                if resolved is None:
                    self.record_failure(
                        reference.source_line,
                        "policy continuation has no resolvable base policy or object",
                        reference.line_number,
                    )
                else:
                    self.convert_config(f"{prefix} match {match_kind} {resolved}")

        for policy_key in self.state.disabled_policy_keys - rendered_policy_keys:
            if policy_key in self.state.reported_disabled_policy_keys:
                continue
            line_number, line = self.state.disabled_policy_sources[policy_key]
            self.record_failure(
                line,
                (
                    f"disabled {policy_key[0]} policy {policy_key[1]} "
                    "does not reference a defined policy"
                ),
                line_number,
            )
            self.state.reported_disabled_policy_keys.add(policy_key)

    def multi_line_rule(
        self,
        line: str,
        line_type: str,
        line_number: int | None = None,
    ) -> None:
        try:
            tokens = shlex.split(line)
        except ValueError:
            tokens = []

        policy = self.state.current_policy
        if policy is None or len(tokens) != 3 or tokens[0].lower() != "set":
            self.record_failure(
                line,
                "policy continuation has no resolvable base policy or object",
                line_number,
            )
            return

        reference = PolicyReference(
            name=tokens[2],
            line_number=line_number or policy.line_number,
            source_line=line,
        )
        if line_type == "source-address":
            policy.source_addresses.append(reference)
        elif line_type == "destination-address":
            policy.destination_addresses.append(reference)
        else:
            policy.services.append(reference)
        policy.continuations.append((line_type, reference))

    def disabled_rule_cleanup(self) -> None:
        """Compatibility no-op; deferred policy rendering already omits disabled rules."""
