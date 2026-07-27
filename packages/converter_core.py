"""Core conversion engine for ScreenOS to Junos transformation."""

from __future__ import annotations

import ipaddress
import logging
import re
import shlex
from dataclasses import dataclass, field
from pathlib import Path
from typing import Final

from .conversion_models import (
    InterfaceModel,
    PolicyModel,
    PolicyReference,
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
    address_set_keys: set[tuple[str, str]] = field(default_factory=set)

    interfaces: dict[str, InterfaceModel] = field(default_factory=dict)
    interface_ns_to_junos: dict[str, str] = field(default_factory=dict)
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
        self.combine_dicts("service")
        self.combine_dicts("address")

        for line in MISSING_CONFIG_LINES:
            self.convert_config(line)

        with input_path.open("r", encoding="utf-8", errors="replace") as input_file:
            for linecount, raw_line in enumerate(input_file, start=1):
                line = raw_line.rstrip("\n")

                if linecount % self.progress_interval == 0:
                    LOGGER.info("Parsing line %s", linecount)

                if RE_MULTI_DST.search(line):
                    self.multi_line_rule(line, "destination-address", linecount)
                elif RE_MULTI_SRC.search(line):
                    self.multi_line_rule(line, "source-address", linecount)
                elif RE_MULTI_SVC.search(line):
                    self.multi_line_rule(line, "application", linecount)
                elif RE_POLICY.search(line):
                    self.parse_policy_line(line, linecount)
                else:
                    self.state.current_policy = None
                    if RE_INTERFACE.search(line):
                        self.parse_interface_line(line, linecount)
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
        self.render_policies()
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
        action = tokens[index + 3].lower()
        if action not in ("permit", "deny", "reject"):
            self.record_failure(
                line,
                f"unsupported policy action: {tokens[index + 3]}",
                line_number,
            )
            return
        index += 4

        log_enabled = False
        count_enabled = False
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
        )
        self.state.policies.append(policy)
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

    def render_policies(self) -> None:
        seen_names: set[tuple[tuple[str, str, str], str]] = set()
        rendered_policy_keys: set[tuple[str, str]] = set()
        for policy in self._ordered_policies():
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

            self.convert_config(f"{prefix} match source-address {base_source}")
            self.convert_config(
                f"{prefix} match destination-address {base_destination}"
            )
            self.convert_config(f"{prefix} match application {base_service}")
            self.convert_config(f"{prefix} then {policy.action}")
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
