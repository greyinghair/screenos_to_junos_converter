"""Core conversion engine for ScreenOS to Junos transformation."""

from __future__ import annotations

import logging
import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Final

from .convert_service import convert_service_in_file
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

DEFAULT_ADDRESS_MAP: Final[dict[str, str]] = {"Any": "any"}
MISSING_CONFIG_LINES: Final[list[str]] = [
    "set applications application udp_161 protocol udp destination-port 161",
    "set applications application-set junos-dns application junos-dns-udp",
    "set applications application-set junos-dns application junos-dns-tcp",
]

RE_MULTI_DST: Final[re.Pattern[str]] = re.compile(r'^set dst-address\s+".+"$')
RE_MULTI_SRC: Final[re.Pattern[str]] = re.compile(r'^set src-address\s+".+"$')
RE_MULTI_SVC: Final[re.Pattern[str]] = re.compile(r'^set service\s+".+"$')
RE_SERVICE_LINE: Final[re.Pattern[str]] = re.compile(r'^set service\s+".+\s(protocol|\+)')
RE_GROUP_SERVICE: Final[re.Pattern[str]] = re.compile(r'^set group service\s+"\S+\sadd')
RE_ADDRESS_LINE: Final[re.Pattern[str]] = re.compile(r'^set address')
RE_GROUP_ADDRESS: Final[re.Pattern[str]] = re.compile(r'^set group address.+add')
RE_POLICY_DISABLE: Final[re.Pattern[str]] = re.compile(r'^set policy id .+\sdisable$')
RE_POLICY: Final[re.Pattern[str]] = re.compile(r'^set policy id.+\s\S')
RE_POLICY_VALID_START: Final[re.Pattern[str]] = re.compile(r'^set policy id \d+ from')


@dataclass(slots=True)
class ConversionState:
    """Mutable conversion state held during a single conversion run."""

    succeeded: int = 0
    failed: int = 0

    default_app: dict[str, str] = field(default_factory=lambda: DEFAULT_APP_MAP.copy())
    default_addr: dict[str, str] = field(default_factory=lambda: DEFAULT_ADDRESS_MAP.copy())

    service_ns_to_junos: dict[str, str] = field(default_factory=dict)
    service_grp_to_app_set: dict[str, str] = field(default_factory=dict)
    service_dicts: dict[str, str] = field(default_factory=dict)

    list_of_zones: list[str] = field(default_factory=list)
    addresses_ns_to_junos: dict[str, str] = field(default_factory=dict)
    address_group_ns_to_junos_address_set: dict[str, str] = field(default_factory=dict)
    address_and_set_dicts: dict[str, str] = field(default_factory=dict)

    multi_rule_params: list[str] = field(default_factory=list)
    converted_config: list[str] = field(default_factory=list)
    disabled_policy_id: set[str] = field(default_factory=set)


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
                    self.multi_line_rule(line, "destination-address")
                elif RE_MULTI_SRC.search(line):
                    self.multi_line_rule(line, "source-address")
                elif RE_MULTI_SVC.search(line):
                    self.multi_line_rule(line, "application")
                elif RE_SERVICE_LINE.search(line):
                    self._parse_service_line(line)
                elif RE_GROUP_SERVICE.search(line):
                    self.create_app_set(line)
                elif RE_ADDRESS_LINE.search(line):
                    self.create_address_book(line)
                elif RE_GROUP_ADDRESS.search(line):
                    self.create_address_set(line)
                elif RE_POLICY_DISABLE.search(line):
                    policy_id = re.findall(r'(\d+)', line)[0]
                    self.state.disabled_policy_id.add(policy_id)
                elif RE_POLICY.search(line):
                    self.create_rule(line)
                else:
                    self.state.failed += 1

    def _parse_service_line(self, line: str) -> None:
        try:
            junos_app_name, converted_line = convert_service_in_file(line)
        except ValueError:
            self.state.failed += 1
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

    def create_app_set(self, line: str) -> None:
        ns_group_name = re.findall(r'"([^"]*)"', line)[0]
        junos_app_set_name = sanity_check_naming(ns_group_name)
        ns_service_member = re.findall(r'"([^"]*)"', line)[1]

        junos_app_name = self.state.service_dicts.get(ns_service_member, "")
        converted_line = (
            f"set applications application-set {junos_app_set_name} application {junos_app_name}"
        ).lower()

        self.state.service_dicts[ns_group_name] = junos_app_set_name.lower()
        self.convert_config(converted_line)

    def zone_name(self, line: str) -> str:
        zone = re.findall(r'"([^"]*)"', line)[0]
        if zone.lower() == "management":
            zone = "System-Management"

        if zone not in self.state.list_of_zones:
            self.state.list_of_zones.append(zone)
        return zone

    def create_address_book(self, original_line: str) -> None:
        line = re.sub(r'\s"([^"]*)"$', '', original_line)

        zone = self.zone_name(line)
        ns_address = re.findall(r'"([^"]*)"', line)[1]
        junos_address_name = sanity_check_naming(ns_address)

        self.state.addresses_ns_to_junos[ns_address] = junos_address_name
        self.combine_dicts("address")

        try:
            intermediate_fqdn_prefix = line.split('"')[4]
            fqdn_prefix = intermediate_fqdn_prefix.split(' ')[1]
        except IndexError:
            self.state.failed += 1
            return

        mask_list = re.findall(r'\d{1,3}(?:\.\d{1,3}){3}$', line)
        mask = ''.join(mask_list)

        if "255" in mask:
            try:
                prefix_cidr = IP(f'{fqdn_prefix}/{mask}', make_net=True)
                converted_line = (
                    f"set security zones security-zone {zone} address-book address "
                    f"{junos_address_name} {prefix_cidr}"
                )
                self.convert_config(converted_line)
            except ValueError:
                self.state.failed += 1
        else:
            try:
                IP(fqdn_prefix, make_net=False)
            except ValueError:
                fqdn = fqdn_prefix.rstrip("\n")
                converted_line = (
                    f"set security zones security-zone {zone} address-book address "
                    f"{junos_address_name} dns-name {fqdn}"
                )
                self.convert_config(converted_line)

    def create_address_set(self, line: str) -> None:
        zone = self.zone_name(line)

        ns_address = re.findall(r'"([^"]*)"', line)[2]
        ns_address_grp = re.findall(r'"([^"]*)"', line)[1]

        junos_address_set = sanity_check_naming(ns_address_grp)
        self.state.address_group_ns_to_junos_address_set[ns_address_grp] = junos_address_set
        self.combine_dicts("address")

        junos_address_name = self.state.address_and_set_dicts.get(ns_address, "")

        if junos_address_name in self.state.address_group_ns_to_junos_address_set:
            converted_line = (
                f"set security zones security-zone {zone} address-book address-set "
                f"{junos_address_set} address-set {junos_address_name}"
            )
        else:
            converted_line = (
                f"set security zones security-zone {zone} address-book address-set "
                f"{junos_address_set} address {junos_address_name}"
            )

        self.convert_config(converted_line)

    def create_rule(self, line: str) -> None:
        try:
            line = re.sub(r'(name\s\"(.+?)\"\s)', '', line)

            if not RE_POLICY_VALID_START.search(line):
                self.state.failed += 1
                return

            src_zone = self.zone_name(re.findall(r'("\S+")', line)[0])
            dst_zone = self.zone_name(re.findall(r'("\S+")', line)[1])
            policy_id = re.findall(r'(\d+)', line)[0]

            self.state.multi_rule_params = [src_zone, dst_zone, policy_id]

            ns_src_addr = re.findall(r'"([^"]*)"', line)[2]
            src_addr = self.state.address_and_set_dicts[ns_src_addr]

            ns_dst_addr = re.findall(r'"([^"]*)"', line)[3]
            dst_addr = self.state.address_and_set_dicts[ns_dst_addr]

            ns_service = re.findall(r'"([^"]*)"', line)[4]
            junos_service = self.state.service_dicts[ns_service]

            action = re.findall(r'\b(permit|deny)', line)[-1]

            rule_params = [
                f'match source-address {src_addr}',
                f'match destination-address {dst_addr}',
                f'match application {junos_service}',
                f'then {action}',
            ]

            for rule_param in rule_params:
                converted_line = (
                    f"set security policies from-zone {src_zone} to-zone {dst_zone} "
                    f"policy {policy_id} {rule_param}"
                )
                self.convert_config(converted_line)

        except (IndexError, KeyError, ValueError):
            self.state.failed += 1

    def multi_line_rule(self, line: str, line_type: str) -> None:
        argument = re.findall(r'"([^"]*)"', line)[0]
        src_dst_or_service = re.findall(r'(.+)', line_type)[0]

        if src_dst_or_service in ("destination-address", "source-address"):
            dict_to_lookup = self.state.address_and_set_dicts
        else:
            dict_to_lookup = self.state.service_dicts

        try:
            converted_line = (
                f"set security policies from-zone {self.state.multi_rule_params[0]} "
                f"to-zone {self.state.multi_rule_params[1]} policy "
                f"{self.state.multi_rule_params[2]} match {src_dst_or_service} "
                f"{dict_to_lookup[argument]}"
            )
            self.convert_config(converted_line)
        except (IndexError, KeyError):
            self.state.failed += 1

    def disabled_rule_cleanup(self) -> None:
        if not self.state.disabled_policy_id:
            return

        removed_count = 0
        disabled_patterns = [
            re.compile(rf'^set security policies.+policy {policy_id}.+')
            for policy_id in self.state.disabled_policy_id
        ]

        kept_lines: list[str] = []
        for line in self.state.converted_config:
            if any(pattern.match(line) for pattern in disabled_patterns):
                removed_count += 1
            else:
                kept_lines.append(line)

        self.state.converted_config = kept_lines
        self.state.succeeded = max(0, self.state.succeeded - removed_count)
        self.state.failed += len(self.state.disabled_policy_id)
