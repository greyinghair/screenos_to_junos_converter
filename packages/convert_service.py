"""Helpers for converting ScreenOS service definitions to Junos applications."""

from __future__ import annotations

import re
from typing import Final

_SERVICE_PATTERN: Final[re.Pattern[str]] = re.compile(
    r'^set\s+service\s+"(?P<name>[^"]+)"\s+(?:protocol|\+)\s+'
    r"(?P<protocol>tcp|udp)\s+src-port\s+(?P<src_start>\d+)-(?P<src_end>\d+)\s+"
    r"dst-port\s+(?P<dst_start>\d+)-(?P<dst_end>\d+)(?:\s+timeout\s+\d+)?\s*$",
    re.IGNORECASE,
)


_ICMP_SERVICE_PATTERN: Final[re.Pattern[str]] = re.compile(
    r'^set\s+service\s+"(?P<name>[^"]+)"\s+(?:protocol|\+)\s+icmp\s+'
    r"type\s+(?P<type>\d+)(?:\s+code\s+(?P<code>\d+))?"
    r"(?:\s+timeout\s+\d+)?\s*$",
    re.IGNORECASE,
)

_PROTOCOL_SERVICE_PATTERN: Final[re.Pattern[str]] = re.compile(
    r'^set\s+service\s+"(?P<name>[^"]+)"\s+(?:protocol|\+)\s+(?P<number>\d{1,3})'
    r"(?:\s+src-port\s+\d+-\d+\s+dst-port\s+\d+-\d+)?"
    r"(?:\s+timeout\s+\d+)?\s*$",
    re.IGNORECASE,
)

# TCP, UDP, and ICMP carry port or type semantics that a bare protocol number
# would discard, so they must use their own service forms.
_PORTED_PROTOCOL_NUMBERS: Final[frozenset[int]] = frozenset({1, 6, 17})


def is_supported_service_definition(line: str) -> bool:
    """Return whether *line* uses the currently supported ScreenOS service grammar."""

    return any(
        pattern.fullmatch(line) is not None
        for pattern in (
            _SERVICE_PATTERN,
            _ICMP_SERVICE_PATTERN,
            _PROTOCOL_SERVICE_PATTERN,
        )
    )


def convert_service_in_file(line: str) -> tuple[str, str]:
    """Convert a single ScreenOS service line into a Junos application entry.

    Returns:
        tuple of (`junos_application_name`, `junos_config_line`)

    Raises:
        ValueError: if protocol/ports cannot be parsed from the input line.
    """

    icmp_match = _ICMP_SERVICE_PATTERN.fullmatch(line)
    if icmp_match:
        return _convert_icmp_service(icmp_match, line)

    protocol_match = _PROTOCOL_SERVICE_PATTERN.fullmatch(line)
    if protocol_match:
        return _convert_protocol_service(protocol_match, line)

    match = _SERVICE_PATTERN.search(line)
    if not match:
        raise ValueError(f"Unable to parse service definition: {line.strip()}")

    protocol = match.group("protocol").lower()
    source_port_start = int(match.group("src_start"))
    source_port_end = int(match.group("src_end"))
    port_start = int(match.group("dst_start"))
    port_end = int(match.group("dst_end"))

    if source_port_start > source_port_end:
        raise ValueError(
            "Invalid source port range "
            f"{source_port_start}-{source_port_end} in: {line.strip()}",
        )

    if port_start > port_end:
        raise ValueError(
            f"Invalid destination port range {port_start}-{port_end} in: {line.strip()}"
        )

    if port_start == port_end:
        junos_app_name = f"{protocol}_{port_start}"
        junos_service = (
            f"set applications application {junos_app_name} "
            f"protocol {protocol} destination-port {port_start}"
        )
        return junos_app_name, junos_service

    junos_app_name = f"{protocol}_{port_start}-{port_end}"
    junos_service = (
        f"set applications application {junos_app_name} "
        f"protocol {protocol} destination-port {port_start}-{port_end}"
    )
    return junos_app_name, junos_service


def _convert_icmp_service(match: re.Match[str], line: str) -> tuple[str, str]:
    """Convert a ScreenOS ICMP service into a Junos ICMP application."""

    icmp_type = int(match.group("type"))
    raw_code = match.group("code")

    if not 0 <= icmp_type <= 255:
        raise ValueError(f"Invalid ICMP type {icmp_type} in: {line.strip()}")

    if raw_code is None:
        junos_app_name = f"icmp_{icmp_type}"
        return junos_app_name, (
            f"set applications application {junos_app_name} "
            f"protocol icmp icmp-type {icmp_type}"
        )

    icmp_code = int(raw_code)
    if not 0 <= icmp_code <= 255:
        raise ValueError(f"Invalid ICMP code {icmp_code} in: {line.strip()}")

    junos_app_name = f"icmp_{icmp_type}_{icmp_code}"
    return junos_app_name, (
        f"set applications application {junos_app_name} "
        f"protocol icmp icmp-type {icmp_type} icmp-code {icmp_code}"
    )


def _convert_protocol_service(match: re.Match[str], line: str) -> tuple[str, str]:
    """Convert a ScreenOS numeric IP-protocol service into a Junos application."""

    protocol_number = int(match.group("number"))

    if not 0 <= protocol_number <= 255:
        raise ValueError(
            f"Invalid IP protocol number {protocol_number} in: {line.strip()}"
        )
    if protocol_number in _PORTED_PROTOCOL_NUMBERS:
        raise ValueError(
            f"IP protocol {protocol_number} requires the named tcp, udp, or icmp "
            f"service form in: {line.strip()}"
        )

    junos_app_name = f"protocol_{protocol_number}"
    return junos_app_name, (
        f"set applications application {junos_app_name} protocol {protocol_number}"
    )
