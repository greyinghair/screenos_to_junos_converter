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


def is_supported_service_definition(line: str) -> bool:
    """Return whether *line* uses the currently supported ScreenOS service grammar."""

    return _SERVICE_PATTERN.fullmatch(line) is not None


def convert_service_in_file(line: str) -> tuple[str, str]:
    """Convert a single ScreenOS service line into a Junos application entry.

    Returns:
        tuple of (`junos_application_name`, `junos_config_line`)

    Raises:
        ValueError: if protocol/ports cannot be parsed from the input line.
    """

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
