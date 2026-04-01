"""Helpers for converting ScreenOS service definitions to Junos applications."""

from __future__ import annotations

import re
from typing import Final

_SERVICE_PATTERN: Final[re.Pattern[str]] = re.compile(
    r"(?:protocol|\+)\s+(tcp|udp)\s+src-port\s+\d+-\d+\s+dst-port\s+(\d+)-(\d+)",
    re.IGNORECASE,
)


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

    protocol = match.group(1).lower()
    port_start = int(match.group(2))
    port_end = int(match.group(3))

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
