from __future__ import annotations

import pytest

from packages.convert_service import convert_service_in_file


def test_convert_service_single_port() -> None:
    line = 'set service "TCP/9200" protocol tcp src-port 0-65535 dst-port 9200-9200'
    app_name, converted = convert_service_in_file(line)
    assert app_name == "tcp_9200"
    assert converted == (
        "set applications application tcp_9200 protocol tcp destination-port 9200"
    )


def test_convert_service_port_range() -> None:
    line = 'set service "TCP/4505-4506" protocol tcp src-port 0-65535 dst-port 4505-4506'
    app_name, converted = convert_service_in_file(line)
    assert app_name == "tcp_4505-4506"
    assert converted == (
        "set applications application tcp_4505-4506 protocol tcp destination-port 4505-4506"
    )


def test_convert_service_invalid_line_raises() -> None:
    line = 'set service "INVALID" timeout 180'
    with pytest.raises(ValueError):
        convert_service_in_file(line)
