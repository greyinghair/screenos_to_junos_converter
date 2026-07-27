from __future__ import annotations

import pytest

from packages.convert_service import (
    convert_service_in_file,
    is_supported_service_definition,
)


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


def test_convert_service_accepts_timeout_and_case_insensitive_protocol() -> None:
    line = (
        'set service "DNS Alternative" protocol UDP src-port 0-65535 '
        'dst-port 5353-5353 timeout 180'
    )

    app_name, converted = convert_service_in_file(line)

    assert app_name == "udp_5353"
    assert converted == (
        "set applications application udp_5353 protocol udp destination-port 5353"
    )
    assert is_supported_service_definition(line)


def test_convert_service_rejects_reversed_source_port_range() -> None:
    line = 'set service "INVALID" protocol tcp src-port 20-10 dst-port 443-443'

    with pytest.raises(ValueError, match="source port range"):
        convert_service_in_file(line)


def test_service_grammar_rejects_unbounded_trailing_tokens() -> None:
    line = 'set service "HTTP" protocol tcp src-port 0-65535 dst-port 80-80 extra'

    assert not is_supported_service_definition(line)
