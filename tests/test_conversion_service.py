from __future__ import annotations

from concurrent.futures import ThreadPoolExecutor

import pytest

from packages.conversion_service import (
    ConfigurationTooLarge,
    ConversionInputError,
    convert_configuration,
)
from packages.converter_core import Converter


def test_in_memory_service_matches_converter_for_text_and_bytes(
    minimal_config_text: str,
) -> None:
    converter = Converter(progress_interval=9999)
    converter.read_text(minimal_config_text)
    expected_output = "\n".join(converter.state.converted_config) + "\n"

    text_result = convert_configuration(minimal_config_text)
    bytes_result = convert_configuration(minimal_config_text.encode())

    assert text_result == bytes_result
    assert text_result.output == expected_output
    assert text_result.converted_count == converter.state.succeeded
    assert text_result.unsupported_count == 0
    assert text_result.diagnostics == ()


@pytest.mark.parametrize(
    ("source", "message"),
    [
        ("", "empty"),
        (" \n\t", "empty"),
        (b"\xff\xfe", "valid UTF-8"),
        ("set service\x00bad", "control bytes"),
    ],
)
def test_in_memory_service_rejects_non_text_input(
    source: str | bytes,
    message: str,
) -> None:
    with pytest.raises(ConversionInputError, match=message):
        convert_configuration(source)


def test_in_memory_service_enforces_encoded_byte_limit() -> None:
    with pytest.raises(ConfigurationTooLarge, match="4-byte limit"):
        convert_configuration("ééé", max_bytes=4)


def test_bom_is_normalized_before_the_text_and_byte_limits_are_compared() -> None:
    source = "set unsupported"

    text_result = convert_configuration(f"\ufeff{source}", max_bytes=len(source))
    byte_result = convert_configuration(
        f"\ufeff{source}".encode(),
        max_bytes=len(source),
    )

    assert text_result == byte_result


def test_in_memory_service_returns_structured_diagnostics_and_warnings() -> None:
    result = convert_configuration("set unsupported command")

    assert result.unsupported_count == 1
    assert result.diagnostics[0].line_number == 1
    assert result.diagnostics[0].reason == "unsupported or unrecognized syntax"
    assert result.manual_review_warnings == ()


def test_in_memory_service_has_no_cross_request_state() -> None:
    sources = [
        f'set service "TCP/{port}" protocol tcp src-port 0-65535 dst-port {port}-{port}'
        for port in (8080, 8443)
    ]

    with ThreadPoolExecutor(max_workers=2) as executor:
        results = list(executor.map(convert_configuration, sources))

    assert "tcp_8080" in results[0].output
    assert "tcp_8443" not in results[0].output
    assert "tcp_8443" in results[1].output
    assert "tcp_8080" not in results[1].output
