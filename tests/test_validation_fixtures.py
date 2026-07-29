from __future__ import annotations

import ipaddress
import re
from pathlib import Path

import pytest

from packages.converter_core import Converter

FIXTURE_ROOT = Path(__file__).parent / "fixtures"


def run_fixture(path: Path) -> Converter:
    converter = Converter(progress_interval=9999)
    converter.read_file(path)
    converter.disabled_rule_cleanup()
    return converter


@pytest.mark.parametrize(
    "feature",
    [
        "services",
        "addresses",
        "policies",
        "global_policies",
        "interfaces",
        "routing",
        "nat",
    ],
)
def test_supported_feature_fixtures_are_exact_and_deterministic(feature: str) -> None:
    input_path = FIXTURE_ROOT / "features" / f"{feature}.screenos"
    expected = (
        (FIXTURE_ROOT / "features" / f"{feature}.junos")
        .read_text(
            encoding="utf-8",
        )
        .splitlines()
    )

    first = run_fixture(input_path)
    second = run_fixture(input_path)

    assert first.state.converted_config == expected
    assert second.state.converted_config == expected
    assert first.state.succeeded == len(expected)
    assert first.state.failed == 0
    assert first.state.diagnostics == []


@pytest.mark.parametrize(
    ("feature", "expected_succeeded"),
    [
        ("services", 3),
        ("addresses", 4),
        ("references", 3),
        ("interfaces", 3),
        ("policies", 5),
        ("routing", 7),
        ("nat", 17),
    ],
)
def test_unsupported_feature_fixtures_report_line_specific_diagnostics(
    feature: str,
    expected_succeeded: int,
) -> None:
    input_path = FIXTURE_ROOT / "negative" / f"{feature}.screenos"
    expected_diagnostics = (
        (FIXTURE_ROOT / "negative" / f"{feature}.diagnostics")
        .read_text(encoding="utf-8")
        .splitlines()
    )

    converter = run_fixture(input_path)
    actual_diagnostics = [
        f"{diagnostic.line_number}|{diagnostic.reason}"
        for diagnostic in converter.state.diagnostics
    ]

    assert actual_diagnostics == expected_diagnostics
    assert converter.state.failed == len(expected_diagnostics)
    assert converter.state.succeeded == expected_succeeded
    assert converter.state.converted_config[:3] == [
        "set applications application udp_161 protocol udp destination-port 161",
        "set applications application-set junos-dns application junos-dns-udp",
        "set applications application-set junos-dns application junos-dns-tcp",
    ]


def test_full_conversion_fixture_validates_output_counts_and_diagnostics() -> None:
    input_path = FIXTURE_ROOT / "end_to_end" / "full.screenos"
    expected = (
        (FIXTURE_ROOT / "end_to_end" / "full.junos")
        .read_text(
            encoding="utf-8",
        )
        .splitlines()
    )

    converter = run_fixture(input_path)

    assert converter.state.converted_config == expected
    assert converter.state.succeeded == len(expected) == 44
    assert converter.state.failed == 1
    assert [
        (diagnostic.line_number, diagnostic.reason)
        for diagnostic in converter.state.diagnostics
    ] == [
        (19, "disabled zone policy 200 omitted from output"),
    ]


def test_fixture_ipv4_values_use_documentation_networks() -> None:
    documentation_networks = (
        ipaddress.ip_network("192.0.2.0/24"),
        ipaddress.ip_network("198.51.100.0/24"),
        ipaddress.ip_network("203.0.113.0/24"),
    )

    for fixture in FIXTURE_ROOT.rglob("*.screenos"):
        values = re.findall(r"\b(?:\d{1,3}\.){3}\d{1,3}\b", fixture.read_text())
        for raw_value in values:
            if raw_value.startswith("255."):
                continue
            try:
                value = ipaddress.ip_address(raw_value)
            except ValueError:
                continue
            if value == ipaddress.ip_address("0.0.0.0"):
                continue
            assert any(value in network for network in documentation_networks), (
                f"{fixture} contains non-documentation IPv4 value {value}"
            )
