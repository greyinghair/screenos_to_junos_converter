from __future__ import annotations

import json
import logging
import sys
from pathlib import Path

from convert import build_output_path, main

FIXTURE_ROOT = Path(__file__).parent / "fixtures"


def test_build_output_path_honors_explicit_and_default_locations() -> None:
    assert build_output_path("custom/output.txt") == Path("custom/output.txt")

    generated = build_output_path(None)

    assert generated.parent == Path("outputs")
    assert generated.name.startswith("converted_")
    assert generated.suffix == ".txt"


def test_main_rejects_a_missing_input(
    monkeypatch,
    caplog,
    tmp_path: Path,
) -> None:
    missing_input = tmp_path / "missing.screenos"
    monkeypatch.setattr(
        sys,
        "argv",
        ["convert.py", "--input", str(missing_input)],
    )

    with caplog.at_level(logging.ERROR):
        result = main()

    assert result == 1
    assert f"Input file does not exist: {missing_input}" in caplog.text


def test_main_converts_and_reports_diagnostics(
    monkeypatch,
    caplog,
    tmp_path: Path,
) -> None:
    fixture = Path(__file__).parent / "fixtures" / "end_to_end" / "full.screenos"
    output = tmp_path / "converted.junos"
    monkeypatch.setattr(
        sys,
        "argv",
        [
            "convert.py",
            "--input",
            str(fixture),
            "--output",
            str(output),
            "--log-level",
            "INFO",
        ],
    )

    with caplog.at_level(logging.INFO):
        result = main()

    assert result == 0
    assert output.is_file()
    assert "number of lines converted: 44" in caplog.text
    assert "number of lines NOT converted: 1" in caplog.text
    assert (
        "line 19 not converted: disabled zone policy 200 omitted from output"
        in caplog.text
    )


def test_main_reports_advanced_security_manual_review_warning(
    monkeypatch,
    caplog,
    tmp_path: Path,
) -> None:
    fixture = Path(__file__).parent / "fixtures" / "features" / "idp.screenos"
    output = tmp_path / "idp.junos"
    monkeypatch.setattr(
        sys,
        "argv",
        [
            "convert.py",
            "--input",
            str(fixture),
            "--output",
            str(output),
            "--log-level",
            "INFO",
        ],
    )

    with caplog.at_level(logging.INFO):
        result = main()

    assert result == 0
    assert "MANUAL REVIEW REQUIRED: IDP output requires" in caplog.text


def test_main_applies_an_approved_interface_map(
    monkeypatch,
    caplog,
    tmp_path: Path,
) -> None:
    fixture = FIXTURE_ROOT / "features" / "interface_mapping.screenos"
    mappings = FIXTURE_ROOT / "features" / "interface_mapping.mappings.json"
    output = tmp_path / "mapped.junos"
    monkeypatch.setattr(
        sys,
        "argv",
        [
            "convert.py",
            "--input",
            str(fixture),
            "--output",
            str(output),
            "--interface-map",
            str(mappings),
            "--log-level",
            "INFO",
        ],
    )

    with caplog.at_level(logging.INFO):
        result = main()

    assert result == 0
    assert output.read_text(encoding="utf-8") == (
        FIXTURE_ROOT / "features" / "interface_mapping.junos"
    ).read_text(encoding="utf-8")
    assert (
        "applied interface mapping: ethernet0/0 -> ge-0/0/9.0 (untagged)" in caplog.text
    )


def test_main_rejects_an_invalid_interface_map(
    monkeypatch,
    caplog,
    tmp_path: Path,
) -> None:
    mappings = tmp_path / "mappings.json"
    mappings.write_text(
        json.dumps([{"screenos_name": "ethernet0/0", "physical_name": "wan0"}]),
        encoding="utf-8",
    )
    monkeypatch.setattr(
        sys,
        "argv",
        [
            "convert.py",
            "--input",
            str(FIXTURE_ROOT / "end_to_end" / "full.screenos"),
            "--output",
            str(tmp_path / "converted.junos"),
            "--interface-map",
            str(mappings),
        ],
    )

    with caplog.at_level(logging.ERROR):
        result = main()

    assert result == 1
    assert 'unsupported Junos interface name: "wan0"' in caplog.text
    assert not (tmp_path / "converted.junos").exists()


def test_main_writes_the_interface_inventory_as_json(
    monkeypatch,
    tmp_path: Path,
) -> None:
    inventory_path = tmp_path / "reports" / "inventory.json"
    monkeypatch.setattr(
        sys,
        "argv",
        [
            "convert.py",
            "--input",
            str(FIXTURE_ROOT / "features" / "interface_inventory.screenos"),
            "--output",
            str(tmp_path / "converted.junos"),
            "--interface-inventory",
            str(inventory_path),
        ],
    )

    assert main() == 0

    document = json.loads(inventory_path.read_text(encoding="utf-8"))
    assert [entry["screenos_name"] for entry in document["interfaces"]] == [
        "ethernet0/0",
        "ethernet0/1.100",
        "ethernet0/4",
        "ethernet0/5",
        "tunnel.10",
    ]
    assert document["interfaces"][0]["binding_counts"]["policy"] == 2
    assert document["unresolved"] == []
