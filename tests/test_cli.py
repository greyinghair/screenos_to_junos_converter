from __future__ import annotations

import logging
import sys
from pathlib import Path

from convert import build_output_path, main


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
