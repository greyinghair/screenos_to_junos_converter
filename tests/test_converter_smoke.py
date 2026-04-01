from __future__ import annotations

from pathlib import Path

from packages.converter_core import Converter


def test_converter_smoke(minimal_config_text: str, write_input_file) -> None:
    input_path = write_input_file(minimal_config_text)
    output_path = Path(input_path.parent / "converted_test.txt")

    converter = Converter(progress_interval=9999)
    converter.read_file(input_path)
    converter.disabled_rule_cleanup()
    converter.converted_config_output(output_path)

    output_lines = output_path.read_text(encoding="utf-8").splitlines()

    assert (
        "set applications application tcp_80 protocol tcp destination-port 80"
        in output_lines
    )
    assert (
        "set security policies from-zone Trust to-zone Untrust policy 1 "
        "match source-address src1"
        in output_lines
    )
    assert converter.state.succeeded > 0
