from __future__ import annotations

from pathlib import Path

import pytest


@pytest.fixture
def minimal_config_text() -> str:
    return "\n".join(
        [
            'set service "TCP/80" protocol tcp src-port 0-65535 dst-port 80-80',
            'set address "Trust" "SRC1" 192.0.2.1 255.255.255.255',
            'set address "Untrust" "DST1" 198.51.100.1 255.255.255.255',
            'set policy id 1 from "Trust" to "Untrust"  "SRC1" "DST1" "TCP/80" permit',
        ]
    )


@pytest.fixture
def write_input_file(tmp_path: Path):
    def _write(contents: str, name: str = "netscreen_config.txt") -> Path:
        path = tmp_path / name
        path.write_text(contents + "\n", encoding="utf-8")
        return path

    return _write
