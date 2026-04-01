"""Name normalization helpers for Junos-compatible identifiers."""

from __future__ import annotations

import re
from typing import Final

_INVALID_CHARS: Final[str] = ' ./"\'\\!?[]{}|()-+'
_TRANSLATION_TABLE: Final[dict[int, int | str | None]] = str.maketrans(
    {char: "_" for char in _INVALID_CHARS}
)


def sanity_check_naming(name: str) -> str:
    """Normalize ScreenOS object names for Junos compatibility.

    - Replaces common invalid characters with `_`
    - Lowercases output
    - Ensures first character is alphanumeric; strips leading non-alphanumeric chars
    - Returns `unnamed` if normalization empties the value
    """

    normalized = name.translate(_TRANSLATION_TABLE).lower().strip()
    normalized = re.sub(r"^[^a-z0-9]+", "", normalized)
    return normalized or "unnamed"
