from __future__ import annotations

from packages.sanity_check_naming import sanity_check_naming


def test_sanity_check_naming_replaces_invalid_chars() -> None:
    assert sanity_check_naming("TCP - 2348") == "tcp___2348"


def test_sanity_check_naming_trims_non_alnum_prefix() -> None:
    assert sanity_check_naming("..MyName") == "myname"


def test_sanity_check_naming_handles_empty_after_normalization() -> None:
    assert sanity_check_naming("///") == "unnamed"
