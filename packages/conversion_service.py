"""Request-scoped in-memory conversion service used by CLI-adjacent clients."""

from __future__ import annotations

from collections.abc import Iterable
from dataclasses import dataclass, field

from .conversion_models import (
    InterfaceMappingError,
    InterfaceMappingRequest,
    ResolvedInterfaceMapping,
    resolve_interface_mappings,
)
from .converter_core import ConversionDiagnostic, Converter
from .interface_inventory import InterfaceInventory, build_interface_inventory


class ConversionInputError(ValueError):
    """Raised when submitted configuration is not safe UTF-8 text."""


class ConfigurationTooLarge(ConversionInputError):
    """Raised when submitted configuration exceeds the configured byte limit."""


@dataclass(frozen=True, slots=True)
class ConversionResult:
    """Immutable output and structured diagnostics for one conversion request."""

    output: str
    converted_count: int
    unsupported_count: int
    diagnostics: tuple[ConversionDiagnostic, ...]
    manual_review_warnings: tuple[str, ...]
    interface_inventory: InterfaceInventory = field(
        default_factory=lambda: InterfaceInventory(interfaces=(), unresolved=())
    )
    applied_interface_mappings: tuple[ResolvedInterfaceMapping, ...] = ()


def _decode_source(source: str | bytes, max_bytes: int | None) -> str:
    if isinstance(source, bytes):
        try:
            text = source.decode("utf-8-sig")
        except UnicodeDecodeError as exc:
            raise ConversionInputError(
                "Configuration must be valid UTF-8 text."
            ) from exc
    elif isinstance(source, str):
        text = source.removeprefix("\ufeff")
    else:
        raise TypeError("Configuration source must be text or bytes.")

    encoded = text.encode("utf-8")
    if max_bytes is not None and len(encoded) > max_bytes:
        raise ConfigurationTooLarge(
            f"Configuration exceeds the {max_bytes}-byte limit."
        )
    if not text.strip():
        raise ConversionInputError("Configuration is empty.")
    if any(ord(character) < 32 and character not in "\t\r\n" for character in text):
        raise ConversionInputError("Configuration contains non-text control bytes.")
    return text


def decode_configuration(source: str | bytes, *, max_bytes: int | None = None) -> str:
    """Validate submitted configuration text without converting it.

    Front ends that echo a submitted configuration back to the user decode it
    once, here, so the size and control-byte rules a conversion enforces are
    applied before the text reaches a template or a second conversion pass.
    """

    return _decode_source(source, max_bytes)


def convert_configuration(
    source: str | bytes,
    *,
    max_bytes: int | None = None,
    interface_mappings: Iterable[InterfaceMappingRequest] | None = None,
) -> ConversionResult:
    """Convert UTF-8 ScreenOS text using a fresh converter instance.

    Interface mappings are optional. They are validated before any conversion
    runs, so invalid or conflicting input is rejected instead of producing
    partially remapped configuration. Without them the converter keeps its
    default ScreenOS-to-Junos interface-name strategy.
    """

    source_text = _decode_source(source, max_bytes)
    try:
        resolved_mappings = resolve_interface_mappings(interface_mappings or ())
    except InterfaceMappingError as exc:
        raise ConversionInputError(f"Invalid interface mapping: {exc}") from exc

    converter = Converter(
        progress_interval=9999,
        interface_mappings=resolved_mappings,
    )
    converter.read_text(source_text)
    converter.disabled_rule_cleanup()
    state = converter.state
    output = "\n".join(state.converted_config)
    if output:
        output += "\n"
    return ConversionResult(
        output=output,
        converted_count=state.succeeded,
        unsupported_count=state.failed,
        diagnostics=tuple(state.diagnostics),
        manual_review_warnings=tuple(state.manual_review_warnings),
        interface_inventory=build_interface_inventory(state),
        applied_interface_mappings=tuple(
            state.applied_interface_mappings[name]
            for name in sorted(state.applied_interface_mappings)
        ),
    )
