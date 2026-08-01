"""Request-scoped in-memory conversion service used by CLI-adjacent clients."""

from __future__ import annotations

from dataclasses import dataclass

from .converter_core import ConversionDiagnostic, Converter


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


def convert_configuration(
    source: str | bytes,
    *,
    max_bytes: int | None = None,
) -> ConversionResult:
    """Convert UTF-8 ScreenOS text using a fresh converter instance."""

    source_text = _decode_source(source, max_bytes)
    converter = Converter(progress_interval=9999)
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
    )
