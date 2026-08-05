"""Flask application for request-scoped ScreenOS configuration conversion."""

from __future__ import annotations

import logging
import os
from io import BytesIO
from pathlib import Path
from typing import Any

from flask import Flask, Response, current_app, render_template, request, send_file
from werkzeug.exceptions import RequestEntityTooLarge
from werkzeug.utils import secure_filename

from .conversion_service import (
    ConfigurationTooLarge,
    ConversionInputError,
    ConversionResult,
    convert_configuration,
    decode_configuration,
)
from .mapping_workspace import (
    MAX_WORKSPACE_ROWS,
    VLAN_CHOICES,
    MappingWorkspace,
    build_workspace,
    conversion_flow,
    has_mapping_form,
    parse_mapping_form,
)

LOGGER = logging.getLogger(__name__)
DEFAULT_MAX_CONFIG_BYTES = 1_048_576
MULTIPART_OVERHEAD_BYTES = 65_536
# The mapping workspace posts five short controls per discovered interface
# alongside the configuration, so the request budget allows for them.
MAPPING_FIELDS_PER_ROW = 5
MAPPING_FORM_OVERHEAD_BYTES = 131_072
MAPPING_FORM_PARTS = MAPPING_FIELDS_PER_ROW * MAX_WORKSPACE_ROWS
BASE_FORM_PARTS = 4
ALLOWED_UPLOAD_MIME_TYPES = frozenset({"text/plain"})
CONVERSION_ACTIONS = frozenset({"map", "preview", "download"})


def _configured_byte_limit() -> int:
    raw_value = os.environ.get("SCREENOS_MAX_CONFIG_BYTES")
    if raw_value is None:
        return DEFAULT_MAX_CONFIG_BYTES
    try:
        value = int(raw_value)
    except ValueError as exc:
        raise RuntimeError("SCREENOS_MAX_CONFIG_BYTES must be an integer.") from exc
    if value < 1:
        raise RuntimeError("SCREENOS_MAX_CONFIG_BYTES must be positive.")
    return value


class _RequestRejected(Exception):
    """A submitted request that never reaches the converter."""

    def __init__(self, status: int, message: str) -> None:
        super().__init__(message)
        self.status = status
        self.message = message


def _conversion_error_response(exc: Exception) -> tuple[str, int]:
    if isinstance(exc, ConfigurationTooLarge):
        return _render_index(status=413, error=str(exc))
    if isinstance(exc, ConversionInputError):
        return _render_index(status=400, error=str(exc))
    # Keep submitted configuration out of error logs.
    LOGGER.error("Unexpected conversion failure (%s)", type(exc).__name__)
    return _render_index(status=500, error="The conversion could not be completed.")


def _read_submitted_configuration() -> tuple[str, str | None, str]:
    """Decode the pasted or uploaded configuration for this request.

    Returns the validated text, the upload name it came from, and which of the
    two input paths was used. The text is decoded once here because the
    workspace echoes it back to the page and may convert it twice.
    """

    max_bytes = current_app.config["MAX_CONFIG_BYTES"]
    pasted_text = request.form.get("config_text", "")
    upload = request.files.get("config_file")
    has_paste = bool(pasted_text.strip())
    has_upload = bool(upload and upload.filename)
    if has_paste == has_upload:
        raise _RequestRejected(
            400,
            "Provide either pasted configuration or one .txt file.",
        )

    source: str | bytes
    source_name: str | None
    source_kind: str
    if has_upload and upload is not None:
        source_name = upload.filename
        if Path(source_name).suffix.lower() != ".txt":
            raise _RequestRejected(
                415,
                "Only .txt configuration uploads are supported.",
            )
        if upload.mimetype.lower() not in ALLOWED_UPLOAD_MIME_TYPES:
            raise _RequestRejected(
                415,
                "The uploaded file must use the text/plain content type.",
            )
        source = upload.stream.read(max_bytes + 1)
        source_kind = "upload"
    else:
        source = pasted_text
        source_name = None
        source_kind = "paste"

    try:
        config_text = decode_configuration(source, max_bytes=max_bytes)
    except ConfigurationTooLarge as exc:
        raise _RequestRejected(413, str(exc)) from exc
    except ConversionInputError as exc:
        raise _RequestRejected(400, str(exc)) from exc
    return config_text, source_name, source_kind


def _safe_download_name(source_name: str | None) -> str:
    safe_source = secure_filename(source_name or "screenos.txt")
    stem = Path(safe_source).stem[:80] or "screenos"
    return f"converted_{stem}.txt"


def _render_index(
    *,
    status: int = 200,
    error: str | None = None,
    result: ConversionResult | None = None,
    download_name: str | None = None,
    workspace: MappingWorkspace | None = None,
    config_text: str = "",
) -> tuple[str, int]:
    return (
        render_template(
            "index.html",
            error=error,
            result=result,
            download_name=download_name,
            workspace=workspace,
            config_text=config_text,
            flow=conversion_flow(workspace=workspace, result=result, error=error),
            vlan_choices=VLAN_CHOICES,
            max_config_bytes=current_app.config["MAX_CONFIG_BYTES"],
        ),
        status,
    )


def _download_response(result: ConversionResult, download_name: str) -> Response:
    return send_file(
        BytesIO(result.output.encode("utf-8")),
        mimetype="text/plain; charset=utf-8",
        as_attachment=True,
        download_name=download_name,
        max_age=0,
    )


def create_app(test_config: dict[str, Any] | None = None) -> Flask:
    """Create an isolated Flask application with production-safe defaults."""

    max_config_bytes = _configured_byte_limit()
    request_overhead = MULTIPART_OVERHEAD_BYTES + MAPPING_FORM_OVERHEAD_BYTES
    app = Flask(__name__)
    app.config.from_mapping(
        DEBUG=False,
        MAX_CONFIG_BYTES=max_config_bytes,
        MAX_CONTENT_LENGTH=max_config_bytes + request_overhead,
        MAX_FORM_MEMORY_SIZE=max_config_bytes + request_overhead,
        MAX_FORM_PARTS=BASE_FORM_PARTS + MAPPING_FORM_PARTS,
    )
    if test_config:
        app.config.update(test_config)
        if "MAX_CONFIG_BYTES" in test_config:
            configured_limit = int(app.config["MAX_CONFIG_BYTES"])
            if "MAX_CONTENT_LENGTH" not in test_config:
                app.config["MAX_CONTENT_LENGTH"] = configured_limit + request_overhead
            if "MAX_FORM_MEMORY_SIZE" not in test_config:
                app.config["MAX_FORM_MEMORY_SIZE"] = configured_limit + request_overhead
    app.config["DEBUG"] = False

    @app.after_request
    def apply_security_headers(response: Response) -> Response:
        response.headers["Cache-Control"] = "no-store"
        response.headers["Content-Security-Policy"] = (
            "default-src 'self'; base-uri 'none'; frame-ancestors 'none'; "
            "form-action 'self'"
        )
        response.headers["Referrer-Policy"] = "no-referrer"
        response.headers["X-Content-Type-Options"] = "nosniff"
        response.headers["X-Frame-Options"] = "DENY"
        return response

    @app.get("/")
    def index() -> tuple[str, int]:
        return _render_index()

    @app.get("/healthz")
    def health() -> dict[str, str]:
        return {"status": "ok"}

    @app.post("/convert")
    def convert() -> Response | tuple[str, int]:
        action = request.form.get("action", "preview")
        if action not in CONVERSION_ACTIONS:
            return _render_index(status=400, error="Invalid conversion action.")

        try:
            config_text, source_name, source_kind = _read_submitted_configuration()
        except _RequestRejected as rejection:
            return _render_index(status=rejection.status, error=rejection.message)

        # The mapping workspace needs the discovered interfaces of the submitted
        # configuration before any approved mapping can be resolved, so a
        # submission that carries mappings converts twice: once to discover,
        # once to render the approved result.
        try:
            discovery = convert_configuration(
                config_text,
                max_bytes=current_app.config["MAX_CONFIG_BYTES"],
            )
        except Exception as exc:
            return _conversion_error_response(exc)

        workspace = (
            parse_mapping_form(discovery.interface_inventory, request.form)
            if has_mapping_form(request.form)
            else build_workspace(discovery.interface_inventory)
        )

        if action == "map":
            LOGGER.info(
                "Discovered %s request: %s interfaces, %s unresolved references",
                source_kind,
                workspace.total,
                len(workspace.unresolved),
            )
            return _render_index(workspace=workspace, config_text=config_text)

        if not workspace.is_valid:
            invalid = workspace.invalid_count
            subject = "mapping needs" if invalid == 1 else "mappings need"
            return _render_index(
                status=400,
                error=(
                    f"{invalid} interface {subject} correcting before this "
                    "configuration can be converted."
                ),
                workspace=workspace,
                config_text=config_text,
            )

        result = discovery
        if workspace.requests:
            try:
                result = convert_configuration(
                    config_text,
                    max_bytes=current_app.config["MAX_CONFIG_BYTES"],
                    interface_mappings=workspace.requests,
                )
            except Exception as exc:
                return _conversion_error_response(exc)
            if action != "download":
                # Rebuild the rows against the converted inventory so each card
                # reports the destination the applied mapping actually reached.
                workspace = build_workspace(
                    result.interface_inventory,
                    selections=workspace.selections,
                    submitted=True,
                )

        download_name = _safe_download_name(source_name)
        LOGGER.info(
            "Converted %s request: %s emitted, %s unsupported, %s remapped interfaces",
            source_kind,
            result.converted_count,
            result.unsupported_count,
            len(result.applied_interface_mappings),
        )
        if action == "download":
            return _download_response(result, download_name)
        return _render_index(
            result=result,
            download_name=download_name,
            workspace=workspace,
            config_text=config_text,
        )

    @app.errorhandler(RequestEntityTooLarge)
    def request_too_large(_error: RequestEntityTooLarge) -> tuple[str, int]:
        return _render_index(
            status=413,
            error="The submitted request exceeds the configured size limit.",
        )

    @app.errorhandler(500)
    def internal_error(error: Exception) -> tuple[str, int]:
        LOGGER.error(
            "Unhandled conversion request failure (%s)",
            type(error).__name__,
        )
        return _render_index(
            status=500,
            error="The conversion could not be completed.",
        )

    return app
