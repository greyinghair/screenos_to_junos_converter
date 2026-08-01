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
)

LOGGER = logging.getLogger(__name__)
DEFAULT_MAX_CONFIG_BYTES = 1_048_576
MULTIPART_OVERHEAD_BYTES = 65_536
ALLOWED_UPLOAD_MIME_TYPES = frozenset({"text/plain"})


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
) -> tuple[str, int]:
    return (
        render_template(
            "index.html",
            error=error,
            result=result,
            download_name=download_name,
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
    app = Flask(__name__)
    app.config.from_mapping(
        DEBUG=False,
        MAX_CONFIG_BYTES=max_config_bytes,
        MAX_CONTENT_LENGTH=max_config_bytes + MULTIPART_OVERHEAD_BYTES,
        MAX_FORM_MEMORY_SIZE=max_config_bytes + MULTIPART_OVERHEAD_BYTES,
        MAX_FORM_PARTS=4,
    )
    if test_config:
        app.config.update(test_config)
        if "MAX_CONFIG_BYTES" in test_config:
            configured_limit = int(app.config["MAX_CONFIG_BYTES"])
            if "MAX_CONTENT_LENGTH" not in test_config:
                app.config["MAX_CONTENT_LENGTH"] = (
                    configured_limit + MULTIPART_OVERHEAD_BYTES
                )
            if "MAX_FORM_MEMORY_SIZE" not in test_config:
                app.config["MAX_FORM_MEMORY_SIZE"] = (
                    configured_limit + MULTIPART_OVERHEAD_BYTES
                )
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
        if action not in {"preview", "download"}:
            return _render_index(status=400, error="Invalid conversion action.")

        pasted_text = request.form.get("config_text", "")
        upload = request.files.get("config_file")
        has_paste = bool(pasted_text.strip())
        has_upload = bool(upload and upload.filename)
        if has_paste == has_upload:
            return _render_index(
                status=400,
                error="Provide either pasted configuration or one .txt file.",
            )

        source: str | bytes
        source_name: str | None
        source_kind: str
        if has_upload and upload is not None:
            source_name = upload.filename
            if Path(source_name).suffix.lower() != ".txt":
                return _render_index(
                    status=415,
                    error="Only .txt configuration uploads are supported.",
                )
            if upload.mimetype.lower() not in ALLOWED_UPLOAD_MIME_TYPES:
                return _render_index(
                    status=415,
                    error="The uploaded file must use the text/plain content type.",
                )
            source = upload.stream.read(current_app.config["MAX_CONFIG_BYTES"] + 1)
            source_kind = "upload"
        else:
            source = pasted_text
            source_name = None
            source_kind = "paste"

        try:
            result = convert_configuration(
                source,
                max_bytes=current_app.config["MAX_CONFIG_BYTES"],
            )
        except ConfigurationTooLarge as exc:
            return _render_index(status=413, error=str(exc))
        except ConversionInputError as exc:
            return _render_index(status=400, error=str(exc))
        except Exception as exc:  # Keep submitted configuration out of error logs.
            LOGGER.error(
                "Unexpected conversion failure (%s)",
                type(exc).__name__,
            )
            return _render_index(
                status=500,
                error="The conversion could not be completed.",
            )

        download_name = _safe_download_name(source_name)
        LOGGER.info(
            "Converted %s request: %s emitted, %s unsupported",
            source_kind,
            result.converted_count,
            result.unsupported_count,
        )
        if action == "download":
            return _download_response(result, download_name)
        return _render_index(result=result, download_name=download_name)

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
