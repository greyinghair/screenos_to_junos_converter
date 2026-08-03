from __future__ import annotations

import html
import re
from concurrent.futures import ThreadPoolExecutor
from io import BytesIO
from pathlib import Path

import pytest

import packages.web_app as web_app
from packages.conversion_service import convert_configuration
from packages.web_app import create_app


@pytest.fixture
def app():
    return create_app({"TESTING": True, "MAX_CONFIG_BYTES": 4096})


@pytest.fixture
def client(app):
    return app.test_client()


def preview_output(response_text: str) -> str:
    match = re.search(
        r'<textarea id="converted_output"[^>]*>(?P<output>.*?)</textarea>',
        response_text,
        re.DOTALL,
    )
    assert match is not None
    return html.unescape(match["output"])


def test_index_is_production_safe_and_has_security_headers(app, client) -> None:
    response = client.get("/")

    assert response.status_code == 200
    assert app.debug is False
    assert b"Paste configuration" in response.data
    assert response.headers["Cache-Control"] == "no-store"
    assert "frame-ancestors 'none'" in response.headers["Content-Security-Policy"]
    assert response.headers["X-Content-Type-Options"] == "nosniff"


def test_health_check_is_minimal(client) -> None:
    response = client.get("/healthz")

    assert response.status_code == 200
    assert response.get_json() == {"status": "ok"}


def test_paste_and_upload_match_the_shared_service(
    client,
    minimal_config_text: str,
) -> None:
    expected = convert_configuration(minimal_config_text).output

    paste_response = client.post(
        "/convert",
        data={"config_text": minimal_config_text, "action": "preview"},
    )
    upload_response = client.post(
        "/convert",
        data={
            "config_file": (
                BytesIO(minimal_config_text.encode()),
                "sample.txt",
                "text/plain",
            ),
            "action": "preview",
        },
    )

    assert paste_response.status_code == upload_response.status_code == 200
    assert preview_output(paste_response.get_data(as_text=True)) == expected
    assert preview_output(upload_response.get_data(as_text=True)) == expected
    assert b"Unsupported lines</dt><dd>0" in paste_response.data


def test_download_uses_safe_generated_filename(
    client,
    minimal_config_text: str,
) -> None:
    response = client.post(
        "/convert",
        data={
            "config_file": (
                BytesIO(minimal_config_text.encode()),
                "../../branch office.txt",
                "text/plain",
            ),
            "action": "download",
        },
    )

    assert response.status_code == 200
    assert response.data.decode() == convert_configuration(minimal_config_text).output
    assert response.headers["Content-Disposition"] == (
        "attachment; filename=converted_branch_office.txt"
    )
    assert response.headers["X-Content-Type-Options"] == "nosniff"


@pytest.mark.parametrize(
    ("data", "status", "message"),
    [
        ({"action": "preview"}, 400, b"Provide either"),
        (
            {
                "config_text": "set unsupported",
                "config_file": (BytesIO(b"set unsupported"), "input.txt", "text/plain"),
                "action": "preview",
            },
            400,
            b"Provide either",
        ),
        (
            {
                "config_file": (
                    BytesIO(b"set unsupported"),
                    "input.conf",
                    "text/plain",
                ),
                "action": "preview",
            },
            415,
            b"Only .txt",
        ),
        (
            {
                "config_file": (
                    BytesIO(b"set unsupported"),
                    "input.txt",
                    "application/octet-stream",
                ),
                "action": "preview",
            },
            415,
            b"text/plain",
        ),
        (
            {
                "config_file": (BytesIO(b"\xff\xfe"), "input.txt", "text/plain"),
                "action": "preview",
            },
            400,
            b"valid UTF-8",
        ),
        (
            {
                "config_file": (BytesIO(b"set\x00bad"), "input.txt", "text/plain"),
                "action": "preview",
            },
            400,
            b"control bytes",
        ),
    ],
)
def test_rejected_requests_are_safe(client, data, status: int, message: bytes) -> None:
    response = client.post("/convert", data=data)

    assert response.status_code == status
    assert message in response.data


def test_oversized_paste_and_upload_are_rejected() -> None:
    app = create_app({"TESTING": True, "MAX_CONFIG_BYTES": 32})

    with app.test_client() as client:
        boundary_paste_response = client.post(
            "/convert",
            data={"config_text": "x" * 32, "action": "preview"},
        )
        boundary_upload_response = client.post(
            "/convert",
            data={
                "config_file": (BytesIO(b"x" * 32), "input.txt", "text/plain"),
                "action": "preview",
            },
        )
        paste_response = client.post(
            "/convert",
            data={"config_text": "x" * 33, "action": "preview"},
        )
        upload_response = client.post(
            "/convert",
            data={
                "config_file": (BytesIO(b"x" * 33), "input.txt", "text/plain"),
                "action": "preview",
            },
        )

    assert boundary_paste_response.status_code == 200
    assert boundary_upload_response.status_code == 200
    assert paste_response.status_code == 413
    assert upload_response.status_code == 413


def test_malformed_config_is_reported_without_becoming_a_server_error(client) -> None:
    response = client.post(
        "/convert",
        data={"config_text": "set unsupported command", "action": "preview"},
    )

    assert response.status_code == 200
    assert b"Unsupported lines</dt><dd>1" in response.data
    assert b"unsupported or unrecognized syntax" in response.data


def test_manual_review_warnings_are_shown(client) -> None:
    source = (
        Path(__file__).parent / "fixtures" / "features" / "ipsec_vpn.screenos"
    ).read_text(encoding="utf-8")

    response = client.post(
        "/convert",
        data={"config_text": source, "action": "preview"},
    )

    assert response.status_code == 200
    assert b"Manual review required" in response.data
    assert b"agreed with the owner of the remote peer" in response.data


def test_unexpected_failure_does_not_log_or_return_submitted_configuration(
    client,
    monkeypatch,
    caplog,
) -> None:
    secret_source = "set admin password super-secret-value"

    def fail_safely(_source, *, max_bytes):
        raise ValueError(f"parser failed on {secret_source} at {max_bytes}")

    monkeypatch.setattr(web_app, "convert_configuration", fail_safely)
    response = client.post(
        "/convert",
        data={"config_text": secret_source, "action": "preview"},
    )

    assert response.status_code == 500
    assert secret_source.encode() not in response.data
    assert secret_source not in caplog.text
    assert "Unexpected conversion failure (ValueError)" in caplog.text


def test_preview_escapes_generated_configuration(client) -> None:
    source = "\n".join(
        [
            'set interface ethernet0/0 zone "Untrust"',
            'set interface ethernet0/0 description "<script>alert(1)</script>"',
        ]
    )

    response = client.post(
        "/convert",
        data={"config_text": source, "action": "preview"},
    )

    assert response.status_code == 200
    assert b"<script>alert(1)</script>" not in response.data
    assert b"&lt;script&gt;alert(1)&lt;/script&gt;" in response.data


def test_concurrent_web_requests_do_not_share_converter_state() -> None:
    app = create_app({"TESTING": True, "MAX_CONFIG_BYTES": 4096})

    def submit(port: int) -> str:
        source = (
            f'set service "TCP/{port}" protocol tcp src-port 0-65535 '
            f"dst-port {port}-{port}"
        )
        with app.test_client() as request_client:
            response = request_client.post(
                "/convert",
                data={"config_text": source, "action": "preview"},
            )
        assert response.status_code == 200
        return preview_output(response.get_data(as_text=True))

    with ThreadPoolExecutor(max_workers=2) as executor:
        outputs = list(executor.map(submit, (8080, 8443)))

    assert "tcp_8080" in outputs[0] and "tcp_8443" not in outputs[0]
    assert "tcp_8443" in outputs[1] and "tcp_8080" not in outputs[1]
