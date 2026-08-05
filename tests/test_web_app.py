from __future__ import annotations

import html
import json
import logging
import re
from concurrent.futures import ThreadPoolExecutor
from io import BytesIO
from pathlib import Path

import pytest

import packages.web_app as web_app
from packages.conversion_service import convert_configuration
from packages.mapping_workspace import MAX_WORKSPACE_ROWS
from packages.web_app import create_app

FIXTURE_ROOT = Path(__file__).parent / "fixtures"


@pytest.fixture
def app():
    return create_app({"TESTING": True, "MAX_CONFIG_BYTES": 4096})


@pytest.fixture
def client(app):
    return app.test_client()


def fixture_text(stem: str, suffix: str, directory: str = "features") -> str:
    return (FIXTURE_ROOT / directory / f"{stem}.{suffix}").read_text(encoding="utf-8")


def mapping_form(stem: str, directory: str = "features") -> dict[str, str]:
    return json.loads(fixture_text(stem, "form.json", directory))


def preview_output(response_text: str) -> str:
    match = re.search(
        r'<textarea id="converted_output"[^>]*>(?P<output>.*?)</textarea>',
        response_text,
        re.DOTALL,
    )
    assert match is not None
    return html.unescape(match["output"])


def workspace_section(response_text: str) -> str:
    match = re.search(
        r'<section class="workspace".*?</section>',
        response_text,
        re.DOTALL,
    )
    assert match is not None
    return match[0]


def field_errors(response_text: str) -> list[str]:
    return [
        " ".join(html.unescape(re.sub(r"<[^>]+>", " ", fragment)).split())
        for fragment in re.findall(
            r'<span class="field-error".*?</span>',
            response_text,
            re.DOTALL,
        )
    ]


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
    assert b"omitted preshared keys" in response.data


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


def test_preview_renders_the_interface_inventory_for_each_interface(client) -> None:
    source = (
        Path(__file__).parent / "fixtures" / "features" / "interface_inventory.screenos"
    ).read_text(encoding="utf-8")

    response = client.post(
        "/convert",
        data={"config_text": source, "action": "preview"},
    )
    body = response.get_data(as_text=True)

    assert response.status_code == 200
    assert "<summary>Interface inventory (5)</summary>" in body
    assert (
        "<caption>Every ScreenOS interface and the configuration bound to it</caption>"
        in body
    )
    assert '<th scope="col">Junos interface</th>' in body
    assert '<th scope="row">ethernet0/1.100</th>' in body
    assert "ge-0/0/1.100" in body
    assert "MIP 198.51.100.30/32 to host 192.0.2.10/32" in body
    # An interface with nothing bound to it still gets an explicit row.
    assert "No detected bindings" in body


def test_preview_escapes_inventory_source_context(client) -> None:
    source = "\n".join(
        [
            'set interface ethernet0/0 zone "Untrust"',
            'set interface ethernet0/0 monitor "<script>alert(1)</script>"',
        ]
    )

    response = client.post(
        "/convert",
        data={"config_text": source, "action": "preview"},
    )
    body = response.get_data(as_text=True)

    assert response.status_code == 200
    assert "<script>alert(1)</script>" not in body
    assert "&lt;script&gt;alert(1)&lt;/script&gt;" in body


def test_paste_and_upload_reach_the_same_mapping_workspace(client) -> None:
    source = fixture_text("mapping_workspace", "screenos")

    pasted = client.post("/convert", data={"config_text": source, "action": "map"})
    uploaded = client.post(
        "/convert",
        data={
            "config_file": (BytesIO(source.encode()), "branch.txt", "text/plain"),
            "action": "map",
        },
    )

    assert pasted.status_code == uploaded.status_code == 200
    pasted_workspace = workspace_section(pasted.get_data(as_text=True))
    assert pasted_workspace == workspace_section(uploaded.get_data(as_text=True))
    assert "Interface mapping workspace" in pasted_workspace
    # The discovered bindings are on the page before any mapping is committed.
    assert "Discovered bindings (3)" in pasted_workspace
    assert "static route 0.0.0.0/0 in trust-vr" in pasted_workspace
    assert 'placeholder="Keep ge-0/0/1.100"' in pasted_workspace
    for index, name in enumerate(("ethernet0/0", "ethernet0/1.100", "tunnel.1")):
        assert f'name="mapping-source-{index}" value="{name}"' in pasted_workspace


def test_discovery_does_not_convert_or_leak_the_configuration_into_logs(
    client,
    caplog,
) -> None:
    source = fixture_text("mapping_workspace", "screenos")

    with caplog.at_level(logging.INFO, logger="packages.web_app"):
        response = client.post(
            "/convert",
            data={"config_text": source, "action": "map"},
        )
    body = response.get_data(as_text=True)

    assert response.status_code == 200
    assert 'id="converted_output"' not in body
    assert "Discovered paste request: 3 interfaces" in caplog.text
    assert "ethernet0/1.100" not in caplog.text


def test_submitted_mapping_is_applied_to_the_conversion(client) -> None:
    source = fixture_text("mapping_workspace", "screenos")
    expected_applied = fixture_text("mapping_workspace", "applied").splitlines()
    data = {**mapping_form("mapping_workspace"), "config_text": source}

    response = client.post("/convert", data={**data, "action": "preview"})
    body = response.get_data(as_text=True)
    output = preview_output(body)

    assert response.status_code == 200
    for applied in expected_applied:
        assert f"# Applied interface mapping: {applied}" in output
    assert "set security zones security-zone Untrust interfaces ge-0/0/9.0" in output
    assert "set interfaces xe-2/0/1 unit 7 vlan-id 100" in output
    assert "set routing-options static route 0.0.0.0/0 next-hop" in output
    assert "ge-0/0/0" not in output
    # The workspace stays on the page with the choices that produced the output.
    workspace = workspace_section(body)
    assert 'value="xe-2/0/1"' in workspace
    assert workspace.count('class="badge badge-mapped"') == 3
    assert workspace.count("Mapped") == 3


def test_mapped_download_matches_the_shared_service(client) -> None:
    source = fixture_text("mapping_workspace", "screenos")
    data = {**mapping_form("mapping_workspace"), "config_text": source}

    preview = client.post("/convert", data={**data, "action": "preview"})
    download = client.post("/convert", data={**data, "action": "download"})

    assert download.status_code == 200
    assert download.headers["Content-Disposition"] == (
        "attachment; filename=converted_screenos.txt"
    )
    assert download.data.decode() == preview_output(preview.get_data(as_text=True))


def test_invalid_mappings_block_conversion_and_are_reported_inline(client) -> None:
    source = fixture_text("mapping_workspace", "screenos", "negative")
    data = {
        **mapping_form("mapping_workspace", "negative"),
        "config_text": source,
        "action": "preview",
    }

    response = client.post("/convert", data=data)
    body = response.get_data(as_text=True)

    assert response.status_code == 400
    assert "3 interface mappings need correcting" in body
    assert 'id="converted_output"' not in body
    assert field_errors(body) == [
        '"ethernet0/2" and "ethernet0/0" both map to ge-0/0/1.0',
        "Enter the VLAN ID to tag this unit with, between 1 and 4094.",
        '"tunnel.1" maps to st0, which does not accept a VLAN tag',
    ]
    # Every submitted choice survives the rejection.
    workspace = workspace_section(body)
    reused = re.findall(
        r'name="mapping-destination-\d+"[^>]*value="ge-0/0/1"',
        workspace,
        re.DOTALL,
    )
    assert len(reused) == 2
    assert 'value="st0"' in workspace
    assert '<option value="tagged" selected>' in workspace
    assert 'data-blocks-conversion="true"' in workspace
    assert body.count('aria-invalid="true"') == 3


def test_an_unmapped_workspace_converts_exactly_like_a_direct_submission(
    client,
    minimal_config_text: str,
) -> None:
    direct = client.post(
        "/convert",
        data={"config_text": minimal_config_text, "action": "preview"},
    )
    through_workspace = client.post(
        "/convert",
        data={
            "config_text": minimal_config_text,
            "mapping-count": "0",
            "action": "preview",
        },
    )

    expected = convert_configuration(minimal_config_text).output

    assert direct.status_code == through_workspace.status_code == 200
    assert preview_output(direct.get_data(as_text=True)) == expected
    assert preview_output(through_workspace.get_data(as_text=True)) == expected


def test_an_empty_inventory_reports_its_own_state(client, minimal_config_text) -> None:
    response = client.post(
        "/convert",
        data={"config_text": minimal_config_text, "action": "map"},
    )
    body = response.get_data(as_text=True)

    assert response.status_code == 200
    assert "No interfaces were discovered in this configuration" in body
    assert "No interfaces discovered" in body
    assert "Nothing to map" in body
    assert 'data-blocks-conversion="true"' not in body


def test_a_stale_mapping_is_reported_rather_than_silently_dropped(client) -> None:
    response = client.post(
        "/convert",
        data={
            "config_text": fixture_text("mapping_workspace", "screenos"),
            "mapping-count": "1",
            "mapping-source-0": "ethernet0/9",
            "mapping-destination-0": "ge-0/0/9",
            "action": "preview",
        },
    )
    body = response.get_data(as_text=True)

    assert response.status_code == 400
    assert "ethernet0/9" in body
    assert (
        '"ethernet0/9" is not defined in the submitted configuration'
        in html.unescape(body)
    )


def test_the_flow_graphic_reports_each_stage_without_javascript(client) -> None:
    landing = client.get("/").get_data(as_text=True)
    discovered = client.post(
        "/convert",
        data={
            "config_text": fixture_text("mapping_workspace", "screenos"),
            "action": "map",
        },
    ).get_data(as_text=True)

    assert '<h2 id="flow-heading" class="visually-hidden">Conversion progress</h2>' in (
        landing
    )
    assert landing.count('class="flow-step is-pending"') == 3
    assert "Paste or upload a configuration" in landing
    assert "3 interfaces, 6 bindings" in discovered
    assert '<span class="flow-status">Needs attention</span>' not in discovered
    # Status words accompany every step, so state never depends on colour.
    for status in ("Done", "In progress", "Waiting"):
        assert f'<span class="flow-status">{status}</span>' in discovered


def test_workspace_controls_are_labelled_and_focusable(client) -> None:
    body = client.post(
        "/convert",
        data={
            "config_text": fixture_text("mapping_workspace", "screenos"),
            "action": "map",
        },
    ).get_data(as_text=True)
    workspace = workspace_section(body)

    labelled = set(re.findall(r'<label for="([^"]+)"', workspace))
    controls = set(
        re.findall(r'<(?:input|select) id="([^"]+)"', workspace),
    )

    assert controls
    assert controls == labelled
    for row in range(3):
        assert f'<label for="mapping-destination-{row}">Junos interface</label>' in (
            workspace
        )
        assert f'<label for="mapping-vlan-{row}">VLAN treatment</label>' in workspace
    # The destination control is a type-ahead list of Junos interface ids.
    assert '<datalist id="junos-interface-options">' in workspace
    assert workspace.count('list="junos-interface-options"') == 3
    assert '<option value="ge-0/0/1"></option>' in workspace
    # Number ranges are enforced by the browser as well as the server.
    assert 'type="number" inputmode="numeric" min="0" max="16385" step="1"' in workspace
    assert 'type="number" inputmode="numeric" min="1" max="4094" step="1"' in workspace
    # Decorative graphics stay out of the accessibility tree.
    assert workspace.count("<svg") == workspace.count('<svg class="icon" aria-hidden')


def test_workspace_escapes_submitted_values(client) -> None:
    response = client.post(
        "/convert",
        data={
            "config_text": fixture_text("mapping_workspace", "screenos"),
            "mapping-count": "1",
            "mapping-source-0": "ethernet0/0",
            "mapping-destination-0": '"><script>alert(1)</script>',
            "action": "preview",
        },
    )
    body = response.get_data(as_text=True)

    assert response.status_code == 400
    assert "<script>alert(1)</script>" not in body
    assert "&lt;script&gt;" in body


def test_large_configurations_render_a_bounded_workspace(client) -> None:
    app = create_app({"TESTING": True, "MAX_CONFIG_BYTES": 1_048_576})
    source = "\n".join(
        f'set interface ethernet{slot}/{port} zone "Trust"'
        for slot in range(9)
        for port in range(50)
    )

    with app.test_client() as large_client:
        response = large_client.post(
            "/convert",
            data={"config_text": source, "action": "map"},
        )
    body = response.get_data(as_text=True)

    assert response.status_code == 200
    assert body.count("data-mapping-row") == MAX_WORKSPACE_ROWS
    assert "50 further interfaces are not shown" in body
