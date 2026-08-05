"""Contracts for the first-party web assets: budget, motion, and semantics."""

from __future__ import annotations

import gzip
import re
from pathlib import Path

import pytest

from packages.mapping_workspace import BINDING_ICONS, conversion_flow

ROOT = Path(__file__).parents[1]
STATIC = ROOT / "packages" / "static"
TEMPLATES = ROOT / "packages" / "templates"
# Issue #72 budget: all first-party client assets, compressed, on one page.
ASSET_BUDGET_BYTES = 100 * 1024


def gzip_size(path: Path) -> int:
    return len(gzip.compress(path.read_bytes(), 9))


def template_text(name: str) -> str:
    return (TEMPLATES / name).read_text(encoding="utf-8")


def test_first_party_assets_stay_within_the_compressed_budget() -> None:
    assets = sorted(STATIC.iterdir())
    total = sum(gzip_size(asset) for asset in assets)

    assert {asset.name for asset in assets} == {"app.js", "icon.svg", "styles.css"}
    assert total <= ASSET_BUDGET_BYTES, (
        f"first-party assets are {total} bytes gzipped: "
        + ", ".join(f"{asset.name}={gzip_size(asset)}" for asset in assets)
    )


def test_no_frontend_framework_or_remote_asset_is_referenced() -> None:
    markup = "\n".join(
        template_text(path.relative_to(TEMPLATES).as_posix())
        for path in sorted(TEMPLATES.rglob("*.html"))
    )
    script = (STATIC / "app.js").read_text(encoding="utf-8")

    for forbidden in ("http://", "https://", "//cdn.", "integrity="):
        assert forbidden not in markup
    # The CSP is default-src 'self' with no unsafe-inline: styles and scripts
    # are files, never attributes or inline blocks.
    assert "<script" not in markup.replace(
        "<script src=\"{{ url_for('static', filename='app.js') }}\" defer></script>",
        "",
    )
    assert " style=" not in markup
    assert "onclick" not in markup
    # Conversion stays server-side; the script never parses configuration.
    for forbidden in ("innerHTML", "eval(", "fetch(", "setInterval", "XMLHttpRequest"):
        assert forbidden not in script


def test_the_application_icon_is_an_original_inline_svg_used_as_the_favicon() -> None:
    icon = (STATIC / "icon.svg").read_text(encoding="utf-8")
    index = template_text("index.html")

    assert icon.startswith("<svg xmlns=")
    assert "<title>ScreenOS to Junos converter</title>" in icon
    assert "<image" not in icon and "base64" not in icon
    assert 'rel="icon" type="image/svg+xml"' in index
    assert 'class="brand"' in index
    # The header logo is decorative; the page heading names the application.
    assert re.search(r'<img class="brand"[^>]*alt=""', index)


def test_animation_is_bounded_and_respects_reduced_motion() -> None:
    styles = (STATIC / "styles.css").read_text(encoding="utf-8")

    animated_properties = set(
        re.findall(r"^\s{4}(transform|opacity|[a-z-]+):", styles, re.MULTILINE)
    )
    keyframe_bodies = re.findall(r"@keyframes[^{]+\{(.*?)\n\}", styles, re.DOTALL)

    assert "@media (prefers-reduced-motion: reduce)" in styles
    assert "animation-iteration-count: 1 !important" in styles
    # Only compositor-friendly properties are animated.
    for body in keyframe_bodies:
        assert set(re.findall(r"([a-z-]+):", body)) <= {"opacity", "transform"}
    assert animated_properties
    # The one repeating animation belongs to the in-flight indicator, which is
    # hidden until a request is submitted and paused when the tab is hidden.
    assert styles.count("infinite") == 1
    assert "[data-hidden-tab] .flow-working::before" in styles
    assert "animation-play-state: paused" in styles


def test_light_and_dark_themes_are_both_defined() -> None:
    styles = (STATIC / "styles.css").read_text(encoding="utf-8")

    assert "color-scheme: light dark" in styles
    assert "@media (prefers-color-scheme: dark)" in styles
    # Colours come from tokens, so both themes stay in step.
    assert styles.count("--surface:") == 2
    assert styles.count("--ink:") == 2


def test_the_layout_adapts_to_narrow_viewports() -> None:
    styles = (STATIC / "styles.css").read_text(encoding="utf-8")

    assert "@media (max-width: 600px)" in styles
    assert "grid-template-columns: repeat(auto-fit, minmax(320px, 1fr))" in styles
    assert "width: min(1040px, calc(100% - 2rem))" in styles
    # Interactive targets stay large enough to hit on a touch screen.
    assert "min-height: 44px" in styles


@pytest.mark.parametrize(
    "name",
    [
        "index.html",
        "partials/flow.html",
        "partials/workspace.html",
        "partials/result.html",
    ],
)
def test_every_icon_reference_resolves_to_a_defined_symbol(name: str) -> None:
    sprite = template_text("partials/icons.html")
    defined = set(re.findall(r'<symbol id="icon-([a-z]+)"', sprite))
    markup = template_text(name)
    referenced = set(re.findall(r'<use href="#icon-([a-z]+)"', markup))

    assert defined
    assert referenced <= defined
    # Every icon is decorative and hidden from assistive technology.
    assert 'class="icon-sprite" aria-hidden="true"' in sprite
    assert '<svg class="icon">' not in markup


def test_icons_chosen_in_python_exist_in_the_sprite() -> None:
    sprite = template_text("partials/icons.html")
    defined = set(re.findall(r'<symbol id="icon-([a-z]+)"', sprite))

    assert set(BINDING_ICONS.values()) <= defined
    assert {step.icon for step in conversion_flow()} <= defined
