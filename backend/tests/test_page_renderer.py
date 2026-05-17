"""Tests for app.services.page_renderer.

Playwright is mocked. The renderer is a thin wrapper around
sync_playwright(); these tests verify it:
  - short-circuits on empty input
  - swallows ImportError when playwright isn't installed
  - swallows any exception thrown by the playwright stack
  - returns a populated RenderResult on the happy path
  - passes the spec'd viewport, JPEG quality, and timeout
"""
from unittest.mock import MagicMock, patch

import pytest


# ─────────────────────────────────────────────────────────────────────
# Short-circuit behaviour
# ─────────────────────────────────────────────────────────────────────


def test_render_returns_none_for_empty_url():
    from app.services.page_renderer import render_page
    assert render_page("") is None


def test_render_returns_none_for_none_url():
    from app.services.page_renderer import render_page
    assert render_page(None) is None


def test_render_returns_none_when_playwright_not_installed():
    """ImportError on `from playwright.sync_api import sync_playwright`
    must be swallowed and the function must return None — a deployment
    without Chromium baked in shouldn't break the scan."""
    from app.services import page_renderer as pr
    # Force the import inside render_page to fail by inserting a stub
    # module that raises on attribute access.
    import sys
    bad = MagicMock()
    bad.sync_api = MagicMock(side_effect=ImportError("no playwright"))
    # Easier: just patch the function to take the ImportError branch by
    # making the import statement itself raise. We do that by removing
    # any cached module and inserting a placeholder that raises.
    sys_modules_backup = dict(sys.modules)
    try:
        # Remove any cached playwright modules
        for k in list(sys.modules.keys()):
            if k.startswith("playwright"):
                del sys.modules[k]
        # Insert a stub that raises ImportError when sync_api is accessed.
        # We make playwright a module-like object whose 'sync_api'
        # submodule import raises.
        class _Boom:
            def __getattr__(self, name):
                raise ImportError(f"stubbed: {name}")
        sys.modules["playwright"] = _Boom()
        sys.modules["playwright.sync_api"] = _Boom()
        # The from-import in render_page is `from playwright.sync_api
        # import sync_playwright` — that'll execute __getattr__ on the
        # sync_api module and raise ImportError.
        result = pr.render_page("https://example.com/")
        assert result is None
    finally:
        sys.modules.clear()
        sys.modules.update(sys_modules_backup)


# ─────────────────────────────────────────────────────────────────────
# Happy-path render
# ─────────────────────────────────────────────────────────────────────


def _build_mock_playwright(
    *,
    status_code: int = 200,
    html: str = "<html><body>hi</body></html>",
    screenshot: bytes = b"\xff\xd8\xff\xe0fake_jpeg",
    final_url: str = "https://example.com/landing",
):
    """Return a MagicMock chain that satisfies the render_page call path."""
    mock_response = MagicMock()
    mock_response.status = status_code

    mock_page = MagicMock()
    mock_page.goto.return_value = mock_response
    mock_page.content.return_value = html
    mock_page.screenshot.return_value = screenshot
    mock_page.url = final_url
    mock_page.set_default_timeout = MagicMock()

    mock_context = MagicMock()
    mock_context.new_page.return_value = mock_page

    mock_browser = MagicMock()
    mock_browser.new_context.return_value = mock_context

    mock_chromium = MagicMock()
    mock_chromium.launch.return_value = mock_browser

    mock_p = MagicMock()
    mock_p.chromium = mock_chromium

    mock_pw = MagicMock()
    mock_pw.__enter__ = MagicMock(return_value=mock_p)
    mock_pw.__exit__ = MagicMock(return_value=False)

    mock_sync_playwright = MagicMock(return_value=mock_pw)
    return {
        "sync_playwright": mock_sync_playwright,
        "p": mock_p,
        "chromium": mock_chromium,
        "browser": mock_browser,
        "context": mock_context,
        "page": mock_page,
        "response": mock_response,
    }


@pytest.fixture()
def fake_playwright(monkeypatch):
    """Install a fake `playwright.sync_api.sync_playwright` so render_page's
    lazy import inside the function resolves to our mocks. Returns the
    handle dict from _build_mock_playwright."""
    import sys
    import types

    handle = _build_mock_playwright()

    fake_sync_api = types.ModuleType("playwright.sync_api")
    fake_sync_api.sync_playwright = handle["sync_playwright"]
    fake_playwright_pkg = types.ModuleType("playwright")
    fake_playwright_pkg.sync_api = fake_sync_api

    monkeypatch.setitem(sys.modules, "playwright", fake_playwright_pkg)
    monkeypatch.setitem(sys.modules, "playwright.sync_api", fake_sync_api)
    return handle


def test_render_returns_populated_result_on_success(fake_playwright):
    from app.services.page_renderer import render_page
    result = render_page("https://example.com/")
    assert result is not None
    assert result.html == "<html><body>hi</body></html>"
    assert result.screenshot_bytes.startswith(b"\xff\xd8\xff")
    assert result.final_url == "https://example.com/landing"
    assert result.status_code == 200
    assert result.width == 1280
    assert result.height == 720
    assert result.render_ms >= 0


def test_render_passes_correct_viewport(fake_playwright):
    from app.services.page_renderer import render_page
    render_page("https://example.com/")
    call_kwargs = fake_playwright["browser"].new_context.call_args.kwargs
    assert call_kwargs["viewport"] == {"width": 1280, "height": 720}
    assert call_kwargs["ignore_https_errors"] is True


def test_render_uses_jpeg_quality_75(fake_playwright):
    from app.services.page_renderer import render_page
    render_page("https://example.com/")
    screenshot_kwargs = fake_playwright["page"].screenshot.call_args.kwargs
    assert screenshot_kwargs["type"] == "jpeg"
    assert screenshot_kwargs["quality"] == 75
    assert screenshot_kwargs["full_page"] is False


def test_render_sets_10_second_timeout(fake_playwright):
    from app.services.page_renderer import render_page
    render_page("https://example.com/")
    fake_playwright["page"].set_default_timeout.assert_called_once_with(10_000)
    goto_kwargs = fake_playwright["page"].goto.call_args.kwargs
    assert goto_kwargs["timeout"] == 10_000
    assert goto_kwargs["wait_until"] == "domcontentloaded"


def test_render_launches_headless_with_safe_args(fake_playwright):
    from app.services.page_renderer import render_page
    render_page("https://example.com/")
    launch_kwargs = fake_playwright["chromium"].launch.call_args.kwargs
    assert launch_kwargs["headless"] is True
    assert "--no-sandbox" in launch_kwargs["args"]
    assert "--disable-dev-shm-usage" in launch_kwargs["args"]


def test_render_closes_browser_even_on_screenshot_error(fake_playwright):
    """If something fails after the browser launches, browser.close()
    must still run. The function returns None on any failure."""
    fake_playwright["page"].screenshot.side_effect = RuntimeError("disk full")
    from app.services.page_renderer import render_page
    result = render_page("https://example.com/")
    assert result is None
    fake_playwright["browser"].close.assert_called_once()


# ─────────────────────────────────────────────────────────────────────
# Error-path tolerance
# ─────────────────────────────────────────────────────────────────────


def test_render_returns_none_when_browser_launch_fails(fake_playwright):
    fake_playwright["chromium"].launch.side_effect = RuntimeError("no chromium")
    from app.services.page_renderer import render_page
    assert render_page("https://example.com/") is None


def test_render_returns_none_when_goto_times_out(fake_playwright):
    fake_playwright["page"].goto.side_effect = RuntimeError("Timeout 10000ms exceeded")
    from app.services.page_renderer import render_page
    assert render_page("https://example.com/") is None


def test_render_handles_none_response_from_goto(fake_playwright):
    """page.goto() can return None for some redirects. status_code should
    be None but the render should still succeed."""
    fake_playwright["page"].goto.return_value = None
    from app.services.page_renderer import render_page
    result = render_page("https://example.com/")
    assert result is not None
    assert result.status_code is None


def test_render_returns_result_even_for_4xx_response(fake_playwright):
    """The renderer itself doesn't filter on status. The engine does
    (and rejects ≥400 candidates). render_page returns whatever it got."""
    fake_playwright["response"].status = 404
    from app.services.page_renderer import render_page
    result = render_page("https://example.com/")
    assert result is not None
    assert result.status_code == 404
