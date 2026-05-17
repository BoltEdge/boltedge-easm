# app/services/page_renderer.py
"""
Playwright/Chromium wrapper used by the Site Mimic Watch matcher to
capture full-page screenshots and the page HTML in a single render.

Importing Playwright is lazy: when MIMIC_ENABLED is false we never
touch it, so deployments without Chromium baked into the image keep
working. Each render call boots a fresh browser context to avoid
state leaks between candidates.

Public surface:

    render_page(url) -> RenderResult | None

A None return means "render didn't succeed but the world didn't end" —
the engine continues with the cheaper signals it has.
"""
from __future__ import annotations

import logging
from dataclasses import dataclass
from typing import Optional


logger = logging.getLogger(__name__)


RENDER_TIMEOUT_MS = 10_000        # 10s wall-clock budget per page
VIEWPORT_WIDTH = 1280
VIEWPORT_HEIGHT = 720
JPEG_QUALITY = 75


@dataclass
class RenderResult:
    """The successful output of a single page render."""
    html: str
    screenshot_bytes: bytes        # JPEG q=75, viewport-sized
    final_url: str                 # after redirects
    status_code: Optional[int]
    width: int
    height: int
    render_ms: int


def render_page(url: str) -> Optional[RenderResult]:
    """Render a URL with Chromium. Never raises.

    Returns RenderResult on success. Returns None when Playwright
    isn't installed, the browser refuses to launch, the page times
    out, or any other render-time error occurs. The engine treats
    None as "skip the visual signal for this candidate"."""
    if not url:
        return None
    try:
        from playwright.sync_api import sync_playwright
    except ImportError:
        logger.info("page_renderer: playwright not installed; skipping render")
        return None

    import time
    start = time.monotonic()
    try:
        with sync_playwright() as p:
            browser = p.chromium.launch(
                headless=True,
                args=["--no-sandbox", "--disable-dev-shm-usage"],
            )
            try:
                context = browser.new_context(
                    viewport={"width": VIEWPORT_WIDTH, "height": VIEWPORT_HEIGHT},
                    user_agent=(
                        "Mozilla/5.0 (Nano-EASM-MimicProbe/1.0) "
                        "Chrome/120.0 Safari/537.36"
                    ),
                    ignore_https_errors=True,
                )
                page = context.new_page()
                page.set_default_timeout(RENDER_TIMEOUT_MS)
                response = page.goto(url, wait_until="domcontentloaded",
                                     timeout=RENDER_TIMEOUT_MS)
                status = response.status if response else None
                html = page.content()
                screenshot = page.screenshot(
                    type="jpeg",
                    quality=JPEG_QUALITY,
                    full_page=False,    # viewport-only; bounds size predictably
                )
                final_url = page.url
            finally:
                browser.close()
    except Exception as e:
        logger.warning("page_renderer: render failed for %s: %s", url, e)
        return None

    elapsed_ms = int((time.monotonic() - start) * 1000)
    return RenderResult(
        html=html or "",
        screenshot_bytes=screenshot or b"",
        final_url=final_url or url,
        status_code=status,
        width=VIEWPORT_WIDTH,
        height=VIEWPORT_HEIGHT,
        render_ms=elapsed_ms,
    )
