"""web_fetch tool — agents fetch a public URL and get plain text back.

SSRF defence: rejects private/loopback/link-local IPs and non-http(s)
schemes. 50 KB result cap after HTML extraction.
"""
from __future__ import annotations
import ipaddress
import socket
from urllib.parse import urlparse

import requests

from . import ToolDef, register_tool
from ._html_to_text import html_to_text


WEB_FETCH_TIMEOUT_SECONDS = 10
WEB_FETCH_RESULT_CAP_BYTES = 50_000


def _is_private_host(host: str) -> bool:
    """Resolve host to IP and check if it's in a private/reserved range."""
    try:
        addr = socket.gethostbyname(host)
        ip = ipaddress.ip_address(addr)
        return (
            ip.is_private or ip.is_loopback or ip.is_link_local
            or ip.is_reserved or ip.is_multicast
        )
    except (socket.gaierror, ValueError):
        return True  # refuse if we can't resolve


def web_fetch_handler(url: str) -> str:
    parsed = urlparse(url)
    if parsed.scheme not in ("http", "https"):
        return f"[rejected: only http/https URLs allowed; got '{parsed.scheme}']"
    if not parsed.hostname:
        return "[rejected: no hostname in URL]"
    if _is_private_host(parsed.hostname):
        return f"[rejected: '{parsed.hostname}' resolves to a private IP]"

    try:
        resp = requests.get(
            url,
            headers={"User-Agent": "Nano-EASM-Agent/1.0"},
            timeout=WEB_FETCH_TIMEOUT_SECONDS,
            allow_redirects=True,
        )
        resp.raise_for_status()
    except requests.exceptions.RequestException as e:
        return f"[fetch failed: {type(e).__name__}: {e}]"

    ctype = resp.headers.get("content-type", "").lower()
    body = resp.text or ""

    if "html" in ctype:
        body = html_to_text(body)

    encoded = body.encode("utf-8")
    if len(encoded) > WEB_FETCH_RESULT_CAP_BYTES:
        body = encoded[:WEB_FETCH_RESULT_CAP_BYTES].decode("utf-8", errors="ignore")
        body += f"\n\n…[truncated at {WEB_FETCH_RESULT_CAP_BYTES} bytes]"

    return body


register_tool(ToolDef(
    name="web_fetch",
    description=(
        "Fetch a public URL and return its main text content (HTML pages "
        "are stripped to readable text). Use for: CVE pages, documentation, "
        "competitor product pages, blog articles, RFCs. Private/internal "
        "URLs are rejected. Result capped at 50 KB."
    ),
    input_schema={
        "type": "object",
        "properties": {
            "url": {
                "type": "string",
                "description": "An http:// or https:// URL to fetch.",
            },
        },
        "required": ["url"],
    },
    handler=web_fetch_handler,
    idempotent=True,
    result_cap_bytes=WEB_FETCH_RESULT_CAP_BYTES,
))
