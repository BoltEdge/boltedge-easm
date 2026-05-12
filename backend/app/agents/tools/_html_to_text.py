"""HTML to plain-text conversion for tool results.

Uses BeautifulSoup to strip script/style/nav and collect text. Errors
silently fall back to a regex-based strip so a malformed page still
returns something.
"""
from __future__ import annotations
import re


_SCRIPT_STYLE_RE = re.compile(
    r"<(script|style|noscript|nav|footer|header)[^>]*>.*?</\1>",
    re.IGNORECASE | re.DOTALL,
)
_TAG_RE = re.compile(r"<[^>]+>")


def html_to_text(html: str) -> str:
    try:
        from bs4 import BeautifulSoup
        soup = BeautifulSoup(html, "html.parser")
        for tag in soup(["script", "style", "noscript", "nav",
                          "footer", "header", "aside"]):
            tag.decompose()
        text = soup.get_text(separator="\n")
        text = re.sub(r"\n{3,}", "\n\n", text)
        return text.strip()
    except Exception:
        out = _SCRIPT_STYLE_RE.sub("", html)
        out = _TAG_RE.sub(" ", out)
        out = re.sub(r"\s+", " ", out)
        return out.strip()
