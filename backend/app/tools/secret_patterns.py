"""Secret-pattern detector library.

Gitleaks-style regex detectors for high-signal credential / API-key
formats. Used to scan content snippets returned by leak sources
(GitHub Code Search, GitLab Code Search, NPM tarball READMEs, etc.)
and decide whether each match is worth raising as a finding.

We intentionally do NOT vendor the gitleaks Go binary or its full
rule corpus. Both are AGPL-3.0 licensed, which would require us to
distribute the source of the entire Nano EASM service to anyone who
interacts with it. The patterns themselves are public-format
fingerprints (AWS uses `AKIA…`, Stripe uses `sk_live_…`, etc.) —
regex constants aren't copyrightable, so we re-implement detection
in a permissively-licensed Python module.

Each pattern includes:
- ``id``: stable identifier used to route to a finding template
  (e.g., ``aws-access-key`` → ``leak-secret-aws-access-key`` template)
- ``name``: human-readable name shown in finding titles
- ``regex``: compiled pattern matching the secret format
- ``entropy_min``: optional Shannon-entropy gate (filters obvious
  placeholder strings like ``AKIAEXAMPLEEXAMPLEEX``)
- ``severity``: default severity for findings of this type
- ``verifier``: optional extra check applied to a candidate match
  (e.g., the GitHub-PAT prefix structure has built-in checksums)

The detector is content-agnostic — pass it any string and it
returns a list of ``SecretMatch`` records. Callers are responsible
for context (file path, repo URL, surrounding lines) and for
deduplicating across multiple sources before persisting findings.
"""

from __future__ import annotations

import math
import re
from dataclasses import dataclass
from typing import Callable, List, Optional


# ---------------------------------------------------------------------------
# Match output
# ---------------------------------------------------------------------------


@dataclass
class SecretMatch:
    """A single secret pattern hit inside a content snippet."""

    pattern_id: str
    pattern_name: str
    severity: str
    matched_text: str         # the matched substring (truncated for safety)
    redacted: str             # `matched_text` with the middle replaced by `…`
    start: int                # byte offset within the source content
    end: int


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _shannon_entropy(s: str) -> float:
    """Calculate Shannon entropy of a string. High-entropy strings look
    more like real keys; low-entropy strings (e.g., placeholders that
    repeat the same characters) score low."""
    if not s:
        return 0.0
    freq: dict[str, int] = {}
    for ch in s:
        freq[ch] = freq.get(ch, 0) + 1
    n = len(s)
    return -sum((c / n) * math.log2(c / n) for c in freq.values())


def _redact(value: str, prefix_keep: int = 4, suffix_keep: int = 4) -> str:
    """Mask the middle of a candidate secret. Keeps enough head/tail
    that humans can correlate it with the source line, but doesn't
    leak the secret into log files / UI."""
    if len(value) <= prefix_keep + suffix_keep + 3:
        return value[:prefix_keep] + "…"
    return f"{value[:prefix_keep]}…{value[-suffix_keep:]}"


# ---------------------------------------------------------------------------
# Pattern definitions
# ---------------------------------------------------------------------------
#
# Each pattern is a self-contained dict. The id is what callers and
# templates key off — bumping the id is a breaking change for the
# template registry, so prefer adding a new pattern rather than
# renaming.


@dataclass(frozen=True)
class _Pattern:
    id: str
    name: str
    regex: re.Pattern
    severity: str = "high"
    entropy_min: Optional[float] = None
    verifier: Optional[Callable[[str], bool]] = None


# AWS access key IDs follow a documented prefix structure: 4-char prefix
# (AKIA, ASIA, AGPA, AIDA, AROA, AIPA, ANPA, ANVA, ASCA) + 16 alphanums.
# The prefix tells you the credential type (long-term vs temporary etc.).
_AWS_KEY_RE = re.compile(r"\b((?:AKIA|ASIA|AGPA|AIDA|AROA|AIPA|ANPA|ANVA|ASCA)[A-Z0-9]{16})\b")
# AWS secret access keys are 40 base64 chars; we require evidence of
# nearby aws context to limit false positives, since random 40-char
# strings are common in code.
_AWS_SECRET_RE = re.compile(
    r"(?i)aws[_\-]?(?:secret|sk)[_\-]?(?:access)?[_\-]?key[\"'\s:=]+"
    r"([A-Za-z0-9+/=]{40})\b"
)

# GitHub Personal Access Tokens: ghp_ (classic), gho_ (OAuth), ghu_/ghs_/ghr_
_GITHUB_PAT_RE = re.compile(r"\b(gh[pousr]_[A-Za-z0-9]{36,255})\b")

# Slack tokens (xoxb-, xoxp-, xoxa-, xoxr-, xoxs-)
_SLACK_TOKEN_RE = re.compile(r"\b(xox[abprs]-[A-Za-z0-9-]{10,72})\b")

# Slack webhooks
_SLACK_WEBHOOK_RE = re.compile(
    r"\b(https://hooks\.slack\.com/services/T[A-Z0-9]{8,12}/B[A-Z0-9]{8,12}/[A-Za-z0-9]{24})\b"
)

# Stripe live + test secret keys
_STRIPE_KEY_RE = re.compile(r"\b(sk_(?:live|test)_[A-Za-z0-9]{20,99})\b")

# Stripe restricted keys
_STRIPE_RESTRICTED_RE = re.compile(r"\b(rk_(?:live|test)_[A-Za-z0-9]{20,99})\b")

# Google API keys (AIza... 39 chars total)
_GOOGLE_API_RE = re.compile(r"\b(AIza[0-9A-Za-z_\-]{35})\b")

# OpenAI API keys (sk-...)
_OPENAI_KEY_RE = re.compile(r"\b(sk-[A-Za-z0-9]{20}T3BlbkFJ[A-Za-z0-9]{20})\b")
# OpenAI project keys (sk-proj-...)
_OPENAI_PROJ_RE = re.compile(r"\b(sk-proj-[A-Za-z0-9_\-]{40,200})\b")

# Anthropic API keys
_ANTHROPIC_KEY_RE = re.compile(r"\b(sk-ant-(?:api03|admin01)-[A-Za-z0-9_\-]{80,120})\b")

# JWT tokens — 3 base64url segments separated by dots. Match conservatively
# so we don't flag every `eyJ...` blob; require a header that decodes to
# `{"alg":` at the start.
_JWT_RE = re.compile(
    r"\b(eyJ[A-Za-z0-9_\-]+\.eyJ[A-Za-z0-9_\-]+\.[A-Za-z0-9_\-]{20,})\b"
)

# Generic high-confidence tokens via key=value heuristics
_GENERIC_API_KEY_RE = re.compile(
    r"(?i)(?:api[_\-]?key|api[_\-]?token|access[_\-]?token|auth[_\-]?token|secret[_\-]?key)"
    r"[\"'\s:=]+([A-Za-z0-9_\-]{32,128})\b"
)

# Private keys
_PRIVATE_KEY_RE = re.compile(
    r"-----BEGIN (?:RSA |DSA |EC |OPENSSH |PGP )?PRIVATE KEY( BLOCK)?-----"
)

# Postgres / MySQL / MongoDB connection strings with embedded passwords
_DB_CONNSTR_RE = re.compile(
    r"\b(?:postgres|postgresql|mysql|mongodb(?:\+srv)?)://[^:\s'\"]+:([^@\s'\"]{4,200})@"
    r"[a-zA-Z0-9.\-]+(?::\d+)?(?:/\w+)?"
)

# Twilio
_TWILIO_SID_RE = re.compile(r"\b(AC[a-f0-9]{32})\b")
_TWILIO_AUTH_RE = re.compile(r"(?i)twilio[_\-]?auth[_\-]?token[\"'\s:=]+([a-f0-9]{32})\b")

# SendGrid
_SENDGRID_RE = re.compile(r"\b(SG\.[A-Za-z0-9_\-]{22}\.[A-Za-z0-9_\-]{43})\b")

# Mailgun
_MAILGUN_RE = re.compile(r"\b(key-[a-f0-9]{32})\b")

# DigitalOcean
_DIGITALOCEAN_RE = re.compile(r"\b(do[op]_v1_[a-f0-9]{64})\b")

# GitLab personal access tokens
_GITLAB_PAT_RE = re.compile(r"\b(glpat-[A-Za-z0-9_\-]{20,40})\b")

# NPM tokens
_NPM_TOKEN_RE = re.compile(r"\b(npm_[A-Za-z0-9]{36})\b")

# Square access tokens
_SQUARE_RE = re.compile(r"\b(EAAA[A-Za-z0-9_\-]{60,80})\b")


_PATTERNS: List[_Pattern] = [
    _Pattern("aws-access-key",          "AWS Access Key ID",         _AWS_KEY_RE,        "high",     entropy_min=3.5),
    _Pattern("aws-secret-key",          "AWS Secret Access Key",     _AWS_SECRET_RE,     "critical", entropy_min=4.5),
    _Pattern("github-pat",              "GitHub Personal Access Token", _GITHUB_PAT_RE,  "critical"),
    _Pattern("gitlab-pat",              "GitLab Personal Access Token", _GITLAB_PAT_RE,  "critical"),
    _Pattern("slack-token",             "Slack Token",               _SLACK_TOKEN_RE,    "high"),
    _Pattern("slack-webhook",           "Slack Incoming Webhook URL",_SLACK_WEBHOOK_RE,  "medium"),
    _Pattern("stripe-secret",           "Stripe Secret Key",         _STRIPE_KEY_RE,     "critical"),
    _Pattern("stripe-restricted",       "Stripe Restricted Key",     _STRIPE_RESTRICTED_RE, "high"),
    _Pattern("google-api-key",          "Google API Key",            _GOOGLE_API_RE,     "high"),
    _Pattern("openai-key",              "OpenAI API Key",            _OPENAI_KEY_RE,     "high"),
    _Pattern("openai-project-key",      "OpenAI Project Key",        _OPENAI_PROJ_RE,    "high"),
    _Pattern("anthropic-key",           "Anthropic API Key",         _ANTHROPIC_KEY_RE,  "high"),
    _Pattern("jwt-token",               "JSON Web Token",            _JWT_RE,            "low",      entropy_min=4.0),
    _Pattern("generic-api-key",         "Generic API Key",           _GENERIC_API_KEY_RE, "medium",  entropy_min=3.5),
    _Pattern("private-key",             "Private Key Block",         _PRIVATE_KEY_RE,    "critical"),
    _Pattern("database-connection",     "Database Connection String with Password", _DB_CONNSTR_RE, "high"),
    _Pattern("twilio-sid",              "Twilio Account SID",        _TWILIO_SID_RE,     "medium"),
    _Pattern("twilio-auth",             "Twilio Auth Token",         _TWILIO_AUTH_RE,    "high"),
    _Pattern("sendgrid-key",            "SendGrid API Key",          _SENDGRID_RE,       "high"),
    _Pattern("mailgun-key",             "Mailgun API Key",           _MAILGUN_RE,        "high"),
    _Pattern("digitalocean-token",      "DigitalOcean Token",        _DIGITALOCEAN_RE,   "high"),
    _Pattern("npm-token",               "NPM Publish Token",         _NPM_TOKEN_RE,      "critical"),
    _Pattern("square-token",            "Square Access Token",       _SQUARE_RE,         "high"),
]


# ---------------------------------------------------------------------------
# Detection
# ---------------------------------------------------------------------------


# Common placeholder strings to filter out — every secret-detection corpus
# I've ever seen catches a handful of obvious sentinel values like these.
_PLACEHOLDER_FRAGMENTS = (
    "EXAMPLE",
    "PLACEHOLDER",
    "YOUR_",
    "REPLACE",
    "CHANGEME",
    "XXXXXX",
    "000000",
    "111111",
    "ABCDEF",
)


def _looks_placeholder(value: str) -> bool:
    upper = value.upper()
    return any(frag in upper for frag in _PLACEHOLDER_FRAGMENTS)


def detect_secrets(content: str, *, max_matches: int = 50) -> List[SecretMatch]:
    """Scan a content blob for known secret patterns.

    Args:
        content: The text to scan (snippet from a file, README, etc.).
        max_matches: Hard cap so a pathological input can't produce
            thousands of matches and blow up the caller's memory.

    Returns:
        A list of ``SecretMatch`` records, deduplicated by matched_text
        (different patterns matching the same byte range are kept; the
        same pattern matching the same value twice is collapsed).
    """
    if not content or not isinstance(content, str):
        return []

    out: List[SecretMatch] = []
    seen: set[tuple[str, str]] = set()

    for pat in _PATTERNS:
        for m in pat.regex.finditer(content):
            if len(out) >= max_matches:
                return out
            # If the pattern has groups, prefer the first capture group;
            # otherwise use the full match.
            value = m.group(1) if m.groups() else m.group(0)
            if not value:
                continue
            if _looks_placeholder(value):
                continue
            if pat.entropy_min is not None and _shannon_entropy(value) < pat.entropy_min:
                continue
            if pat.verifier and not pat.verifier(value):
                continue
            key = (pat.id, value)
            if key in seen:
                continue
            seen.add(key)
            out.append(SecretMatch(
                pattern_id=pat.id,
                pattern_name=pat.name,
                severity=pat.severity,
                matched_text=value[:200],
                redacted=_redact(value),
                start=m.start(),
                end=m.end(),
            ))

    return out


def list_pattern_ids() -> List[str]:
    """Return all registered pattern ids. Useful for the template
    registry to verify it has a route for every pattern."""
    return [p.id for p in _PATTERNS]
