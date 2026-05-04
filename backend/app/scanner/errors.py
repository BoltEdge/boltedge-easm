# =============================================================================
# File: app/scanner/errors.py
# Description: Map raw scan-pipeline exceptions to short, customer-facing
# messages. Used for the `error_message` shown on a failed ScanJob.
#
# Why this exists:
#   Stack traces and Python type names ("TypeError: ScanOrchestrator() takes
#   no arguments") leak implementation details and look broken. The full
#   error is still captured via `logger.exception(...)` at the call site;
#   this helper produces only what's safe to show end users.
#
# Design:
#   - Whitelist a few well-understood failure modes (timeout, network,
#     bad target, capacity) and surface a tailored message for each.
#   - Everything else collapses to a single neutral message — operators
#     debug from logs, customers see something they can act on or ignore.
# =============================================================================

from __future__ import annotations

import socket


# Maximum stored length — `ScanJob.error_message` is VARCHAR(500). Keep
# something tighter so the UI cell can render without ellipsis on most
# screens; the log already has the full detail.
_MAX_LEN = 240


def user_facing_error_message(exc: BaseException) -> str:
    """
    Return a short, end-user-safe description of a scan failure.

    Never returns a raw `str(exc)` for unknown exceptions — those leak
    Python internals (class names, attribute paths, SQL fragments) that
    customers can't act on and that look like the product is broken.
    """
    msg = _classify(exc)
    return msg[:_MAX_LEN]


def _classify(exc: BaseException) -> str:
    # Network — receiver unreachable / DNS / connection refused.
    if isinstance(exc, (socket.gaierror, socket.timeout, ConnectionError)):
        return (
            "Could not reach the target during scanning. "
            "It may be offline, blocking our scanners, or behind a firewall."
        )

    # Generic timeout (concurrent.futures.TimeoutError, builtin TimeoutError).
    if isinstance(exc, TimeoutError) or _is_timeout(exc):
        return "Scan timed out before all engines could finish. Try a lighter scan profile."

    # Programming bugs — TypeError / AttributeError / NameError. Almost
    # always means the orchestrator was wired up wrong; users can't fix
    # these and the raw text just looks broken.
    if isinstance(exc, (TypeError, AttributeError, NameError, ValueError, KeyError)):
        return "Scan failed due to an internal error. Our team has been notified."

    # SQLAlchemy / DB layer — never expose raw SQL or driver text.
    name = type(exc).__name__
    module = type(exc).__module__ or ""
    if module.startswith(("sqlalchemy", "psycopg2", "psycopg")):
        return "Scan failed due to an internal error. Our team has been notified."

    # Anything from `requests` (HTTPError, etc.) — at this layer we don't
    # know which engine failed, so keep the message generic.
    if module.startswith("requests"):
        return "A scanner could not contact an upstream service. Please retry."

    # Unknown — fall back to generic. Don't echo str(exc): it can contain
    # tracebacks, secrets in URLs, internal hostnames, etc.
    return f"Scan failed due to an internal error ({name}). Our team has been notified."


def _is_timeout(exc: BaseException) -> bool:
    """Detect timeouts from libraries that don't subclass TimeoutError."""
    name = type(exc).__name__.lower()
    return "timeout" in name
