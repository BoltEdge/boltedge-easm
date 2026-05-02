"""Nano EASM Security AI Assistant (NESAA) — Phase 1.

Phase 1 is intentionally template-based, NOT LLM-backed:
  - Zero external API costs
  - Zero data leaves the platform
  - Deterministic, auditable explanations
  - Sub-millisecond response time
  - Reuses the FindingTemplate registry already maintained by the scanner

The "AI" naming is for the user-facing button label. The underlying
implementation can be swapped to an LLM in Phase 3 without changing the
endpoint contract.
"""

from .routes import assistant_bp

__all__ = ["assistant_bp"]
