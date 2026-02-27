# File: app/utils/scoring.py
# =============================================================================
# Centralized Exposure Score Calculator
# =============================================================================
# Single source of truth for exposure score calculation across the platform.
# Used by: dashboard, groups, reports, trending, scanner/exposure_scorer.
#
# Scale:
#   0       = no open findings
#   < 30    = healthy (minor findings only)
#   30–60   = moderate concern
#   60–80   = significant risk (criticals present or many highs)
#   80–100  = critical posture, needs immediate action
#
# Only OPEN findings count — resolved, suppressed, and info are excluded.
# =============================================================================

from __future__ import annotations
import math


def calc_exposure_score(
    critical: int = 0,
    high: int = 0,
    medium: int = 0,
    low: int = 0,
    info: int = 0,
) -> float:
    """
    Calculate an exposure score from 0–100 based on open finding severity counts.

    Tier breakdown (with caps to prevent any single tier from dominating):
      - Critical: 15 pts each, max 40 pts  → 3 criticals nearly maxes this tier
      - High:      4 pts each, max 30 pts  → 8 highs maxes this tier
      - Medium:    sqrt(n) × 5, max 20 pts → diminishing returns from volume
      - Low:       sqrt(n) × 2, max 10 pts → diminishing returns from volume
      - Info:      0 pts                    → informational, no risk contribution

    Total theoretical max = 40 + 30 + 20 + 10 = 100
    """
    c_score = min(40.0, critical * 15.0)
    h_score = min(30.0, high * 4.0)
    m_score = min(20.0, math.sqrt(max(medium, 0)) * 5.0)
    l_score = min(10.0, math.sqrt(max(low, 0)) * 2.0)

    raw = c_score + h_score + m_score + l_score
    return round(min(100.0, raw), 1)


def exposure_grade(score: float) -> tuple[str, str]:
    """
    Convert a numeric exposure score to a letter grade and description.
    Returns: (grade, description)
    """
    if score < 15:
        return "A", "Excellent — minimal exposure"
    elif score < 30:
        return "B", "Good — low-severity findings only"
    elif score < 50:
        return "C", "Moderate — some concerning findings"
    elif score < 70:
        return "D", "Significant — high-severity findings present"
    else:
        return "F", "Critical — immediate remediation required"


def exposure_label_and_color(score: float) -> tuple[str, str]:
    """
    Return (label, hex_color) for dashboard/group display.
    Matches the existing UI color scheme.
    """
    if score == 0:
        return "Secure", "#10b981"
    elif score < 25:
        return "Low Risk", "#22c55e"
    elif score < 50:
        return "Moderate", "#eab308"
    elif score < 75:
        return "High Risk", "#f97316"
    else:
        return "Critical", "#ef4444"