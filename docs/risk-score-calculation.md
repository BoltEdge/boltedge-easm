# Risk Score Calculation

Single source of truth for what the **exposure score** (also called
"risk score") means in Nano EASM, which findings count toward it, and
which finding statuses do not. If you're touching any of the surfaces
that compute this number, read this first — there are five different
call sites and they need to agree.

## What the score represents

The exposure score is a 0–100 number summarising the **current real
exposure** of an organisation, group, or asset. The intent is one
specific thing:

> "If an attacker probed this surface today, how much would they find?"

Not "how much work is the team doing", not "how many tickets are
open", not "how many findings exist in the database". Three direct
consequences of that framing:

- **Resolved** findings do not count — the issue is fixed, the
  exposure is gone.
- **Suppressed** (ignored) findings do not count — the user has
  declared them false positives; they were never real exposure.
- **In progress** findings *do* count — work is underway but the
  exposure is still real until the fix lands.
- **Accepted-risk** findings *do* count — the user has acknowledged
  the exposure and chosen to live with it. The risk is still there;
  acceptance is an organisational decision, not a remediation.

The accepted-risk rule is load-bearing. Without it, a user could dial
their score to zero by clicking *Accept risk* on every finding —
which would defeat the entire metric.

## What counts toward the score

| Finding status | Counts? | Reasoning |
|---|---|---|
| **Open** | ✓ | Active, unaddressed exposure. |
| **In progress** | ✓ | Work is happening, but the exposure still exists until the fix is verified. |
| **Accepted risk** | ✓ | The user has acknowledged the exposure but chosen not to fix it. The risk is still real. |
| **Resolved** | ✗ | The user has fixed the issue. Score should drop. |
| **Suppressed (ignored)** | ✗ | False positive. Never was real. |

This is **not the same** as the *Open* tab on the findings page,
which excludes all four flag-set states (so it can show only "open
work"). That filter has a different purpose; don't reuse it for
scoring.

## Where the policy is implemented

Five places aggregate findings into an exposure score. They all need
to use the same filter.

| Surface | File | Function |
|---|---|---|
| Org dashboard tile | `backend/app/dashboard/routes.py` | `_counts_toward_exposure()` |
| Per-asset detail | `backend/app/assets/routes.py` | inline filter (search for `Finding.resolved`) |
| Per-group detail | `backend/app/groups/routes.py` | inline filter at lines ~80, ~95, ~105 |
| Trending snapshot (daily) | `backend/app/trending/routes.py` | `active_findings` filter inside `_take_snapshot` |
| PDF / scheduled reports | `backend/app/reports/routes.py` | inside the report-generation query |

The shared SQLAlchemy expression all of them are equivalent to:

```python
and_(
    or_(Finding.ignored  == False, Finding.ignored  == None),
    or_(Finding.resolved == False, Finding.resolved == None),
)
```

Note what is **not** in this filter:
- No check on `in_progress` — those findings should be counted.
- No check on `accepted_risk` — those findings should be counted.

If you ever feel tempted to add either, re-read the table at the top
of this doc.

## The scoring formula

Source of truth: `backend/app/utils/scoring.py:calc_exposure_score`.
The function takes already-filtered severity counts and returns a
score from 0 to 100. Tiers are capped so no single severity can
dominate the score.

| Severity | Per-finding contribution | Cap | Meaning of cap |
|---|---|---|---|
| **Critical** | 15.0 pts | 40 pts | ~3 criticals nearly maxes this tier |
| **High** | 4.0 pts | 30 pts | ~8 highs maxes this tier |
| **Medium** | √n × 5 pts | 20 pts | Diminishing returns from volume |
| **Low** | √n × 2 pts | 10 pts | Diminishing returns from volume |
| **Info** | 0 pts | — | Informational, no risk contribution |

Theoretical max: 40 + 30 + 20 + 10 = **100**.

### Worked examples

| Counts | Calculation | Score |
|---|---|---|
| 0 critical, 0 high, 0 medium, 0 low | 0 | **0.0** |
| 1 critical, 0 high, 0 medium, 0 low | 15 | **15.0** |
| 3 critical, 0 high, 0 medium, 0 low | min(40, 45) | **40.0** |
| 0 critical, 5 high, 0 medium, 0 low | 5 × 4 = 20 | **20.0** |
| 0 critical, 0 high, 16 medium, 0 low | √16 × 5 = 20 | **20.0** |
| 2 critical, 4 high, 9 medium, 25 low | 30 + 16 + 15 + 10 = 71 | **71.0** |
| 5 critical, 20 high, 100 medium, 100 low | min each tier | **100.0** |

### Letter grades

`exposure_grade()` maps the numeric score to a letter for UI display:

| Score range | Grade | Label |
|---|---|---|
| < 15 | A | Excellent — minimal exposure |
| 15–29 | B | Good — low-severity findings only |
| 30–49 | C | Moderate — some concerning findings |
| 50–69 | D | Significant — high-severity findings present |
| ≥ 70 | F | Critical — immediate remediation required |

## Asset-criticality weighting

The org-level dashboard uses `calc_weighted_exposure_score` instead
of the raw `calc_exposure_score`. It multiplies each finding's
contribution by the asset's criticality tier before running the
severity formula:

| Tier | Multiplier | Meaning |
|---|---|---|
| `tier_1` | 1.5× | Crown-jewel assets — a finding here counts for 1.5 |
| `tier_2` | 1.0× | Default — counts as 1 |
| `tier_3` | 0.5× | Low-criticality — counts as 0.5 |

Per-asset and per-group rollups use the unweighted formula because
the weighting is already implicit in the scope (you're already
looking at one asset / one group).

## "Still detected after resolution" — separate signal

A user marking a finding **resolved** removes it from the score (per
the rules above). But our scanner doesn't auto-reopen resolved
findings on rescan; the orchestrator silently bumps `last_seen_at`
and keeps the user-set status. That's a deliberate choice — auto-
reopening can frustrate users who consciously accepted partial
mitigations as good enough.

The risk this creates: a "fix" that didn't actually take is invisible
to the user. So the UI surfaces it explicitly without changing the
score itself:

- **Findings table**: amber "Still detected" badge appears when a
  finding is `resolved=true` AND `last_seen_at > resolved_at + 60s`.
- **Finding details dialog**: amber warning banner with both
  timestamps and a prompt to verify with the lookup tools before
  reopening.

The **score is unchanged** in this state. The user can decide whether
to re-open the finding (which would put it back into the score) or
keep it resolved. The badge is there to make sure they see the
discrepancy.

Helper functions:
- Frontend: `findings/page.tsx:isResolvedButStillDetected`
- Component: `FindingDetailsDialog.tsx` — inline "still detected"
  banner block (search for `lastSeenMs > resolvedAtMs`).

## Notification gating (related but separate)

Risk score and notifications use different rules. Notifications
("alerts") fire on **truly new findings only** — the orchestrator's
`dispatch_event(finding.{sev})` only iterates `new_drafts` (created
this scan), not findings updated via the dedupe path. Same for
`MonitorAlert` rows of type `new_finding`.

So:

- A re-detected finding does NOT trigger a fresh alert.
- A re-detected resolved finding does NOT trigger an alert.
- A re-detected resolved finding DOES surface a "still detected"
  badge in the UI, but no notification.

Code references:
- `backend/app/scanner/orchestrator.py:_persist_findings` — the
  `new_drafts` list and the `dispatch_event` call gated on it.
- `backend/app/monitoring/change_detector.py` — the `new_finding`
  alert path, which compares current scan's `dedupe_key` set against
  the previous scan's set.

## Things people get wrong (don't repeat these)

1. **Adding `accepted_risk` to the score filter.** Tempting because
   the findings page hides accepted-risk from the open tab. But the
   findings page filter is for "show me my open work"; the score
   filter is for "what is my real exposure". They are not the same.

2. **Filtering on `in_progress`.** Same trap. The user is doing
   something about it, but the exposure exists until the fix lands
   and is verified.

3. **Trying to compute the score from `Finding.status`.** The
   `status` field is derived (see `findings/routes.py:_derive_status`)
   from the four boolean flags. Always filter on the underlying
   booleans (`Finding.resolved`, `Finding.ignored`) — they're indexed
   and the derivation can change.

4. **Using `_is_open_filter` from `findings/routes.py` for scoring.**
   That filter is for the findings-page status tabs, not for risk
   calculation. It excludes all four flags. The scoring filter only
   excludes two.

5. **Forgetting the `info` severity is zero.** Don't bump it to
   non-zero "to make it match Splunk / Tenable scoring" — info
   findings are inventory, not risk. If you want to count them, add
   a separate metric.

## When this doc is wrong

If you change the scoring policy (e.g., decide accepted-risk should
no longer count, or change tier weights), update **both** this doc
and every site listed in the *Where the policy is implemented*
table. Inconsistency between surfaces is worse than the wrong
policy applied uniformly — a user who sees three different exposure
numbers across dashboard / trending / reports stops trusting any of
them.
