# ADR 0001 — Record Architecture Decisions

| Field | Value |
|---|---|
| Status | Accepted |
| Date | 2026-05-05 |
| Deciders | Founder / sole engineer |
| Supersedes | – |
| Superseded by | – |

## Context

Nano EASM is moving from "code first, document later" to a structured SDLC. The SAD captures structure as it is *now*; we also need a place to capture the **why** behind individual choices, and the trade-offs the team considered and rejected. Without this, future contributors (including future-me) revisit decisions because the reasoning has been lost.

We need a lightweight, well-known format. We do not need a heavyweight ADR tooling (adr-tools, log4brains) at one-engineer scale.

## Decision

We will record significant architectural decisions as **Architectural Decision Records (ADRs)** following Michael Nygard's lightweight format, stored as Markdown files in `docs/adr/`.

- File naming: `NNNN-kebab-case-title.md`, monotonic NNNN.
- Required sections: **Status**, **Date**, **Context**, **Decision**, **Consequences**.
- Optional sections: **Considered alternatives**, **Notes**, **References**.
- Status values: `Proposed`, `Accepted`, `Deprecated`, `Superseded by ADR-NNNN`.

**Scope of what gets an ADR:**
- Choice of language, framework, database, scheduler, payment processor.
- Decisions that establish a project-wide convention (file layout, auth model, multi-tenancy approach).
- Choices we may revisit at a later scaling step (and want the next person to understand the *why* before they change it).

**Scope of what does not get an ADR:**
- Per-feature implementation choices (those live in commit messages and PR descriptions).
- Style decisions covered by linter / formatter config.
- Anything already documented in the SAD views — ADRs explain *why a choice was made*; SAD describes *what the system is*.

## Considered alternatives

| Alternative | Why rejected |
|---|---|
| No ADRs, decisions in commit messages | Commit messages don't surface for "why did we pick Postgres?"-type questions years later |
| Wiki / Notion page per decision | External tool, search drift, doesn't sit alongside the code, hard to PR-review |
| Heavy ADR tooling (adr-tools CLI) | Overhead at our size; the value is the discipline, not the tool |
| Inline comments in `models.py` etc. | Comments rot; don't capture the "considered alternatives" axis |

## Consequences

**Positive:**
- Decisions become discoverable. New contributors can read ADRs to ramp on the project's reasoning, not just its current shape.
- Decisions become reviewable. ADRs go through PR like code; a reviewer can challenge the reasoning before the decision lands.
- Superseded decisions are explicit (status + cross-link), not silently overwritten.

**Negative:**
- Light overhead. Writing an ADR adds 30 minutes to a decision.
- Risk of ADR rot. We commit to keeping ADRs current — when a decision is reversed, the old ADR is marked `Superseded by ADR-NNNN` rather than edited.

## References

- Michael Nygard, "Documenting Architecture Decisions" (2011)
- ThoughtWorks Tech Radar — ADRs as "Adopt"

---
