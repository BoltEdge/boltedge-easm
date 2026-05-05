# ADR 0012 — Mermaid for In-Document Diagrams

| Field | Value |
|---|---|
| Status | Accepted |
| Date | 2026-05-05 |
| Deciders | Founder / sole engineer |
| Supersedes | – |
| Superseded by | – |

## Context

The SDLC docs (SAD, SRS, threat model, etc.) need diagrams: sequence diagrams for flows, ERD-ish diagrams for data, block diagrams for topology, state diagrams for lifecycles. We need to choose a diagramming approach that:

- Lives **in the repo**, alongside the prose.
- Is **reviewable in PR** (a diagram change shows up as a code diff).
- Is **renderable on GitHub** out of the box (so reviewers don't need to install tooling).
- Is **good-enough**, not pixel-perfect. The audience is engineers and auditors, not marketing.
- Is **versionable** — diagrams evolve with the architecture; we want them to track.

## Decision

We use **Mermaid** (version-agnostic; whatever GitHub renders) for **all** in-document diagrams in `docs/sdlc/` and `docs/adr/`.

- Diagrams are inline ` ```mermaid ... ``` ` fenced blocks in the relevant Markdown file.
- We do not render to images and check those in.
- We do not embed external diagram services (draw.io, Lucid, Excalidraw).
- Sequence, flowchart, class/ERD, state, and gantt are the supported diagram types we lean on.

## Considered alternatives

| Alternative | Why rejected |
|---|---|
| **PlantUML** | Comparable feature set. Renders less smoothly on GitHub by default (often requires an external server or a GitHub Action). Mermaid wins on out-of-box rendering. |
| **Excalidraw** (`.excalidraw` JSON checked in + PNG export) | Beautiful diagrams. But the JSON is hostile to PR diff (any move shifts coordinates), and the rendered PNG is a binary blob that bloats the repo over time. |
| **draw.io / diagrams.net** | Same problem — XML is a wall of coordinates, not reviewable as a diff. |
| **Hand-drawn → SVG export** | Pretty. Not reviewable. Not versionable. |
| **AsciiDoc with embedded ditaa / blockdiag** | Smaller community than Mermaid; AsciiDoc is also outside our Markdown convention. |
| **No diagrams; prose only** | Some flows are genuinely clearer with a sequence diagram. Forcing prose-only is a false economy for complex interactions. |

## Consequences

**Positive:**
- **Diagrams are diffable.** A PR that renames a component shows the rename in the source.
- **No tooling to install.** Anyone with GitHub access sees the rendered diagram.
- **AI-assisted authoring works.** Mermaid is a text format; an LLM can update a diagram without manual re-drawing.
- **Repo footprint is small.** No PNG / SVG bloat over time.

**Negative:**
- **Layout control is limited.** Mermaid auto-lays out; sometimes the result is suboptimal. We accept it.
- **Some diagram styles are weak.** Network / topology diagrams with custom icons aren't really Mermaid's strength. We use blocks-and-arrows and live with it.
- **Renderer differences.** GitHub's Mermaid version may lag the latest features. We stick to the well-supported subset.
- **Dense diagrams become hard to read.** We split a too-dense diagram into multiple smaller ones rather than fight the auto-layout.

## Conventions

- **One diagram per concept.** Don't try to cram three flows into one sequence diagram; produce three diagrams.
- **Label the participants** (`participant FE as Frontend`) for clarity, not just symbols.
- **Use `autonumber`** on sequence diagrams so the prose can reference steps.
- **Use `note over X,Y: ...`** to capture rationale that wouldn't otherwise be visible (e.g., "fire-and-forget; never blocks user action").
- **Don't include data values** in diagrams that change frequently (specific URLs, IPs, timestamps). Reference them in prose so the diagram doesn't rot.

## What this ADR does not cover

- **Architecture diagrams used in marketing or pitch decks.** Those can be drawn in any tool; they're not engineering artifacts.
- **Whiteboard sessions** for in-progress design. Those produce sketches that get translated into Mermaid when the design is ready for review.

## References

- §03 SAD parent — section on diagram conventions
- All `03-sad/*.md` view files — Mermaid usage
- All `09-key-scenarios.md` flows — Mermaid sequence diagrams

---
