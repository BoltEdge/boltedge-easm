"""One-shot seed for the universal `team_memory` namespace.

Run once after Phase-1 setup. Re-running is idempotent (upserts by key).

Usage:
    cd backend && python -m scripts.seed_team_memory
"""
from app import create_app
from app.extensions import db
from app.agents.memory import write_team_memory


SEEDS = [
    ("brand:never_use_boltedge",
     {"rule": "Always say 'Nano EASM'. The product was rebranded April "
              "2026 from 'BoltEdge EASM'. No reference to 'BoltEdge' "
              "should ever appear in any output."},
     ["brand", "rule"]),
    ("brand:no_community_framing",
     {"rule": "Do NOT describe Nano EASM as 'community edition', "
              "'community preview', or 'community version'. The accepted "
              "phrasing is 'free upgrades until further notice', "
              "'currently free', or 'free to use'."},
     ["brand", "rule"]),
    ("market:global",
     {"rule": "Customer base is global (APAC, USA, Europe, Africa, "
              "Australia). Do not pitch as Australia-only or use AU "
              "sovereignty as a primary differentiator."},
     ["market", "rule"]),
    ("compliance:no_audit_ready_claims",
     {"rule": "Never claim 'audit-ready for SOC 2' or 'audit-ready for "
              "ISO 27001'. Marketing copy should say 'surfaces findings "
              "that may inform your compliance evidence — verify with "
              "your auditor'."},
     ["compliance", "rule"]),
    ("billing:disabled",
     {"rule": "Billing is currently disabled (ENABLE_BILLING=false). "
              "Plans are free upgrade tiers — no payment required. Do "
              "not surface prices, trials, or checkout in user-facing "
              "copy until billing is re-enabled."},
     ["billing", "current-state"]),
    ("approval:hard_gates",
     {"rule": "Never agent-initiated, always founder action: production "
              "deploys, DNS/cert/secrets changes, pricing/plan/commercial "
              "decisions, legal/policy/terms changes, granting access, "
              "outbound spend."},
     ["approval", "rule"]),
    ("voice:tone",
     {"rule": "Brand voice: terse, factual, useful. Lead with the punch "
              "line. Numbers where possible. No filler."},
     ["voice", "rule"]),
    ("nano_easm:url",
     {"rule": "Production URL is https://nanoeasm.com."},
     ["fact"]),
]


def main():
    app = create_app()
    with app.app_context():
        for key, value, tags in SEEDS:
            write_team_memory(key, value, tags)
            print(f"  seeded: {key}")
        db.session.commit()
        print(f"\nseeded {len(SEEDS)} team_memory facts.")


if __name__ == "__main__":
    main()
