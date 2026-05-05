# SAD View 09 — Key Scenarios

| Field | Value |
|---|---|
| Parent document | `03-sad.md` |
| View ID | 09 — Scenarios (the "+1" of 4+1) |
| Status | Draft |
| Last reviewed | 2026-05-05 |

This view illustrates the most architecturally significant flows end-to-end, tying the four other views together. Each scenario shows the pieces in motion: which components are involved, where the data lives, and where the system enforces invariants. The choices below are the flows where multiple SRS modules interact and where most of the architecture earns its keep.

Scenarios in this view:

1. New user signup → first scan
2. Discovery → asset onboarding
3. Scheduled monitoring tick
4. Stripe webhook → plan upgrade
5. API key authentication → finding update
6. Free-tier expiry → 30-day grace → hard delete
7. Audit log → customer SIEM webhook
8. Cross-tenant isolation guard (illustrative)
9. Backend container restart with in-flight scans
10. Superadmin impersonation

---

## 1. New user signup → first scan

**SRS modules touched:** 01 (Onboarding), 02 (Auth), 03 (Org), 05 (Assets), 07 (Scanning), 10 (Billing)

```mermaid
sequenceDiagram
    autonumber
    participant U as User
    participant FE as Frontend
    participant BE as Backend
    participant DB
    participant RS as Resend
    participant SC as Scanner orchestrator

    U->>FE: open /register
    FE->>FE: solve reCAPTCHA
    FE->>BE: POST /auth/register {email, password, org_name, recaptcha}
    BE->>BE: verify reCAPTCHA, validate input
    BE->>DB: INSERT organization (plan=Free, free_expires_at=now+90d)
    BE->>DB: INSERT user (Owner, email_verified=false)
    BE->>RS: send verification email (signed token, no auto-fire link)
    BE-->>FE: 201 {pending_email_verification}

    Note over U,RS: User clicks link → verify page<br/>(requires explicit "Verify my email" click)

    U->>FE: click "Verify my email"
    FE->>BE: POST /auth/verify-email {token}
    BE->>DB: UPDATE user SET email_verified=true
    BE-->>FE: 200 {access_token (JWT)}

    U->>FE: navigate to /assets/new
    FE->>BE: POST /assets {kind=domain, value=example.com}
    BE->>BE: check_limit("assets") → 1/2 used, allowed
    BE->>DB: INSERT asset (display_id=AS0001, organization_id=...)
    BE-->>FE: 201 {asset}

    U->>FE: click "Run quick scan"
    FE->>BE: POST /scan/jobs {asset_id, profile=quick}
    BE->>BE: check_limit("scans_per_month") → 1/5, allowed
    BE->>DB: INSERT scan_job (status=queued)
    BE->>SC: submit(job)
    BE-->>FE: 202 {job_id}

    Note over SC,DB: scanner runs async on thread pool
    SC->>DB: UPDATE scan_job (status=running)
    SC->>SC: run engines + analyzers
    SC->>DB: INSERT findings (idempotent on (job, template, target))
    SC->>DB: UPDATE scan_job (status=completed)

    FE->>BE: GET /scan/jobs/<id> (polled every 3s)
    BE-->>FE: 200 {status: completed, findings_count: 12}
```

**Architectural points illustrated:**
- Email verification gate (§06 Security §4) sits between signup and login.
- Plan limits (§05 Data §3, §06 Security §7) check **before** any expensive operation.
- Scan kickoff is **async** (§02 Runtime §5) — request returns 202 immediately.
- Display ids (`AS0001`, `SC0001`) become the user-facing identifier from this point on (§05 Data §5).
- The 90-day Free expiry (§05 Data §8 retention; SRS FR-BILL-002) is set at org creation; nothing else needs to track it.

---

## 2. Discovery → asset onboarding

**SRS modules touched:** 05 (Assets), 06 (Discovery)

```mermaid
sequenceDiagram
    autonumber
    participant U as User
    participant FE as Frontend
    participant BE as Backend
    participant Orch as Discovery orchestrator
    participant CT as crt.sh
    participant DNS as Public DNS
    participant SH as Shodan
    participant DB

    U->>FE: enter root_domain "example.com"
    FE->>BE: POST /discovery/run {root_domain}
    BE->>BE: check_limit("discoveries_per_month")
    BE->>DB: INSERT discovery_job (status=queued)
    BE->>Orch: submit(job)
    BE-->>FE: 202 {job_id}

    Orch->>DB: UPDATE discovery_job (status=running)

    par fan-out across 11 modules
        Orch->>CT: certs for example.com
        CT-->>Orch: list of subdomains (incl. internal-leakage)
    and
        Orch->>DNS: brute-force common subdomains
        DNS-->>Orch: A/AAAA results
    and
        Orch->>SH: org-scoped Shodan query
        SH-->>Orch: hosts + services
    end

    Orch->>Orch: dedupe + classify by kind
    Orch->>DB: INSERT/UPDATE asset rows (tenant-scoped)
    Orch->>DB: UPDATE discovery_job (status=completed, summary)

    U->>FE: view discovery results
    FE->>BE: GET /discovery/jobs/<id>/results
    BE->>DB: SELECT assets WHERE discovery_job_id = ?
    BE-->>FE: 200 [...]
```

**Architectural points illustrated:**
- Fan-out concurrency happens **inside the orchestrator's thread**, not via a queue (§02 Runtime §3, §05 Data §9.1).
- Each external source (§07 Integrations §6) can fail independently; the orchestrator merges what came back.
- Discovery is **additive** (§05 Data §9.1) — it never deletes user-owned assets.
- Tenant scoping applies to the writes; an org's discovery cannot touch another org's data even if the root domain string overlaps.

---

## 3. Scheduled monitoring tick

**SRS modules touched:** 09 (Monitoring), 07 (Scanning)

```mermaid
sequenceDiagram
    autonumber
    participant SCH as Scheduler thread
    participant DB
    participant TP as Thread pool
    participant SC as Scanner orchestrator

    Note over SCH: tick every 5 min
    SCH->>SCH: pg_try_advisory_lock(monitor_tick_lock)
    SCH->>DB: SELECT monitors WHERE next_run_at <= now() AND is_active
    DB-->>SCH: due monitors

    loop each due monitor
        SCH->>DB: pg_try_advisory_lock(monitor_id)
        alt got lock
            SCH->>DB: INSERT scan_job (source=monitor, status=queued)
            SCH->>TP: submit(run_scan, job_id)
            SCH->>DB: UPDATE monitor SET next_run_at = now() + cadence
            SCH->>DB: pg_advisory_unlock(monitor_id)
        else previous tick still running
            SCH->>SCH: skip (logged WARN)
        end
    end

    Note over TP,SC: scans run async; same path as user-triggered scans
    TP->>SC: run scan
    SC->>DB: write findings, update job
```

**Architectural points illustrated:**
- One scheduler-owning worker only (§02 Runtime §3); file-lock election.
- **Per-row advisory lock** prevents overlapping runs of the same monitor — the scheduler can drift by a tick, but a slow monitor is never doubled-up (§02 Runtime §6).
- Monitor scans share the same `scan_job` table and same scanner orchestrator as user-triggered scans. Plan limits count both against `scans_per_month` (CLAUDE.md hard rule #4).
- **Indexed on `(next_run_at)` partial WHERE `is_active`** (§05 Data §10) — the scheduler's hot path is cheap.

---

## 4. Stripe webhook → plan upgrade

**SRS modules touched:** 10 (Billing)

```mermaid
sequenceDiagram
    autonumber
    participant ST as Stripe
    participant BE as Backend
    participant DB
    participant RS as Resend

    Note over ST,BE: customer completed Checkout for "Professional monthly"

    ST->>BE: POST /billing/stripe-webhook<br/>Stripe-Signature: ...
    BE->>BE: stripe.Webhook.construct_event<br/>(verifies signature)

    BE->>DB: SELECT stripe_event WHERE id = event.id
    alt already processed
        BE-->>ST: 200 (idempotent no-op)
    else new event
        BE->>DB: INSERT stripe_event
        BE->>BE: dispatch on event.type<br/>(checkout.session.completed)
        BE->>DB: SELECT organization WHERE stripe_customer_id = ...
        BE->>DB: UPDATE organization SET plan=Professional,<br/>plan_expires_at=now+30d
        BE->>DB: INSERT audit_log (category=billing, action=upgrade)
        BE->>RS: send "plan upgraded" receipt email
        BE-->>ST: 200
    end
```

**Architectural points illustrated:**
- Signature verification is **non-negotiable** before parsing the body (§06 Security §10, §07 Integrations §2.3).
- Idempotency is a **table** (`stripe_event`, §05 Data §8) keyed by Stripe's event id. Stripe retries → no-op.
- Receipt email goes through **Resend** from `nanoasm.com`, not Stripe's default mailer (§07 Integrations §3.5).
- Audit log row is written within the same transaction as the plan change.

---

## 5. API key authentication → finding update

**SRS modules touched:** 04 (Findings), 17 (API Access)

```mermaid
sequenceDiagram
    autonumber
    participant CL as Customer script
    participant BE as Backend
    participant DB

    CL->>BE: PATCH /api/findings/FD2317<br/>Authorization: Bearer ag_sk_xxxx<br/>{status: "resolved"}
    BE->>BE: parse token, recognise ag_sk_ prefix
    BE->>BE: hash candidate
    BE->>DB: SELECT api_key WHERE prefix_hint AND hash
    DB-->>BE: row {org_id, key_id}
    BE->>BE: rate-limit check (per-key + per-IP)
    BE->>BE: route is decorated @allow_api_key ✓
    BE->>BE: g.user = synthetic ApiKeyIdentity(org_id, key_id)
    BE->>DB: SELECT finding WHERE display_id=FD2317<br/>AND organization_id = g.user.org_id
    DB-->>BE: row
    BE->>DB: UPDATE finding SET status='resolved'
    BE->>DB: INSERT audit_log (actor=api_key:<key_id>, action=finding_update)
    BE-->>CL: 200 {finding}
```

**Architectural points illustrated:**
- API key auth follows the same **tenant-scoping discipline** as JWT auth (§06 Security §6, §05 Data §3).
- The `@allow_api_key` decorator is the **default-deny** opt-in (FR-API-004): try the same call against `/billing/upgrade` and you get 403 `API_KEY_NOT_ALLOWED`.
- Audit log records the **API key id** as actor — when the key is revoked, the operator can correlate any damage (FR-API-014).
- The `display_id` (`FD2317`) is canonical in the URL (FR-API-013).

---

## 6. Free-tier expiry → 30-day grace → hard delete

**SRS modules touched:** 10 (Billing), 11 (Audit), 16 (Data retention)

```mermaid
sequenceDiagram
    autonumber
    participant SCH as Scheduler thread
    participant DB
    participant RS as Resend
    participant LG as Login route

    Note over SCH: every 6h: billing.expire_free_tier

    SCH->>DB: SELECT orgs WHERE plan=Free AND free_expires_at < now()<br/>AND is_login_blocked=false
    DB-->>SCH: orgs at day 90

    loop each
        SCH->>DB: UPDATE org SET is_login_blocked=true, grace_starts_at=now()
        SCH->>RS: send "free tier expired, 30 days to upgrade or delete"
        SCH->>DB: INSERT audit_log (category=billing, action=free_expired)
    end

    Note over LG: meanwhile, blocked user tries to log in
    LG->>DB: SELECT user/org
    LG->>LG: org.is_login_blocked → 403 FREE_TIER_EXPIRED
    LG-->>LG: response includes upgrade_url

    Note over SCH: grace tick: orgs at day 113, 117 → reminder emails
    Note over SCH: orgs at day 120 → hard delete

    SCH->>DB: SELECT orgs WHERE is_login_blocked=true<br/>AND grace_starts_at < now() - INTERVAL '30 days'
    DB-->>SCH: orgs at day 120
    loop each
        SCH->>DB: DELETE org (CASCADE → assets, scans, findings, members, audit, ...)
        SCH->>RS: send "account deleted" final notice
    end
```

**Architectural points illustrated:**
- The whole lifecycle (§05 Data §8 retention) is enforced by **one scheduled job**, not threaded through the request path.
- Login-block is a **separate flag** (`is_login_blocked`) from suspension; the user gets a distinct error message and an upgrade path.
- Hard delete is a **DB cascade** — every tenant-scoped table has its FK to `organization` set up so a single `DELETE` removes the lineage in one transaction (§05 Data §11 expand-contract discipline applies).
- An upgrade during grace flips the flag back, restoring access; nothing has been deleted yet.

---

## 7. Audit log → customer SIEM webhook

**SRS modules touched:** 11 (Audit), 12 (Integrations)

```mermaid
sequenceDiagram
    autonumber
    participant ROUTE as A privileged route
    participant AUDIT as audit.log_audit
    participant DB
    participant FW as audit/webhook.py
    participant SIEM as Customer SIEM endpoint

    Note over ROUTE: e.g. user updated a setting
    ROUTE->>AUDIT: log_audit(category=settings, action=update, target=...)
    AUDIT->>DB: INSERT audit_log (within outer txn)
    AUDIT->>AUDIT: snapshot row → plain dict
    AUDIT->>FW: forward_audit_event(snapshot, org_id) [daemon thread]
    Note over ROUTE,DB: outer txn commits — request continues / completes
    ROUTE-->>ROUTE: response sent

    Note over FW: in daemon thread, after commit
    FW->>FW: HMAC-SHA256 sign body with org's whsec_*
    FW->>SIEM: POST customer URL<br/>X-Nano-Signature: sha256=...<br/>X-Nano-Event-Id: <uuid><br/>X-Nano-Event-Type: settings
    alt 2xx within 10s
        SIEM-->>FW: 200
        FW->>DB: INSERT audit_webhook_delivery (status=success)
    else timeout / non-2xx
        FW->>DB: INSERT audit_webhook_delivery (status=failed, error=...)
    end
```

**Architectural points illustrated:**
- Audit row is committed **before** webhook fires (§05 Data §9.3) — the snapshot is plain dict because SQLAlchemy instances cannot cross thread boundaries and the row's transaction isn't visible to a background session.
- Webhook is **fire-and-forget**: a customer SIEM going down does not roll back the user's settings change.
- Per-event UUID enables idempotency on the receiver (§07 Integrations §8.1).
- Plan-gated to Enterprise Gold + Custom; non-eligible orgs simply have no forwarder configured (silent no-op).

---

## 8. Cross-tenant isolation guard (illustrative)

**SRS modules touched:** all (this is a property, not a feature)

The most security-critical scenario is the one we *don't* want to happen — user A reading user B's data. The architecture guards this with three layers (§06 Security §8). An illustrative attempted attack:

```mermaid
sequenceDiagram
    autonumber
    participant A as User A (org X)
    participant FE as Frontend
    participant BE as Backend
    participant DB

    A->>FE: discover/guess display_id "AS9999" belongs to org Y
    A->>BE: GET /assets/AS9999<br/>Authorization: Bearer <A's JWT>
    BE->>BE: g.user.org_id = X (from JWT)
    BE->>DB: SELECT asset WHERE display_id=AS9999<br/>AND organization_id = X
    DB-->>BE: 0 rows
    BE-->>A: 404 NOT_FOUND
```

**Architectural points illustrated:**
- Tenant scoping is in the **query**, not the serializer (§05 Data §3.2). The DB never returns the row.
- The error is **404, not 403** — we don't reveal "this id exists but you can't see it."
- Even if Display ids are guessable (they are; they're monotonic per-tenant), the guess is harmless because the cross-tenant lookup returns nothing.
- The same pattern protects scan jobs, findings, members, monitors, reports, audit log entries, and every other tenant-scoped resource.

---

## 9. Backend container restart with in-flight scans

**SRS modules touched:** 07 (Scanning), 16 (Reliability NFRs)

```mermaid
sequenceDiagram
    autonumber
    participant OP as Operator
    participant BE as Backend (old)
    participant TP as Thread pool (old)
    participant DB
    participant BE2 as Backend (new)
    participant SCH as Scheduler thread (new)

    Note over BE,TP: 3 scans running in thread pool
    OP->>BE: docker compose up -d --build (SIGTERM)
    BE->>TP: scheduler.shutdown(wait=True)
    Note over TP: continues writing findings briefly
    BE->>BE: --graceful-timeout 30s elapses
    TP--xBE: SIGKILL
    Note over DB: 3 scan_job rows still status=running

    Note over BE2: container starts
    BE2->>SCH: init_scheduler() runs reconciliation pass
    SCH->>DB: SELECT scan_job WHERE status=running<br/>AND last_heartbeat_at < now() - INTERVAL '15 min'
    DB-->>SCH: 3 rows
    SCH->>DB: UPDATE scan_job SET status=failed,<br/>error_code=BACKEND_RESTART
    Note over BE2: stale findings already written remain<br/>(idempotent by (job, template, target))
    Note over BE2: scheduler resumes normal duties
```

**Architectural points illustrated:**
- Graceful shutdown gets 30 seconds (§02 Runtime §9). Scans that finish within that window land cleanly; longer ones are killed.
- Reconciliation pass on boot (§02 Runtime §10) is the only recovery — we don't auto-resume.
- Findings already written are kept; idempotent insert key prevents double-count on a manual rerun.
- The user sees the failed job in the UI and may rerun manually.

This is also the scenario that motivates the future **decouple long-running scans onto worker hosts** scaling step (§04 Deployment §10 step 5) — at that point the worker host outliving the API host stops being a workaround.

---

## 10. Superadmin impersonation

**SRS modules touched:** 11 (Audit), platform-admin (CLAUDE.md)

```mermaid
sequenceDiagram
    autonumber
    participant SA as Superadmin
    participant FE as Frontend
    participant BE as Backend
    participant DB

    SA->>FE: at /admin/users, click "Impersonate" on user U (org Y)
    FE->>BE: POST /admin/users/<U>/impersonate
    BE->>BE: require_superadmin (re-fetch user from DB)
    BE->>DB: INSERT audit_log (organization_id=NULL, action=impersonate_start, target=U)
    BE->>BE: issue normal session token for U (org_id=Y, role=U.role)
    BE-->>FE: 200 {access_token, user_summary}
    FE->>FE: store admin's own JWT in localStorage[asm_impersonate_return]
    FE->>FE: store {asm_impersonating: true} flag
    FE->>FE: replace current JWT with U's
    FE->>FE: render amber banner "Impersonating U — Exit impersonation"

    Note over SA,FE: SA browses as U, all subsequent actions are U's<br/>(but the underlying actor is audit-logged on every action)

    SA->>FE: click "Exit impersonation"
    FE->>FE: read asm_impersonate_return → restore SA JWT
    FE->>FE: clear asm_impersonating flag
    FE->>BE: navigate to /admin/users
    BE->>DB: INSERT audit_log (organization_id=NULL, action=impersonate_end)
```

**Architectural points illustrated:**
- `require_superadmin` re-fetches user from DB **every request** (§06 Security §15) — JWT-only trust is insufficient, a revoked superadmin loses access on the next click.
- Impersonate **issues a normal session** for the target user; the system itself can't tell the difference downstream. This means tenant-scoping continues to work without special cases.
- Audit log captures both ends (`impersonate_start` / `impersonate_end`) with `organization_id=NULL` (platform-level action) and the target user as the audit target. Subsequent actions during impersonation are audit-logged as the target user, with metadata noting the impersonator.
- Superadmin cannot impersonate another superadmin (privilege escalation guard).

---

## 11. What scenarios view does not show

- The static module structure → §01-logical-view
- The runtime process model that powers the sequences → §02-runtime-view
- Code organisation supporting these flows → §03-development-view
- Deployment topology these flows run on → §04-deployment-view
- Schemas of the tables these flows touch → §05-data-architecture
- Auth and tenant-scoping primitives → §06-security-architecture
- Vendor-specific contracts → §07-external-integrations
- How we observe these flows in production → §08-observability

---

*End of view 09 — Key scenarios.*
