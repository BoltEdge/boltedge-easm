# 06 — Test Strategy

| Field | Value |
|---|---|
| Document | 06 — Test Strategy |
| Owner | Founder / sole engineer |
| Status | Draft |
| Last reviewed | 2026-05-05 |
| Related docs | `02-srs.md`, `03-sad.md`, `04-threat-model.md`, `07-uat-plan.md` (forthcoming) |

---

## 1. Purpose

This document describes **what we test, how, and why**. It is the contract between the SRS / SAD (which prescribes *what the system must do*) and the implementation (which *should*, but proves it through tests).

The strategy is sized for a one-engineer team. It deliberately avoids ceremony that would not pay off at this scale. As the team grows, the cadences and gates here tighten.

---

## 2. Goals and non-goals

**Goals:**
- Catch regressions before they reach production.
- Establish behavioural invariants that guard load-bearing requirements (tenant isolation, RBAC, plan limits, audit logging).
- Make every PR provably green or provably broken — no "tests fail intermittently, just rerun."
- Test pyramid that biases toward fast, focused tests with a thin slice of integration / end-to-end.

**Non-goals:**
- A coverage-percentage metric as a hard CI gate. Coverage is reported, not enforced. The bar is judgement, not a number.
- Manual QA as the primary gate. Manual checks happen for visual / UX work; behavioural correctness is automated.
- 100% reliable end-to-end suite. We accept some flakiness in E2E in exchange for testing real flows; flaky tests are quarantined and fixed, not deleted.

---

## 3. Test pyramid

```
           E2E (Playwright)
          ┌────────────┐         ← few; slow; real browsers; smoke
          │            │
       Integration (pytest + Postgres)
      ┌──────────────────┐       ← many; medium; HTTP-level routes against real DB
      │                  │
            Unit (pytest / vitest)
      ┌──────────────────────┐   ← lots; fast; pure functions, components, hooks
```

Approximate target shape:

| Layer | What it tests | Speed | Numbers |
|---|---|---|---|
| Unit (backend) | Pure logic, validators, formatters, scoring math, finding template registry | < 5 ms each | many hundreds |
| Unit (frontend) | Component rendering, hook behaviour, utilities | < 50 ms each | dozens |
| Integration (backend) | Routes end-to-end against real Postgres; auth, tenant scoping, RBAC, plan limits | 100 ms – 2 s each | many hundreds |
| End-to-end | Critical user journeys in a real browser | 5 – 30 s each | a handful |

The **load-bearing layer is integration**. That is where most bugs live (route + DB + auth interaction) and where most invariants are best expressed.

---

## 4. Tooling

### 4.1 Backend

- **`pytest`** — runner, fixtures, parametrisation.
- **`pytest-cov`** — coverage reporting (not gating).
- **`pytest-xdist`** — parallel test execution.
- **`Faker`** — synthetic data generation.
- **Real PostgreSQL 16** — integration tests against a per-test ephemeral database (template + clone, or fast truncate-between-tests).
- **`responses` / `pytest-httpx`** — HTTP mocking for `app/services/*` external calls.

### 4.2 Frontend

- **`vitest`** — unit test runner.
- **`@testing-library/react`** — component testing.
- **`msw`** — API mocking at the network boundary, not via spying on `fetch`.
- **`playwright`** — end-to-end browser tests.

### 4.3 Lint and static analysis

- `ruff` (format + lint) for backend Python.
- `mypy` for backend type checks.
- `eslint` for frontend.
- `tsc --noEmit` for frontend type checks.

---

## 5. Backend testing

### 5.1 Unit tests

Live in `backend/tests/unit/` (or colocated `tests/` per blueprint). Constraints:

- **No DB.** A unit test must not require Postgres. If it does, it is an integration test.
- **No network.** External clients are stubbed at the module boundary.
- **Fast.** A unit test that takes more than 5 ms is suspect.
- **Pure where possible.** Functions of inputs to outputs are easiest to test; design for that.

What lives here:
- Validators (`utils/validators.py`): IP, domain, port, severity coercion.
- Formatters (`utils/formatters.py`): display id construction, time formatting.
- Score math: risk-score computation given findings list.
- Compliance map lookups: CWE → ASVS / CIS / NIST CSF.
- Finding template registry: every template has the required fields.
- Pure helpers across `app/`.

### 5.2 Integration tests

Live in `backend/tests/integration/`. Constraints:

- **Real Postgres.** Mocking the DB in integration tests is **forbidden** (CLAUDE.md feedback rule — prior incident where mock/prod divergence masked a broken migration). The test database is ephemeral, schema applied via `flask db upgrade`.
- **HTTP-level interface.** Tests call routes via the Flask test client; they don't reach into service functions directly.
- **External services mocked at the client boundary.** `services/shodan_client.py` is mocked; we don't call Shodan in CI.
- **Each test seeds its own data** (an org, a couple of users, a couple of assets). Fixtures keep this terse.

#### What every tenant-scoped route test must include

For every route that reads or mutates tenant-scoped data, three test shapes:

```
def test_route_happy_path(...): ...
def test_route_other_org_returns_404(...): ...      # cross-tenant leak guard
def test_route_role_gate(...): ...                  # RBAC: viewer → 403 if mutating, etc.
```

The cross-tenant test is the **single most important integration-test pattern in the codebase**. It is the regression check for the highest-risk failure mode (T-12 in the threat model).

#### What every plan-limited operation must include

```
def test_route_within_limit(...): ...
def test_route_at_limit_returns_402_or_403(...): ...
def test_route_with_per_org_override(...): ...
```

#### Audit-log assertions

Tests for routes that should produce an audit entry assert the entry appears with correct category / action / target. Missing audit log is a bug class — tests catch it.

### 5.3 Migration tests

- Every Alembic migration is reviewed by hand before commit.
- A migration that includes data movement is tested with a representative seed: apply migration, verify pre/post data shape.
- A migration that adds a NOT NULL column is tested for backfill correctness on a populated DB.
- Migrations are idempotent where possible (`IF NOT EXISTS`); idempotency is tested by running the migration twice in CI.

### 5.4 Background-job tests

Scheduled jobs (`monitoring.run_due_monitors`, `billing.expire_free_tier`, etc.) are tested:

- Time is parametrised — we do not `sleep`. A test fixture sets `now()` and verifies the right rows were picked.
- Idempotency under double-tick is tested explicitly.
- Side effects that fan out to external services (email, webhook) are mocked at the client boundary; the test asserts the side effect was *attempted*, not delivered.

### 5.5 Service-client tests

`app/services/<vendor>_client.py` modules are tested with `responses` / `pytest-httpx`:

- Happy path, 4xx (and what we propagate), 5xx (and what we retry / give up on), timeout, missing API key.
- The interface presented to the rest of the app (return shapes, exception types) is the contract; tests assert against it.

### 5.6 Generated artefact tests

- The finding-template catalogue (`docs/finding-templates.md`) drift check runs in CI: `python backend/scripts/generate_catalogue.py --check`.
- The pre-commit hook prevents drift locally.

---

## 6. Frontend testing

### 6.1 Unit / component tests

- Component rendering (presentational components in `app/ui/`): renders without crashing, displays props correctly, handles edge cases (empty lists, loading, error states).
- Hook tests: state transitions, side effects.
- Utility functions in `app/lib/`: pure-function tests.

### 6.2 Integration tests (via `msw`)

For pages that orchestrate multiple API calls + state, integration tests render the page with `msw` mocking the API. We assert what the user sees, not what `fetch` was called with.

The `app/lib/api.ts` client is **not** mocked at the module level — `msw` intercepts at the network layer, which means we test the real client behaviour including auth header injection and error normalisation.

### 6.3 Visual / styling

We do not run automated visual regression today. PR screenshots in description plus reviewer judgement is the gate. We may adopt Chromatic / Percy if styling regressions become a recurring problem.

---

## 7. End-to-end tests

A small set of Playwright tests covers **golden paths** that span frontend + backend + DB:

| Scenario | What it validates |
|---|---|
| Register → verify email → login → see empty dashboard | Auth + verification + first-render |
| Add asset → run quick scan → see findings | Asset CRUD, scan kickoff, async polling, finding rendering |
| Create API key → use it via curl-like HTTP call → revoke | API key surface end-to-end |
| Login as Admin → invite Analyst → switch user → confirm reduced permissions | RBAC + multi-user |
| Trigger billing upgrade in test mode → confirm plan change reflected in UI | Billing surface |
| Hit `/admin` as non-admin → 404 | Superadmin oracle protection |

E2E tests run **only on `master` post-merge and pre-deploy**, not on every PR — they're slow and the integration tests already cover the building blocks. PR-level CI ensures no E2E test was broken structurally (linter / type check).

If an E2E flake recurs more than once, it is **quarantined** (skipped with a TODO and a tracking issue) and fixed within the same week. We do not "rerun until green."

---

## 8. Security testing

The threat model (`04-threat-model.md`) lists threats; the test strategy verifies the mitigations.

### 8.1 Tested by integration tests

- **T-12 cross-tenant data leak** — every tenant-scoped route has a "user from org B" test.
- **T-13 vertical privilege escalation** — every privileged route has a Viewer / Analyst / Admin / Owner matrix.
- **T-14 plan-limit bypass** — at-limit and over-limit tests.
- **T-20 API key calling non-opted route** — tests that 403 is returned.
- **T-31 audit log integrity** — append-only is tested by assertion (no edit / delete endpoint exists).
- **T-33 Stripe webhook signature** — bad-signature returns 400; good-signature processes; replay returns 200 idempotent.

### 8.2 Tested by unit tests

- **T-28 SQL injection** — covered structurally by SQLAlchemy parametrisation; we do not write specific SQLi tests because the risk is "did anyone string-concatenate SQL?" which is a code-review item, not a runtime test.
- **T-05 / T-16 XSS** — React's escape-by-default is structural; we do not write per-component XSS tests.

### 8.3 Tested by tooling

- **T-43 dependency compromise** — `pip list --outdated` quarterly; Dependabot when adopted.
- **T-47 secret committed** — pre-commit hook for known patterns; `gitleaks` in CI when adopted.

### 8.4 Tested manually / via external tooling

- **Pen-test cadence:** annual (or at major architectural changes) once we hold paid Enterprise customers. Internal review is the only check today.
- **DAST / SAST:** not in CI today. ASVS-aligned manual review covers the surface we have.

---

## 9. Performance testing

Performance is **not** in the regression suite today. We do not have a P50/P95 SLO commitment and the workload is modest.

Targeted performance tests when:
- A specific endpoint shows up in user-reported slowness or in the (future) APM trace data.
- We add a new feature whose query pattern is suspect (large fan-out, unbounded scan).
- Before any scaling step (vertical resize, RDS migration, multi-host).

The tooling, when needed, will be `locust` or `k6` against a dedicated performance environment. Not built today.

---

## 10. Compatibility testing

### 10.1 Browser matrix

| Browser | Version | Tier |
|---|---|---|
| Chrome | latest 2 | Tier 1 — fully supported, tested in E2E |
| Firefox | latest 2 | Tier 1 |
| Safari | latest 2 | Tier 1 |
| Edge | latest 2 | Tier 2 — manual smoke only |
| Older / niche browsers | – | Best-effort |

E2E tests run on Chromium by default; cross-browser runs occur pre-release.

### 10.2 Database / runtime matrix

- Postgres 16 — production target.
- We do not test against earlier Postgres versions; no contract to support them.
- Python 3.12 — production target. No multi-version testing.
- Node.js: whichever version is in the Next.js Docker base.

---

## 11. CI integration

CI runs on every PR via GitHub Actions (per §03 SAD Development View §6):

```
Lint  → Drift check  → Unit tests  → Integration tests  → Build
```

Mandatory gates:
- All linters pass.
- Catalogue drift check passes.
- All unit + integration tests pass.
- Both Docker builds succeed.

E2E tests run **post-merge to `master`** as a separate workflow before deploying.

CI must be **green to merge**. There is no "merge anyway" override; if a test is broken because of an external service blip, the test is fixed (mocked at the boundary) before merge, not bypassed.

---

## 12. Test data discipline

- Tests use **synthetic data** (`Faker`); no production PII anywhere in test fixtures or recorded HTTP responses.
- Test database is reset between tests; no state leakage.
- Production database is **never** the source of test data.
- A bug reproduction that requires a specific customer's data uses a **redacted, anonymised fixture** derived from that data, committed to the repo only after the customer's PII is removed.

---

## 13. Test code quality

Tests are first-class code:

- Tests are reviewed in PRs alongside the production code they test.
- A test that tests "the implementation" rather than "the behaviour" is a smell. We test what the system does, not how.
- Test names describe the behaviour: `test_admin_can_change_user_role`, not `test_change_role_function`.
- Fixtures live in `conftest.py` and are sized to be reusable; per-test setup is local.
- Each integration test creates exactly the state it needs and asserts exactly the outcome it cares about — no "test all the things" tests.

---

## 14. Failure handling

When a test starts failing:

1. **Don't disable.** Investigate first.
2. If the production code is broken, fix it (the test was correct).
3. If the test was wrong, fix the test. Document why the previous assertion was incorrect (commit message + comment if non-obvious).
4. If the test is genuinely flaky (timing, ordering), fix the flakiness — usually by removing time-of-day dependence, removing implicit ordering assumptions, or mocking I/O.
5. **Quarantine is a last resort.** A skipped test with a TODO is a debt; pay it down within the week.

---

## 15. UAT

User Acceptance Testing has its own document (`07-uat-plan.md`, forthcoming). The boundary:

- **This document** covers automated tests against the spec.
- **UAT** covers structured user-facing acceptance against the SRS — focused on end-to-end flows from a customer perspective, including human judgement on usability.

UAT runs:
- Before significant releases (major UI changes, billing flag flip, MFA launch).
- For each Enterprise customer onboarding.
- On a recurring smoke schedule (monthly).

---

## 16. Coverage targets

We **report** coverage but do not gate on a specific number. Reasonable targets:

| Layer | Target |
|---|---|
| Backend unit | ≥ 90% on `utils/`, `auth/`, `scanner/templates.py`, `compliance_map.py` |
| Backend integration | Every route with at least the three required test shapes (happy / cross-tenant / RBAC) |
| Frontend unit | ≥ 70% on components in `app/ui/` |
| End-to-end | ≥ 1 test per critical journey |

A PR that reduces coverage materially on a sensitive module is reviewed with that lens — coverage drop is a question, not a blocker.

---

## 17. Test ownership

| Test class | Owner |
|---|---|
| Backend unit / integration | The PR author |
| Frontend unit | The PR author |
| End-to-end | The PR author for any new critical flow |
| Security regressions | Security Lead reviews; PR author writes |
| Performance | Whoever shipped the regressing change owns the fix |

There is no separate QA function. Engineers own test correctness for the code they ship.

---

## 18. References

- `02-srs.md` — requirements that drive test cases
- `03-sad/03-development-view.md` §5–§6 — code-organisation and CI integration
- `03-sad/06-security-architecture.md` — security invariants tests must guard
- `04-threat-model.md` — threats and their tested mitigations
- `07-uat-plan.md` (forthcoming) — user-acceptance procedures
- CLAUDE.md "tests must hit a real database, not mocks" — primary feedback memory driving §5.2

---

*End of 06 Test Strategy.*
