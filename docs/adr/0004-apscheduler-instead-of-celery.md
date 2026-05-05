# ADR 0004 — APScheduler Instead of Celery / RQ

| Field | Value |
|---|---|
| Status | Accepted |
| Date | 2026-05-05 |
| Deciders | Founder / sole engineer |
| Supersedes | – |
| Superseded by | – |

## Context

Nano EASM has two kinds of asynchronous work:

1. **Scheduled jobs** — monitoring ticks, scan-schedule ticks, trial expiry, free-tier expiry, audit purge, quick-scan log pruning. Run on a clock.
2. **Long-running per-request work** — scans and discovery jobs kicked off from API requests. Need to return a 202 quickly and run in the background.

We need:
- A job runner.
- Time-based scheduling.
- Coordination so multiple Gunicorn workers don't all run the same tick.
- Acceptable failure isolation.

## Decision

We use **APScheduler's `BlockingScheduler` running in-process** inside one Gunicorn worker, elected via OS file lock. Long-running per-request work runs on a `ThreadPoolExecutor(max_workers=8)` shared across the scheduler and the request path.

- Single backend process owns the scheduler. The election is a file lock on `/tmp/easm-scheduler.lock`.
- If the scheduler-owning worker dies, the next-started worker acquires the lock.
- Jobs run synchronously on the scheduler thread; long actual work is dispatched to the thread pool so a slow scan doesn't block the next tick.
- Per-row coordination (don't run the same monitor twice if a tick takes longer than the cadence) uses Postgres `pg_try_advisory_lock` per `monitor_id`.

We do **not** use Celery, RQ, Dramatiq, SQS, or any external broker.

## Considered alternatives

| Alternative | Why rejected (today) |
|---|---|
| **Celery + Redis broker** | Two new processes (broker + worker), persistent state to manage, deploy complexity. Worth it at fleet scale; overkill at single-host. The death of the workers is also a real failure mode that needs ops attention. |
| **RQ (Redis Queue)** | Lighter than Celery but still requires Redis. Same calculus: not worth a new dependency for our throughput. |
| **Dramatiq + RabbitMQ / Redis** | Same as RQ's reasoning. |
| **AWS SQS + Lambda workers** | Couples us to AWS-specific dispatch. Cold-start latency for scans matters; warm Lambdas + concurrency tuning is a project. |
| **Cron on the host + HTTP triggers** | Decouples scheduling from the app cleanly, but every cron invocation has to take a lock too, and we'd still need an in-process executor for request-triggered scans. Solves half the problem at most. |
| **Celery beat for scheduling, plus thread pool for inline scans** | Same broker overhead. Only worth doing if we already had Celery for other reasons. |

## Consequences

**Positive:**
- Zero broker. No Redis to monitor. No worker fleet to deploy. Rollbacks are `docker compose down && up` end-to-end.
- Scheduled jobs and request-triggered jobs share the same thread pool, so capacity is one number to size.
- Postgres advisory locks give us the per-row coordination primitive without a separate lock manager.
- Job code is regular Python with regular Flask context (`with app.app_context(): ...`). No `@celery.task` decorators or task-discovery quirks.

**Negative:**
- Single-host bottleneck. The thread pool maxes at the host's CPU+IO budget. When concurrent scan throughput passes ~30–50, we hit the wall.
- No durable queue. If a scheduler-owning worker dies between "decide to run" and "submit to pool," the tick is missed. We accept this — next tick (5 minutes later) catches it. Idempotency on monitor advance + finding insertion makes a missed tick benign.
- Scheduler election is OS-level. If the file lock is somehow held without a live process (rare — process death releases the lock), the scheduler doesn't run until a worker restarts. Mitigation: monitor scheduler-tick freshness via the `/admin/health` page.
- Scan failure isolation is process-level. A scan that segfaults the worker takes down all in-flight work in that worker. (Doesn't happen in practice; we don't run native code in dangerous ways.)

## Revisit conditions

We move to a real broker when **any** of these is true:
1. Concurrent scan throughput target exceeds ~50 concurrent jobs sustained.
2. We deploy more than one backend host (a queue is the right cross-host rendezvous; file locks no longer work).
3. Scans need genuine isolation (separate process / container) for security or reliability reasons (e.g., running customer-supplied templates).
4. SLO commitments require durable scheduling guarantees ("exactly once" or "guaranteed within N minutes of schedule").

The most likely path is **Redis + RQ** — small footprint, similar mental model, much less ceremony than Celery.

## References

- ADR 0007 (Single EC2 deployment) — APScheduler is fit-for-purpose because of single-host
- §02 Runtime View §3 — scheduler implementation detail
- §02 Runtime View §10 — in-flight scan recovery on restart

---
