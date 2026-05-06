# ADR 0007 — Single-Host EC2 Deployment, Docker Compose

| Field | Value |
|---|---|
| Status | Accepted |
| Date | 2026-05-05 |
| Deciders | Founder / sole engineer |
| Supersedes | – |
| Superseded by | – |

## Context

We need to run Nano EASM in production. The system is three containers (frontend, backend, database) plus a host-level Nginx reverse proxy. The team is one engineer. The customer count is small. Revenue is pre-paid-tier today (Free preview during launch), expected to ramp into paid tiers.

The deployment-platform decision sets the cadence for everything operational: how we deploy, how we observe, how we scale, how much surface we have to learn / pay for.

## Decision

Production runs on **a single AWS EC2 t2.medium instance, Ubuntu 24.04, with Docker Compose** orchestrating the application containers. A shared Nginx (also via Docker Compose, in a separate project at `~/boltedge/`) terminates TLS and reverse-proxies traffic.

- Region: `us-east-1`.
- Static Elastic IP, Route 53 A record for `nanoeasm.com`.
- TLS via Let's Encrypt with certbot on the host.
- Application is `~/boltedge-easm/` with `docker-compose.yml`.
- Deploy is `git pull && docker compose up -d --build` from the host.
- Database is a Postgres container with a Docker named volume on EBS.

## Considered alternatives

| Alternative | Why rejected (today) |
|---|---|
| **AWS ECS / Fargate** | Excellent target. Adds: task definitions, ALB, target groups, service auto-scaling, IAM roles, secrets manager wiring. Each piece is a half-day. Total: a week of platform work before the first deploy. Worth it once we need rolling restarts and zero-downtime; not yet. |
| **Kubernetes (EKS / k3s / kind on EC2)** | Massive overkill at single-host scale. Cluster operating cost dwarfs application cost. We'd be paying for an orchestrator with nothing to orchestrate. |
| **AWS App Runner** | Managed container hosting; much simpler than ECS. Constraints around stateful apps, scheduled jobs in-process, and our database hosting choice push it down the list. Could revisit at the "split DB to RDS" step. |
| **AWS Elastic Beanstalk** | Simpler than ECS, more opinionated. The opinions don't match ours (e.g. instance lifecycle assumptions). Not worth the friction. |
| **Render / Fly.io / Railway** | Solid PaaS options. They become attractive **if** we want a managed experience and are willing to pay the monthly tax. Today, raw EC2 + Docker Compose is the cheapest competent thing. |
| **Bare metal / on-prem** | No reason; not where customers expect SaaS to run. |

## Consequences

**Positive:**
- **Cheapest competent deployment.** ~$30/mo for the EC2 + EBS + Elastic IP, vs. several times that for managed alternatives.
- **Familiar.** SSH + `docker compose` is a tool every engineer knows. No learning curve, no proprietary API.
- **No vendor lock-in beyond AWS itself.** The same `docker-compose.yml` runs on any Docker host. We could move to Hetzner or DigitalOcean tomorrow with hours of work, not weeks.
- **Iteration speed is high.** "git push && ssh && pull && up" is faster than any ECS / EBS pipeline.

**Negative:**
- **Deploy has a brief blip** (5–15 s) during container swap. Acceptable while we are pre-paid-customer; not acceptable under SLAs.
- **No horizontal scaling.** Vertical-only — we go from t2.medium → t3.large → t3.xlarge before any architectural change.
- **No managed DB.** Postgres running in a container on EBS. We back it up nightly. A managed RDS would give us PITR, multi-AZ failover, automated minor-version upgrades — none of which we have.
- **Single-AZ.** AZ outage = full outage.
- **No staging environment.** Pre-production verification is local + CI. Acceptable while customer count is small.
- **TLS + DNS + cert renewal lives on the host.** certbot is reliable, but it's one more thing to monitor.

## Scaling path (recap from §04 Deployment §10)

1. Vertical first (t2.medium → t3.large → t3.xlarge).
2. Database off the app host (RDS, single-AZ first, multi-AZ when revenue justifies).
3. Externalise secrets (Secrets Manager / SSM).
4. Two backend containers behind ALB; rolling deploys.
5. Workers split off (queue + worker hosts).
6. Multi-region (EU residency).

Each step is independent. Each step changes one thing.

## Revisit conditions

We move to ECS / managed orchestration when **any** of these is true:
1. SLA commitments require zero-downtime deploys.
2. We onboard a customer that demands multi-AZ / multi-region.
3. We add a second engineer and the SSH-into-the-host operating model becomes a bottleneck.
4. Concurrent scan throughput requires a second backend host.

## References

- ADR 0003 (PostgreSQL) — DB on the same host today
- ADR 0004 (APScheduler) — depends on single-host election
- ADR 0008 (No cache/queue/search) — corollary; if we add Redis, ECS becomes more attractive
- §04 Deployment View — full topology

---
