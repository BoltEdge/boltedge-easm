# 08 — Backup, Recovery, and Disaster Recovery (DR)

| Field | Value |
|---|---|
| Document | 08 — Backup & DR |
| Owner | Founder / sole engineer (acting as Production Operator) |
| Status | Draft |
| Last reviewed | 2026-05-05 |
| Next review | 2026-08-05 (quarterly) |
| Related docs | `03-sad/04-deployment-view.md`, `03-sad/05-data-architecture.md`, `05-security-policy.md`, `09-sla.md` (forthcoming) |

---

## 1. Purpose

This document describes how we **back up** Nano EASM data, how we **recover** from common failures, and how we plan to handle a **disaster** (loss of host, region, or significant data corruption). It also contains the runbooks the operator follows during an incident.

It is the single source of truth for "what do I do when production is on fire?"

---

## 2. Goals: RPO and RTO

| Metric | Definition | Current target |
|---|---|---|
| **RPO** (Recovery Point Objective) | Maximum acceptable data loss, measured in time | **24 hours** |
| **RTO** (Recovery Time Objective) | Maximum acceptable downtime to restore service | **4 hours** for SEV-1 |

These are operator-side commitments today; they harden into customer-facing commitments in `09-sla.md`. The numbers reflect single-host, single-region reality. They tighten as we move to multi-AZ / multi-region (SAD §04 Deployment §10).

---

## 3. What we back up

| Data | Backup mechanism | Retention | Where it lives |
|---|---|---|---|
| **PostgreSQL** | Nightly `pg_dump` (logical backup) | 30 nightly + 12 monthly | EBS volume on host; S3 bucket in `us-east-1` (planned, not yet) |
| **EBS volume snapshot** | Nightly snapshot via AWS Backup | 30 nightly + 12 monthly | AWS Backup vault, `us-east-1` |
| **Application logs** | Rotated locally; not backed up | 5 × 100 MB rotation | Host EBS only |
| **Generated reports (PDF/Excel)** | Regenerable from DB on demand; not backed up | n/a | Host EBS |
| **Configuration (`.env` files)** | Stored separately; **not** in version control | – | Operator's password manager (canonical copy) + EC2 host |
| **Repository** | GitHub origin is the canonical source | Forever | GitHub |

**What we deliberately do not back up:** logs (size; not customer-critical), generated reports (regenerable), Docker images (rebuildable from `git`).

---

## 4. Backup procedures

### 4.1 Nightly `pg_dump` (current, manual host cron)

A cron job on the EC2 host runs nightly:

```
00 03 * * *  /home/ubuntu/scripts/pg_backup.sh
```

The script:
1. Runs `docker compose exec -T easm-db pg_dump -U easm_user -F c easm > /home/ubuntu/backups/easm-$(date +%Y-%m-%d).dump`
2. Computes a SHA-256 checksum of the dump.
3. Prunes dumps older than 30 days (excluding the 1st of each month, which is kept for 12 months).
4. Logs to `/home/ubuntu/backups/backup.log`.

**Known gap:** dumps live on the same EBS volume as the source data. A volume failure loses both. The remediation — copying dumps to S3 — is on the to-do list but not yet implemented. Until then, the EBS snapshot (§4.2) is the off-volume copy.

### 4.2 Nightly EBS snapshot (current)

AWS Backup is configured with a daily snapshot of the EC2 instance's root + data EBS volumes:

- **Schedule:** 03:30 UTC, after `pg_dump` completes.
- **Retention:** 30 daily + 12 monthly.
- **Encryption:** AWS-managed key (default for new gp3 volumes).
- **Vault:** default AWS Backup vault, `us-east-1`.

The snapshot is a **physical** copy of the volume — by definition consistent at the snapshot time, but Postgres is mid-flight unless we coordinate. Practically, Postgres recovers from WAL on restart, which is acceptable. For the daily logical backup we rely on `pg_dump` (§4.1), which is application-consistent.

### 4.3 Off-host copy (planned, not yet implemented)

The next backup hardening step:

1. Create an S3 bucket `nano-easm-backups` in `us-east-1` with versioning, SSE-KMS, and a lifecycle rule (transition to Glacier after 90 days, expire after 365).
2. Extend the cron script to `aws s3 cp` the dump after creation.
3. Apply a bucket policy that denies delete to the EC2 instance role except for explicit lifecycle.
4. Test restore from S3 on the next quarterly drill.

This is the highest-priority backup gap. Tracked in `00-positioning-pivot-tasks.md`.

### 4.4 Verification

A backup that has never been restored is a hope, not a backup. We verify:

- **Daily:** the cron script's exit code; failure emails the operator.
- **Weekly:** size and timestamp check that the latest dump exists and is non-trivially sized.
- **Quarterly:** **full restore drill** — restore the latest dump to a non-production environment, run schema migration, verify a sample query, confirm row counts match expected.

The quarterly drill is recorded in `docs/dr-drills/` (when established) with date, duration, dump size, restore time, anomalies found.

---

## 5. Recovery procedures (runbooks)

Each runbook is a **numbered, executable** procedure. The operator follows it step-by-step during an incident; deviating from the runbook requires the operator to record why.

### 5.1 SOP — Restore database from `pg_dump`

**Scenario:** Database corruption, accidental destructive operation, need to recover yesterday's state.

```
PRE-CHECK
1. Confirm the incident (queries returning wrong results; constraint errors; user reports).
2. Notify customers via status channel — SEV-1.
3. Take a fresh dump of current state if possible (so we can investigate later):
     docker compose exec -T easm-db pg_dump -U easm_user -F c easm > /tmp/pre-restore.dump

RESTORE
4. Identify the dump to restore from:
     ls -lh /home/ubuntu/backups/
   Pick the most recent good dump (typically last night).
5. Stop the backend and frontend (preserve DB container running):
     cd ~/boltedge-easm
     docker compose stop easm-backend easm-frontend
6. Drop and recreate the database:
     docker compose exec -T easm-db psql -U easm_user -d postgres \
       -c "DROP DATABASE easm; CREATE DATABASE easm OWNER easm_user;"
7. Restore the dump:
     docker compose exec -T easm-db pg_restore -U easm_user -d easm \
       --no-owner --no-privileges < /home/ubuntu/backups/easm-YYYY-MM-DD.dump
8. Apply any migrations introduced after the dump:
     docker compose start easm-backend
     docker compose exec easm-backend flask db upgrade
9. Smoke-check:
     curl https://nanoasm.com/api/health
     # log in as a known user, view dashboard, verify data shape
10. Bring the frontend up:
     docker compose start easm-frontend
11. Notify customers — service restored. Provide RCA timeline.

POST
12. Decide if any data loss between dump and incident needs customer-side reconciliation.
13. Schedule post-mortem within 5 business days.
```

### 5.2 SOP — Recover from EBS snapshot (volume failure)

**Scenario:** EBS volume corruption, instance disk failure, snapshot-level recovery needed.

```
1. SEV-1 declared; status notification sent.
2. AWS console: identify the latest healthy snapshot.
3. Create a new EBS volume from the snapshot (same AZ as the EC2 instance).
4. Stop the EC2 instance.
5. Detach the corrupt volume; attach the new volume in its place (same device name).
6. Start the EC2 instance.
7. SSH in. Verify Docker volumes mount; run `docker compose up -d`.
8. Smoke-check `/api/health`, log in, verify data.
9. Apply any migrations introduced after the snapshot was taken (if applicable).
10. Notify customers — service restored.
```

### 5.3 SOP — Recover from total instance loss

**Scenario:** EC2 instance is unrecoverable (AZ event, hardware failure, accidental termination).

```
1. SEV-1 declared; status notification sent.
2. AWS console: launch a new EC2 t2.medium in us-east-1 (any healthy AZ).
   Use the most recent AMI / OS we run (Ubuntu 24.04).
3. Reattach the Elastic IP `34.232.100.29` to the new instance.
4. SSH in. Install Docker:
     sudo apt-get update && sudo apt-get install -y docker.io docker-compose-plugin
5. Restore configuration files:
     mkdir -p ~/boltedge ~/boltedge-easm
     # restore .env from password manager (canonical copy)
     # restore docker-compose.yml from the git repo (clone it):
     git clone https://github.com/<org>/boltedge-easm.git ~/boltedge-easm
6. Recover data: either
   (a) attach the most recent EBS snapshot as a new volume, or
   (b) restore the latest pg_dump if the snapshot is unavailable.
7. Mount the data volume; ensure Docker volume `easm_db_data` points to it.
8. docker compose up -d --build
9. flask db upgrade if migrations are pending.
10. Smoke-check.
11. Restore Nginx (~/boltedge) configuration similarly.
12. Verify TLS cert renewal: certbot renew --dry-run.
13. Notify customers.

Estimated wall-clock: 60–120 minutes if all artifacts are at hand.
```

### 5.4 SOP — Rollback a bad deploy

**Scenario:** A deploy introduced a regression; the previous SHA was healthy.

```
1. Identify previous good SHA from `git log` on the host.
2. cd ~/boltedge-easm
3. git fetch && git checkout <prev-sha>
4. docker compose up -d --build
5. If the bad deploy ran a forward-only migration, do NOT auto-rollback the migration.
   Instead: leave the schema as-is and rely on the previous code being forward-compatible
   with the new schema (which our expand-contract migration discipline guarantees for one
   step). If the schema is incompatible with the previous code, escalate to 5.1 (restore).
6. Smoke-check.
7. File an issue with the bad SHA, the symptoms, and the rollback trigger.
8. Investigate root cause and ship a forward fix.
```

### 5.5 SOP — Compromised credential / API key

**Scenario:** A user reports their API key was committed to a public GitHub repo, or an integration secret leaked.

```
1. Confirm the leak (visit the URL, verify the key value).
2. Revoke the key immediately:
   - For a customer API key: the customer can revoke via Settings → API Keys.
     If they cannot reach the UI fast enough, superadmin revokes via DB:
       UPDATE api_key SET revoked_at = NOW() WHERE id = ...;
   - For our own vendor key (Stripe, Resend, Shodan): rotate via the vendor dashboard.
3. Check the audit log for any usage of the key after the suspected leak time.
   Customer-facing actions taken with the leaked key are audit-logged with actor=api_key:<id>.
4. Notify the affected party (customer or internal) with the activity timeline.
5. If the leak was internal vendor key:
   - Update .env on the host.
   - docker compose restart easm-backend.
6. File an issue: leak source, time-to-detect, time-to-revoke, follow-ups (secret scanning, etc.).
```

### 5.6 SOP — Compromised superadmin

**Scenario:** Superadmin credentials suspected compromised.

```
1. SEV-1; treat as active intrusion until proven otherwise.
2. Revoke the suspect superadmin via SSH to the host:
     docker compose exec easm-backend flask revoke-superadmin <email>
3. Force log-out of all sessions for that user:
     # rotate JWT secret to invalidate ALL JWTs platform-wide:
     # update SECRET_KEY in .env, then:
     docker compose restart easm-backend
   This logs out everyone — accept the user impact.
4. Pull audit log for that user's actions — every privileged action since suspected compromise.
   Identify: tenant data viewed, plan changes made, broadcasts sent, IPs blocked, users impersonated.
5. Notify any affected tenants whose data was accessed.
6. Reset the suspect user's password via CLI; force MFA enrolment (when available).
7. Investigate root cause (laptop loss, credential theft, etc.).
8. Re-grant superadmin only after investigation closes.
```

### 5.7 SOP — Stripe webhook / billing outage

**Scenario:** Stripe is down; customers cannot upgrade.

```
1. Confirm via status.stripe.com.
2. UI behaviour today: /billing/checkout returns 503 with retry copy. No further action needed.
3. If outage lasts > 1 hour, post a status update for affected customers.
4. After Stripe recovers, verify:
   - any pending checkouts processed correctly,
   - any missed webhooks were retried by Stripe (they retry up to 3 days),
   - no plan-state drift between our DB and Stripe.
5. If drift is detected, run the (planned) reconciliation job that pulls customer state from Stripe.
   Until that job exists, the operator manually corrects the small number of affected rows.
```

### 5.8 SOP — TLS cert renewal failure

**Scenario:** certbot has not renewed and the cert is approaching expiry (< 7 days).

```
1. SSH to host. Run certbot renewal manually:
     sudo certbot renew --force-renewal --no-random-sleep-on-renew
2. If it succeeds: reload Nginx (cd ~/boltedge && docker compose exec nginx nginx -s reload).
3. If it fails:
   - Check for rate-limit (LE production rate-limits: 5 duplicate certs per week).
   - Check DNS — is nanoasm.com resolving to our Elastic IP?
   - Check port 80 — is it reachable for the LE challenge?
4. If LE rate-limited, request a manual cert via the LE staging environment first to validate config,
   then production again after the rate window passes.
5. As a fallback, issue a Cloudflare-origin or AWS ACM cert and re-config Nginx to use it.
```

---

## 6. Disaster recovery scenarios (broader)

### 6.1 Single-AZ outage

**Impact:** Full outage for the duration of the AZ event.

**Today's response:**
1. Confirm via AWS Health.
2. Wait for AZ recovery (typical: < 4 hours for a partial event).
3. If recovery exceeds RTO, manually launch a new EC2 in another AZ in `us-east-1` and follow §5.3.
4. Communicate via status channel.

**Future (post multi-AZ):** automatic failover handled by ALB + multi-AZ EC2/RDS.

### 6.2 Region outage

**Impact:** Full outage; longest recovery window today.

**Today's response:**
1. Confirm via AWS Health.
2. **No documented multi-region DR plan today** — explicitly out of scope for current scale.
3. Wait for region recovery, OR perform manual region-failover:
   - Restore latest pg_dump to a new EC2 in another region (`us-west-2` is closest).
   - Update Route 53 to point `nanoasm.com` to the new instance.
4. Customer impact: all data later than the most recent S3-backed dump (when implemented) is lost.

**This is an explicit risk we accept** at single-region scale. Documented for Enterprise customer review. Mitigated by:
- Single-region SLA commitment (we don't promise multi-region today).
- Multi-region is on the SAD scaling path (§04 Deployment §10 step 6).

### 6.3 Data corruption (logical, e.g. bad migration)

**Impact:** Severity depends on what's corrupted; can range from "one table" to "unable to log in."

**Response:**
1. **Stop writes** — take backend offline if the corruption is spreading.
2. Take an emergency dump of current state.
3. Restore from the most recent pre-corruption dump (§5.1).
4. **Replay** any customer-significant operations between dump and corruption time, if recoverable from logs.
5. Communicate clearly with affected customers about what was lost.

### 6.4 Ransomware / hostile data destruction

**Impact:** Crown-jewel scenario.

**Response:**
1. Disconnect the affected host from the internet immediately (security group → no inbound).
2. Preserve the affected disks for forensic analysis (do NOT reboot — forensic data is in RAM).
3. Bring up replacement infrastructure from backup (§5.3) on a fresh host.
4. Engage incident response per `05-security-policy.md` §10.
5. Notify customers, regulators, payment processor.
6. Forensic analysis of the disks; root-cause investigation.

The off-host backup gap (§4.3) is most acute here — until S3 dumps are in place, ransomware that reaches the EBS volume could destroy the dumps too. The EBS snapshots (in AWS Backup vault, separately encrypted) are the current defence; AWS Backup vault access is IAM-protected and can be locked down further with Vault Lock policies.

---

## 7. Communication during an incident

| Phase | Channel | Audience |
|---|---|---|
| Incident detected | Internal chat thread | Operator + (future) team |
| Customer-affecting confirmed | Status channel (`status.nanoasm.com` — planned), customer email | Customers |
| In-progress updates | Status channel, every 30 minutes for SEV-1 | Customers |
| Resolved | Status channel + post-mortem follow-up | Customers |
| Post-mortem | Email + customer-portal post within 5 business days | Customers (affected); internal record |

A status page is on the planned-list (currently we use a banner in the app + email). The status channel will be Statuspage / BetterStack-style.

---

## 8. Post-incident review

Every SEV-1 and SEV-2 incident gets a post-mortem within 5 business days. Template:

```
## Post-Mortem: <title>

**Incident date:** <date>
**Severity:** SEV-<n>
**Duration:** <start> → <end>
**Customer impact:** <quantified — orgs affected, requests failed, data lost>

## Timeline
HH:MM — what happened
HH:MM — what we did

## Root cause
<the actual technical / process cause>

## What went well
- ...

## What went badly
- ...

## Action items
- [ ] <fix> — owner, target date
- [ ] <improvement> — owner, target date
```

Action items become tracked work; fixes that are systemic (not just for this incident) become test cases or ADRs.

---

## 9. Operator readiness

The operator on duty is expected to:

- Have **SSH key + password manager** on a charged, FDE-encrypted laptop.
- Have **2FA tokens** for AWS, GitHub, Stripe, Resend on at least two devices.
- Have read this document recently enough to recognise the runbook flow.
- Know how to reach the rest of the team (when there is a team).

The operator is **not** expected to memorise commands — the runbooks are the source of truth. Reading the runbook during an incident is correct behaviour; deviating from it without recording why is not.

---

## 10. Future hardening (priority order)

1. **S3-backed dumps** (§4.3). The largest backup gap.
2. **Status page** (§7). Customers should not have to email to learn we're down.
3. **Automated alerting** for backup job failure beyond email. PagerDuty or similar.
4. **Stripe reconciliation job** (§5.7). Closes drift after long Stripe outages.
5. **Multi-AZ** for the database (move to RDS multi-AZ — §04 Deployment §10 step 2).
6. **Quarterly DR drill** including a region-failover dry run on staging.
7. **Vault Lock** on AWS Backup to make snapshots ransomware-resistant.
8. **Documented multi-region DR plan** for an Enterprise prospect that requires it.

---

## 11. References

- `03-sad/04-deployment-view.md` §11 — failure domains and blast radius
- `03-sad/05-data-architecture.md` §8 — retention table (the input to backup retention)
- `05-security-policy.md` §15 — policy commitments (RPO / RTO numbers, drill cadence)
- `09-sla.md` (forthcoming) — customer-facing uptime / response commitments derived from these RTO/RPO values
- AWS shared responsibility model — what AWS does for us at the infrastructure level

---

*End of 08 Backup, Recovery, and DR.*
