# Database Probe

**Module:** `backend/app/scanner/engines/db_probe_engine.py` + `backend/app/scanner/analyzers/exposed_db_analyzer.py`
**Detects:** Exposed and unauthenticated database services — MongoDB, Redis, Elasticsearch, MySQL, PostgreSQL, CouchDB, Cassandra. The engine takes Nmap's open-port output, identifies database ports, and tries a lightweight protocol handshake to confirm "an actual database is here and accepts connections"
**Plan gate:** Runs whenever Nmap runs (Deep scan profile). The engine has no separate profile flag — it activates when Nmap output contains database ports
**Severity:** Confirmed exposed-and-unauthenticated database → critical. Database port open but auth required → medium

## Required setup

None — the engine depends on the Nmap engine ([nmap.md](nmap.md)) which is already in the image. No separate auth or env var.

## Optional setup

None.

## How to verify

```bash
# Run a Deep scan against a host with a known open database port (test
# environment, not a real customer host). Watch for engine activity:
docker compose logs easm-backend --tail=200 2>&1 | grep -i "db_probe\|exposed_db"

# Find database-exposure findings:
docker compose exec easm-db psql -U easm_user -d easm -c "
SELECT public_id, severity, title FROM finding
WHERE finding_type='db_exposed' AND ignored=false AND resolved=false
ORDER BY id DESC LIMIT 10;
"
```

## Operational notes

- The engine **does not attempt authentication bypass** — it sends a handshake / version-probe packet and reads the response. No actual queries are issued
- For some database protocols (MongoDB, Redis), even the version-probe packet may be logged by the target as a connection attempt. This is unavoidable when confirming a service is live
- The engine respects a per-port timeout (5 seconds default) — slow DBs can return as "port open, service unconfirmed"
- A confirmed exposed database is one of the highest-signal findings the platform produces. False-positive rate is essentially zero

## Findings produced

| Template ID | Trigger | Severity |
|---|---|---|
| `db-mongodb-exposed-unauth` | MongoDB responds to `isMaster` without auth | critical |
| `db-redis-exposed-unauth` | Redis responds to `PING` without `AUTH` | critical |
| `db-elasticsearch-exposed-unauth` | Elasticsearch `/` returns cluster info without auth | critical |
| `db-mysql-exposed` | MySQL responds with version banner | high |
| `db-postgres-exposed` | PostgreSQL responds with SSL request | high |
| `db-couchdb-exposed-unauth` | CouchDB `/` returns version info without auth | critical |
| `db-cassandra-exposed-unauth` | Cassandra native-transport responds without auth | critical |
| `db-memcached-exposed` | Memcached responds to `stats` without auth | critical |

**Customer-facing category:** Service Exposure
