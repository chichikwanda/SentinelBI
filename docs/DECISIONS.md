# Architecture decision records

Short ADR entries for non-obvious choices. Newest at the bottom. Where a decision deviates
from `cyber-bi-project-plan.md`, the entry says so under **Deviation**.

---

## ADR-001: `ml/src` is exposed as the package `sentinelbi_ml`

**Context.** The plan lays code out as `ml/src/features.py` and requires training and serving to
share it, but `features` is not an importable, collision-free name.
**Decision.** `ml/pyproject.toml` maps the directory `src` to the package `sentinelbi_ml`
(`[tool.setuptools.package-dir]`). The backend depends on it as a uv path dependency.
Serving imports `sentinelbi_ml.features`, the same module `train.py` imports.
**Consequence.** Heavy training dependencies sit in the `train` extra, so the API image stays small.

## ADR-002: uv + lockfiles, one Python (3.12) in containers

`backend/uv.lock` and `collector/uv.lock` are committed; Dockerfiles use `uv sync --frozen`.
The venv lives in `/opt/venv` (outside the source tree) so bind mounts in dev never shadow it.
Reproducibility requirement from the plan (pinned dependencies).

## ADR-003: psycopg 3 for both sync (Alembic) and async (app) access

One driver instead of psycopg2 + asyncpg. URL scheme `postgresql+psycopg://`.

## ADR-004: Flow idempotency via `flows.flow_ref`

**Deviation.** The plan's `flows` table has no row identifier, so `predictions.flow_ref` has nothing
to reference and a worker crash between "persist" and "ack" would duplicate rows when the stream
message is redelivered. We add `flows.flow_ref TEXT` (the Redis stream message id) and a unique
index `(org_id, flow_ref, ts)` (Timescale unique indexes must include the partition column `ts`).
`ts` is fixed at ingest time, so a redelivered message carries identical values and
`INSERT ... ON CONFLICT DO NOTHING` makes persistence idempotent.

## ADR-005: NetFlow exporter identification (open design gap)

**Problem.** The plan accepts an exporter if its IP matches a *registered CIDR*. Two SMEs can register
the same private range (`192.168.1.0/24`), and a router's export address often is not inside the
range being monitored (NAT, VPN). Matching on monitored CIDR is therefore ambiguous across tenants,
and an ambiguous match would put one tenant's flows into another's account.
**Decision for now.** The collector accepts an exporter only when **exactly one** source of
`method='netflow'` contains its IP; zero or multiple matches are dropped and logged
(rule: unknown exporters are dropped).
**Proposal (next session).** Add a dedicated `exporter_ip` (and optionally a per-source UDP port or
IPFIX observation-domain id) to `sources`, and match on that instead.

## ADR-006: Active scanning disabled

`method='scan'` stays in the DB CHECK constraint (plan schema) but `POST /sources` rejects it until
the ownership-attestation flow and audit log exist (design rule 8). No scanning code is present.

## ADR-007: Source criticality lives on `sources`

**Deviation.** F2 asks to label criticality at registration, but the plan's `sources` table has no
such column (only `assets` does). We add `sources.criticality SMALLINT DEFAULT 2` (1 low, 2 medium,
3 high) as the default for assets discovered in that source.

## ADR-008: `predictions` is a hypertable with the same retention as `flows`

**Deviation.** One prediction row per flow would otherwise grow without bound on a small VM.
Retention: 30 days for `flows` and `predictions` (Timescale policy), alerts kept (plan: 1 year;
the purge job comes with the scheduler in a later phase). Chunk interval is 1 day so retention
drops data at day granularity.

## ADR-009: Demo seed is a script, not part of the migration

Seeding a demo org with known credentials inside a migration would ship it to production.
`python -m app.db.seed` is idempotent, refuses to run when `ENV=prod`, and the `migrate` compose
service runs it only when `SEED_DEMO_DATA=true`.

## ADR-010: API keys are SHA-256 hashed, looked up by hash

Keys are 256-bit random values, so a fast hash is appropriate (no brute-force risk that would call
for argon2) and lets ingest authenticate with one indexed lookup. The plaintext key is shown once
at creation. Passwords use argon2id.

## ADR-011: Docker Desktop and UDP source addresses

On Docker Desktop (Windows/macOS) published UDP ports are NAT'd, so the collector sees the Docker
gateway instead of the router's real IP, and exporter allow-listing cannot match. On a Linux VM the
source IP is preserved; for production, `network_mode: host` on the collector is the safest option.
Local development therefore tests the collector with unit tests and crafted packets, not a real router.

## ADR-012: Placeholder classifier behind the real predictor interface

The worker depends on `Predictor` (`classes`, `version`, `predict_proba(features_df)`). Until Phase 2
produces a trained model, `PlaceholderPredictor` applies fixed, documented rules on the shared
features. It is **not** a trained model: it is registered in `model_registry` as
`placeholder-heuristic-v0` with empty metrics and no dataset, and no claims are made about its
accuracy.
