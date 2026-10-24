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

## ADR-013: `org_id` on every tenant table; global reference tables are exempt

**Deviation.** Design rule 1 says every table carries `org_id`. The plan's `recommendations` and
`evaluation_responses` tables omit it, so we add it (scoping queries without a join is safer).
`model_registry` and `vulnerabilities` stay global on purpose: models and the CVE/KEV catalogue
are platform-wide, not tenant data. `flows`/`predictions` carry `org_id` without a foreign key to
keep hypertable inserts cheap; the worker only ever writes the `org_id` taken from the authenticated
source.

## ADR-014: Risk weights are provisional

`app/services/risk/scoring.py` uses the formula from plan section 7 with impact weights DoS 0.6,
BruteForce 0.7, Botnet 0.9, Exploit 0.9 (given in the plan as examples) plus Recon 0.3 and
WebAttack 0.7 (our provisional values), and a criticality factor of 0.75 / 1.0 / 1.25 for
criticality 1 / 2 / 3 (the plan multiplies by the raw criticality, which would exceed 1 after
clipping). In this phase an alert's score is `100 x` the maximum event risk in its group; asset and
organisation aggregation, KEV and threat-intel exposure terms come with the risk phase. These
numbers must be expert-elicited and justified in the thesis before they are presented as results.

## ADR-015: Router flows are unidirectional, training flows are bidirectional (open)

NetFlow v5/v9 records describe one direction; `out_bytes`/`out_pkts` are therefore 0 for routers
that do not export output counters. The NF-v2 datasets are bidirectional (IN and OUT populated),
so a model trained on them sees different `OUT_*`-derived features than the collector produces:
exactly the train/serve skew the plan warns about. Before the real model goes live either the
collector pairs reverse-direction records into one bidirectional flow, or the "core" feature set
drops the OUT-derived features. Decide in Phase 2 when the datasets are inspected.

## ADR-016: Web app is a thin BFF; JWT lives in an httpOnly cookie

**Deviation** (plan: "NextAuth or custom JWT cookie"). Route handlers `/api/session/*` exchange
credentials with the API and set an httpOnly, SameSite=Lax cookie (`COOKIE_SECURE=true` behind
TLS). `/api/proxy/*` forwards same-origin calls to the API with the token as a Bearer header, so
there is no CORS configuration and page JavaScript can never read the token. State-changing
proxy calls also refuse a cross-origin `Origin`. Expired tokens surface as a 401, which clears the
cookie and returns to `/login`. There is no refresh token yet.

## ADR-017: Frontend choices

* The scaffold's `cacheComponents` / `partialPrefetching` flags are removed: every page here is
  authenticated and dynamic, so they add behaviour we do not need and cannot yet vouch for.
* UI primitives (`components/ui/*`) are written by hand in the shadcn/ui style (class-variance-
  authority + tailwind-merge) rather than generated with the shadcn CLI; the CLI can be adopted
  later without changing call sites.
* System font stack instead of `next/font/google`: no build-time network dependency.
* "Live" alerts poll every 3 s with TanStack Query. SSE (`GET /stream/alerts`, in the plan) is not
  built yet.
* API types are hand-written in `lib/types.ts`; generating them from the OpenAPI schema is the
  next step so the contract cannot drift.

## ADR-018: Tests run against real Postgres/TimescaleDB and Redis

No mocks on the data path. `tests/backend/conftest.py` creates `sentinelbi_test`, runs the real
Alembic migration, and uses Redis db 1 (flushed per test). `make test` runs this inside the dev
image on Linux; host runs on Windows additionally need the selector event loop (set in
conftest) and `127.0.0.1` instead of `localhost`.
