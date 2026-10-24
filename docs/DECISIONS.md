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

---

# Phase 2 / MVP completion (second session)

## ADR-015 update: resolved by pairing records in the collector

Checked against the real file: NF-UNSW-NB15-v2 flows ARE bidirectional (IN_* and OUT_* both
populated). The collector therefore merges a record with its reverse-direction partner
(`collector/pairing.py`): the earlier record (ties: the one aimed at the lower, service port) is the
client, `in_*` = client to server, `out_*` = server to client, TCP flags are OR-ed, duration spans both.
Records that find no partner within `PAIRING_HOLD_S` (default 10 s) are emitted unchanged. Pairing is
keyed per source, so tenants can never be merged. Cost: up to 10 s extra detection latency on the
NetFlow path (HTTP/sensor/CSV paths carry bidirectional flows already and are not delayed).
Residual risk: NetFlow's active/inactive timeouts can split one long conversation into several
records; those are paired record-by-record, which only approximates nProbe's bidirectional flows.
Not verified against a real router (none available on the development machine).

## ADR-016b: the first real model (measured, not claimed)

Trained on NF-UNSW-NB15-v2 with the shared core features (`make train`): 2,390,275 rows, 424,336 exact
duplicates removed, stratified random 70/15/15 split (no timestamps exist), benign down-sampled to 400k
in the TRAIN split only. Compared LR, DT, RF, LightGBM, XGBoost; **selection rule fixed in advance:
best validation macro-F1** => Random Forest (0.598; LightGBM 0.584, XGBoost 0.573, DT 0.570, LR 0.282).
The test split was evaluated once, for the selected model only:

| Test (294,891 flows) | |
|---|---|
| Accuracy | 99.11% (not the headline: ~96% of traffic is benign) |
| Macro-F1 | 0.610 |
| False-alarm rate (benign flagged as any attack) | 0.50% |
| Attack detection rate (any attack class flagged) | 99.82% |
| ROC-AUC (one-vs-rest, macro) | 0.996 |
| Per-class F1 | Benign 0.997, Exploit/Other 0.884, Recon/Scan 0.857, DoS/DDoS 0.484, Botnet/Backdoor 0.298, WebAttack 0.140 |
| Serving latency | 32 ms per 500 flows (single thread, idle machine; plan target < 50 ms) |

**Dataset shift (informal probe, not a metric).** Hand-made flows resembling everyday traffic (HTTPS small and
large, HTTP, SMTP, DNS, a UDP stream, ICMP) were all labelled Exploit/Other with probability 0.34-0.81; only an
SSH flow was Benign. The `alert_min_probability` gate (0.7) lets the highest of these through (an e2e test
with 12 plain HTTPS flows raised an alert). On this evidence the model will produce false alarms on real
networks. Not tuned away on purpose: moving the threshold using the test split would contaminate it.

**Throughput (measured on the Windows/Docker Desktop development machine, not a target VM).** One 500-flow
batch: RF inference 130-450 ms in the container (32 ms on the idle host), flows INSERT ~430 ms, other SQL ~200 ms,
plus commit/Redis; live worker batches ran 2-11 s, i.e. roughly 65-230 flows/s, well below the plan's
2,000 flows/s target. Not profiled further or optimised; load testing is deferred. Obvious levers: more worker
replicas (the consumer group scales), COPY for flows, larger batches, a Linux host.

Read this honestly: the model separates attack from benign very well and recognises exploits and
scans, but it is poor at telling DoS, backdoor and web attacks apart (their NetFlow features are
weak and, after de-duplication, only ~700 distinct backdoor and web examples exist). Scores are
optimistic because the split is random and same-session flows can land on both sides. Not done and
therefore NOT claimed: k-fold cross-validation, hyper-parameter search, cross-dataset
generalisation, significance tests, an MLP, any evaluation on real SME traffic. These are deferred
by decision (MVP first) and listed in the model card (`training.not_done`).

## ADR-017b: model artifacts are verified before they are loaded

`model.joblib` files are pickles. The card stores the artifact's SHA-256; the loader refuses a
mismatch, refuses a card whose feature list differs from the serving features, and rejects version
strings that would escape the models directory. A model that fails to load never takes the worker
down: it keeps serving the previous model. `migrate` registers every model found in `ml/models`
and activates the newest only when just the placeholder is active, so an administrator's choice is
never overridden. Switching the model is platform-wide, so it needs an administrator whose email is
in `PLATFORM_ADMIN_EMAILS` (an organisation admin is not enough).

## ADR-018b: alerts need a flagged SHARE, not just a count

A per-flow classifier with a ~0.5% false-alarm rate would raise alerts for any busy benign host
(5 flagged flows in a minute is routine at 1,000 flows/minute). An alert now also requires the
flagged flows to be at least `ALERT_MIN_SHARE` (default 20%) of ALL the source's flows in the
window. Trade-off: an attacker hiding a few attack flows inside lots of normal traffic from the same
address can stay below the gate. The value is a provisional default, not tuned.

## ADR-019: prescriptive rules and what was verified

Rules are YAML (`rules/*.yaml`, schema-validated at load) mapping each attack class to ranked actions
with ATT&CK / CIS / NIST references and a generic Zimbabwe data-protection note. **Verified:** every
MITRE mitigation id exists in ATT&CK 20.0 (the mapping file is generated from the STIX data and the
generator fails otherwise). **Not verified:** CIS Controls v8 and NIST CSF 2.0 ids and titles were
written from the author's knowledge; the files say `unverified-needs-review`. The compliance notes
deliberately cite no section numbers or deadlines (a test enforces that) until a lawyer has
confirmed the interpretation of the Cyber and Data Protection Act [Chapter 12:07]. Context rules
(KEV-vulnerable exposed service, threat-intel hits) are not built: no vulnerability or intel data is
ingested yet.

## ADR-020: explanations exist only for boosted-tree models

LightGBM/XGBoost compute exact tree-SHAP natively, so alert detail can show per-feature
contributions without the heavy `shap` package. The selected model is a Random Forest, which has no
native support, so alerts currently show "no explanation available" instead of an invented one.
Options for later: serve LightGBM (validation macro-F1 0.584 vs 0.598, within what a different split
could change), or add `shap` to the serving image.

## ADR-021: retention applies to replayed history

The 30-day Timescale retention policy also drops flows whose own timestamps are older than 30 days.
Replaying a historical capture with `--keep-timestamps` will therefore lose it in the background; the
default (server stamps ingest time) is unaffected. An earlier test used year-old NetFlow export
times and flaked for exactly this reason; test packets now use the current time.

## ADR-022: demo data policy

The real-data demo sample is generated locally from the held-out TEST split (`make sample`) and is
never committed, because it is a subset of a dataset licensed for academic use with citation. It is
enriched with attacks (the real data is ~96% benign) purely so a demo has something to show; that is
a presentation choice, not a performance claim.
