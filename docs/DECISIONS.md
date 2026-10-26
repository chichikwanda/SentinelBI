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

---

# Third session: a second dataset, and what it showed

## ADR-023: NF-CSE-CIC-IDS2018-v2 added; the false-alarm problem is real and not solved by more data alone

> **Partly superseded by ADR-024.** The numbers below come from a model trained on a flawed duration
> feature (kept for the record; that model no longer loads). The conclusions about false alarms and
> dataset shift still hold; the 85 ms latency figure was a measurement artefact.

**Why.** The first model (UNSW only) labelled ordinary-looking traffic as attacks (ADR-016b). A second,
more enterprise-like dataset was the obvious remedy.

**Data.** NF-CSE-CIC-IDS2018-v2 (host id `ce5161d0-ef9c-11ed-827d-e762de186848`, open access, same
academic-use licence), 612 MB zipped, 3.2 GB CSV. Read in chunks keeping EVERY attack row and 8% of benign
rows (3,587,089 rows; 3,141,703 after exact-duplicate removal, of which 1.70M are DoS/DDoS). Label mapping
follows the host's own grouping (checked against its published table: SSH + FTP brute force = its
"BruteForce" 120,912; Brute Force-Web + -XSS + SQL Injection = its "Web Attacks" 3,502). This dataset
finally gives the model BruteForce examples. Verification: see data/DATASETS.md (CRC-32 and the publisher's
SHA-1 both match; a first extraction reported a CRC mismatch that I could not reproduce or explain).

**Training.** Same pipeline and selection rule as before (validation macro-F1), models DT / RF / LightGBM
(LR and XGBoost were not competitive in the first run and cost a lot of time), per-class training caps
(benign 400k, others 150k, TRAIN split only). Random Forest again won (validation macro-F1 0.711; LightGBM
0.704, DT 0.701). Test split (766,147 flows, evaluated once):

| Combined RF, test | |
|---|---|
| Macro-F1 | 0.712 (not comparable with the 0.610 of the UNSW-only model: different data and classes) |
| Per-class F1 | BruteForce 1.000, Botnet/Backdoor 0.989, DoS/DDoS 0.875, Recon/Scan 0.835, Exploit/Other 0.369, WebAttack 0.011 |
| False-alarm rate, plain argmax | **17.3%** overall: UNSW part 0.5%, **CSE-CIC part 44.2%** |
| Serving latency | 85 ms per 500 flows as first recorded; re-measured later under controlled conditions the same model takes 21 ms, so 85 ms was a loaded-machine artefact (ADR-024) |

**Dataset shift, measured (leave-one-dataset-out, same algorithm refitted on one dataset):**

| Train -> test | Macro-F1 | False alarms | Attack recall |
|---|---|---|---|
| UNSW -> CSE-CIC | 0.065 | 67.8% | 85.2% |
| CSE-CIC -> UNSW | 0.144 | 1.7% | **1.5%** |

Attacks learned on one testbed do not transfer to the other with the router-compatible core features, and
the benign traffic of one testbed looks "attack-like" to a model trained on the other. The in-distribution
numbers (for example BruteForce 1.000) partly reflect scripted attack tools with fixed ports and sizes and
should not be read as real-world detection quality. (An earlier run's cross-dataset figure of 0.161 was
wrong: the model lacked a class, so its probability columns were misaligned; they are now padded to the full
class list.)

**What was done about false alarms: an alert threshold calibrated on VALIDATION data.** Rule fixed in advance:
the smallest probability threshold in 0.50-0.99 whose false-alarm rate is <= 2% on every dataset. It is 0.82
(validation false alarms 0.82% worst dataset). Reported once on the test split:

| Test split, flow level, at threshold 0.82 | False alarms | Attack recall |
|---|---|---|
| Overall | 0.46% | **45.0%** |
| UNSW part | 0.26% | 86.4% |
| CSE-CIC part | 0.78% | 43.5% |

So false alarms fall by a factor of ~38 and **more than half of attack flows are no longer flagged**. This is
a trade, not a free fix. The worker uses `max(ALERT_MIN_PROBABILITY, model threshold)`, and alerting is
window-based (>= 5 flagged flows and >= 20% of the source's flows), so a sustained attack can still alert
at 45% flow recall, but short or sparse attacks will be missed. The everyday-traffic probe now calls 4 of 8
flows Benign and the other four are low-confidence (0.45-0.60) calls, all below the threshold.

**Consequence for the thesis and the MVP.** The system's detection quality on a NEW network is unproven and
probably poor; only a consented pilot capture can establish it, and calibrating the threshold (and the share
gate) on that capture is the realistic next step. Other levers, not tried: sensor-mode features
(payload-free but richer than NetFlow), anomaly detection against each network's own baseline, per-network
retraining from analyst feedback.

**Process notes.** This machine produced several unexplained transient faults in one session (two zip CRC
mismatches that later verified, a 64 PiB array allocation inside scikit-learn, a Node segfault); every result
that depends on them was re-run or re-verified. A memory test of the host is advisable. `train.py` now drops
raw columns once features exist, exports the model BEFORE the optional cross-dataset check, and records a
failure of that check instead of crashing, because the first full run lost its model to such a fault.

---

## ADR-024: a flow-duration artefact in both datasets; feature spec v2; data integrity on a faulty machine

**How it was found.** Writing the CSE-CIC entry of data/DATASETS.md, the feature ranges showed
`FLOW_DURATION_MILLISECONDS` with a median of 4,294,663 ms (UNSW: 0). Counted over the whole CSVs, the
share of flows whose duration is >= 4,290,000 ms (the unsigned 32-bit wrap of a negative duration:
2^32/1000 ms minus a median of 16-27 ms):

| Dataset | Benign | Attack |
|---|---:|---:|
| NF-UNSW-NB15-v2 | 5.8% | 10.5% |
| NF-CSE-CIC-IDS2018-v2 | 4.0% | **82.6%** |

No router exports a negative duration, so this is a property of the testbeds' flow exporter, and in
CSE-CIC it is an almost perfect attack marker. A model that sees the raw value learns it.

**Decision.** `build_features` (the one module training and serving share) maps such values to 0, like any
other negative duration (`WRAPPED_DURATION_MS`), with a test that training and serving agree. Because a change
in how a feature is computed changes what a trained model means, model cards now record
`feature_spec_version` (this change is v2) and the loader refuses an artifact with another version; models
without the field count as v1. The two earlier models were moved to `ml/models/_superseded/`.

**Effect, same pipeline and seed, test split (766,147 flows, evaluated once):**

| | Before (raw duration) | After (spec v2) |
|---|---|---|
| Macro-F1 | 0.712 | 0.690 |
| DoS/DDoS F1 (recall) | 0.875 (0.779) | 0.729 (0.574) |
| BruteForce / Botnet / Recon / Exploit / WebAttack F1 | 1.000 / 0.989 / 0.835 / 0.369 / 0.011 | 1.000 / 0.990 / 0.832 / 0.368 / 0.008 |
| Alert threshold (validation rule unchanged) | 0.82 | 0.81 |
| At threshold, false alarms overall / UNSW / CSE | 0.46% / 0.26% / 0.78% | 0.92% / 0.27% / 1.97% |
| At threshold, attack flows flagged overall / UNSW / CSE | 45.0% / 86.4% / 43.5% | 44.3% / 87.4% / 42.7% |
| Everyday-traffic probe, called Benign | 4 of 8 | 5 of 8 |
| Trained UNSW, tested CSE: macro-F1 / false alarms / attack recall | 0.065 / 67.8% / 85.2% | 0.053 / 65.0% / 36.8% |
| Trained CSE, tested UNSW: macro-F1 / false alarms / attack recall | 0.144 / 1.7% / 1.5% | 0.143 / 2.2% / 2.9% |

**Reading it.** The artefact had flattered DoS/DDoS (90% of the attack rows) and the "85% recall" of the UNSW->CSE
experiment, which falls to 37%. It did **not** cause the transfer failure: CSE->UNSW still finds 2.9% of attacks and
UNSW->CSE still raises 65% false alarms. The conclusion of ADR-023 stands: detection on a new network is unproven. The
chosen threshold now sits at the edge of the 2% target (validation 1.99%, CSE test 1.97%), so the false-alarm
guarantee on a new network is weak.

**Latency correction.** ADR-023 and the first card said 85 ms per 500 flows (above the 50 ms target). Re-measured
the same way (single thread, median of 30 runs, idle machine) the old model takes 21.1 ms and the new one 21.0-23.3 ms.
The 85 ms was the machine's state when it was measured, not the model. Both are under the target; only the idle-machine
condition is recorded, not behaviour under load.

**Data integrity on this machine (read this before trusting any number).** The development laptop has faulty RAM.
Evidence from one afternoon: a numpy string array with one flipped bit (U+002D read back as U+0020002D) that crashed
a training run; the 3.2 GB CSE-CIC CSV, hash-verified at download, differed from its zip member by exactly two bytes
(each a single bit-5 flip, 1,768 bytes apart), and a second extraction reproduced the same pair at other file offsets
but the same in-page offsets (94 and 1862 of a 4 KB page): one defective physical page that the OS hands to different
file pages. The zip, the UNSW CSV and the on-disk copy after a fresh extraction were intact. Earlier faults of the
session (zip CRC mismatches, a corrupted TypeScript compiler file, a 64 PiB allocation, a Node segfault) fit the same
cause. Measures taken: training now verifies every CSV against the SHA-256 in MANIFEST.json before reading it
(`verify_sha256`, test included), so the checksum recorded in a model card is a checked claim; the damaged CSV was
re-extracted until it verified; and **the reported model was trained twice from the same seed, giving a byte-identical
artifact (SHA-256 `8b78768169bef02e...`) and identical validation, test, per-dataset, cross-dataset and probe results.**
That repeat is the evidence for the numbers in this ADR, not the first run. The owner should test the memory (Windows
Memory Diagnostic, or MemTest86 per module; the laptop has a Samsung and a Hynix SODIMM) and replace the faulty one;
until then any figure that matters should be reproduced the same way.

**Not done.** The cross-dataset gap, the 44% attack-flow recall and the thin false-alarm margin are open problems; the
levers listed in ADR-023 (richer sensor-mode features, per-network baselines, pilot calibration) are untouched.

---

## ADR-025: ingest throughput, sign-in throttling, backups, log caps and CI

**Method (throughput).** The worker's batch log line now shows milliseconds per stage. Capacity was measured by
stopping the worker, queueing a backlog through the ingest API, starting the worker(s) and timing the drain (wall
clock, first batch start to last batch end), so it measures the worker and not the load generator. Two loads, both
made from real held-out flows: "attack-heavy" is the 4,212-flow demo sample (about 70% attack flows, about 25 alert
groups per 500-flow batch) and "benign-only" is its 2,000 benign flows repeated. Runs vary by about 15%; one laptop,
normal desktop load, faulty RAM (ADR-024). This is a backlog-drain capacity figure, not a soak or a real-exporter test.

**Where the time went.** At the start one worker took about 1.0 s per 500-flow batch (about 470 flows/s attack-heavy).
The model was negligible (features about 20 ms, prediction about 40 ms). Writing flows took 300-600 ms, predictions
100-200 ms, alert handling 250-450 ms.

**What the flow insert was really doing.** Profiling showed most of the insert time was client-side: SQLAlchemy
compiling and psycopg parsing one 8,000-placeholder `VALUES` statement per batch (142 of 267 ms per 500 flows), not
Postgres. Steps measured in isolation, in a rolled-back transaction: inline `VALUES` 267 ms; `executemany` 125 ms
(and, without `RETURNING`, slower than `VALUES`, because SQLAlchemy only batches with `RETURNING`); `INSERT ... SELECT
... FROM unnest(column arrays) ON CONFLICT DO NOTHING` **48 ms**. The last is now `app/db/bulk.py`, used for flows and
predictions. It stores identical values (NULLs inside the arrays, INET, JSONB, microsecond timestamps), skips conflicts
and reports only inserted rows, which the idempotent redelivery in ADR-004 needs (tests). In the pipeline the flow
insert dropped from about 270 to 75-95 ms and the prediction insert to 50-60 ms.

**Other changes.** The Redis window counters for all alert groups of a batch share one pipeline (no difference visible
within the noise; one round trip instead of one per group). The default batch size went from 500 to 2,000: alert work
is per source and class per batch, not per flow, so bigger batches are cheaper per flow (attack-heavy, one worker:
786 flows/s at 500, 921 at 1,000, 1,441 at 2,000), and under light load a batch is only what has arrived, so latency
does not grow. A failed batch is now retried whole once before the per-message fallback, because that fallback costs a
transaction per message; the Redis counters sit outside the transaction, so a retry can count a batch twice, which can
only make an alert fire slightly early. `WORKER_REPLICAS` (compose) runs more workers on the same consumer group.

| Backlog drain, 4-core laptop | Benign-only | Attack-heavy |
|---|---:|---:|
| Start of this work, 1 worker, batch 500 | not measured | about 470 flows/s |
| Now, 1 worker | about 1,680 flows/s | about 1,355 flows/s |
| Now, 2 workers | about 2,370 flows/s | about 2,050 flows/s |

**Tried and rejected.** Merging the advisory lock and the alert lookup into one statement: the statement's snapshot
could be taken before the lock is granted and miss an alert a concurrent worker just created. Caching which
recommendations were already stored: about 10% on attack-heavy traffic, but it must only be updated after the
transaction commits or a rollback would hide a recommendation; not worth the state. **Still open:** alert handling is
350-460 ms per batch on attack-heavy traffic (four or five sequential statements per group).

**Sign-in throttling.** Failed attempts are counted per account in Redis (8 in 15 minutes, then 429 with
`Retry-After`; a success resets the count) and checked before the password, so a locked account cannot be guessed at.
Unknown addresses are counted the same way so the limiter does not reveal which accounts exist. It is deliberately not
per client address: browsers reach the API through the web container, so one address would be shared by every user and
anyone could lock everyone out. The price is that a known account can be locked for 15 minutes by someone who fails on
purpose. Redis errors fail open (logged). Open sign-up is capped at 20 organisations per hour across the deployment,
and `ENV=prod` logs a warning if `ALLOW_REGISTRATION` is still true. Tested, and exercised against the running stack
(8 x 401, then 429 even for the right password, another account unaffected, unlock by deleting the key).

**Backups.** `scripts/backup.sh` dumps the database (custom format), reads the dump back before trusting it, copies the
models and writes a SHA256SUMS file. `scripts/restore.sh` restores into a scratch database by default, with the
TimescaleDB pre/post-restore calls it needs, and refuses the live database without `FORCE=1`. Checked on a real
backup: every table's row count matched the live database and both hypertables survived. There is no schedule and no
off-machine copy; `backups/` holds password hashes and tenant data and is gitignored.

**Logs and CI.** Every long-running container's log is capped at 3 files of 10 MB (the default is unbounded, on a
disk that is nearly full). `.github/workflows/ci.yml` runs ruff, mypy, the whole pytest suite against real TimescaleDB
and Redis service containers, the frontend lint, type check and build, and a compose validity check. The Playwright
specs are not in CI: they need a trained model, which is not committed.

---

## ADR-026: a "flowless" quick start: the sensor, data-volume views and reports

**The request.** Register, type an IP address, and watch that address's traffic, with reports and the amount of
data transmitted, without configuring flow export on a router.

**The constraint.** A server cannot observe an arbitrary address's traffic from outside; packets have to be seen
where they pass. Three real options: (1) a program on the host, a gateway or a mirror port that reads packet
headers and reports them; (2) polling a device's interface counters over SNMP, which gives volume but needs
credentials and gives the model no flows; (3) probing the address from outside, which shows reachability, not
traffic, and active scanning stays off until the attestation flow and audit log exist (ADR-006). Option 1 is the
plan's "sensor mode", it feeds the same pipeline (so alerts, risk and recommendations work on it), and it is what
the long-reserved `sensor` method was for. It is what was built.

**Decisions.**

- **The sensor** (`sensor/sentinelbi_sensor.py`): one standard-library file, Python 3.9+. Linux packet socket,
  Windows receive-all raw socket, or `--read-pcap`. Headers only, no payload field exists in the record. Flows
  are bidirectional with the NetFlow v9 convention the model was trained on (client opens, `in_*` client to
  server, ICMP type and code in the destination port, IP-level byte counts, a server's reply seen first does not
  make it the client). It never counts its own reports, keeps a bounded backlog while the server is down, and
  reads the kernel's drop counter so any loss is reported, not hidden.
- **Delivery**: the API serves the script (`GET /sensor/sentinelbi_sensor.py`, public because it is code, with its
  SHA-256 in a header and in the wizard). The wizard prints commands for Windows, Linux, Docker and a demo replay
  with the key and address filled in. A bundled synthetic capture (`data/samples/sensor_demo.pcap`) lets the whole
  path be tried without capture rights.
- **Onboarding**: the register form takes an optional IP and the wizard opens with it filled in; the sensor is
  the wizard's default method; an empty dashboard offers the same in one box.
- **Data volume**: a host's *sent* is `in_bytes` when it is the flow's source and `out_bytes` when it is the
  destination (and the reverse for *received*); a flow between two monitored hosts counts for both. *Monitored*
  means inside a registered source. New: `/traffic/summary`, `/traffic/hosts`, `/traffic/hosts/{ip}` (sent and
  received over time, top peers, top services), a Traffic page, a data tile and Flows/Data switch on the
  dashboard, a per-host CSV and a data-volume table in the PDF. Sizes are decimal everywhere (the UI used 1024
  while the reports used 1000; one rule now).
- **Addresses**: a single host is shown as `10.0.0.5`, never `10.0.0.5/32`, in every response (it differed
  between the create response and lists).

**What verifying it found** (all fixed):

1. The first live capture **under-counted**: about 369 kB reported for 400 kB uploaded, 7 packets short of the
   kernel's counters. The packet socket's buffer is charged per whole (offloaded, up to 64 kB) packet, so a burst
   overflowed it and the kernel dropped the copies. Fix: read only the headers with the real length from
   `MSG_TRUNC`, enlarge the buffer where privileges allow, count drops and warn. Result, two containers moving 3.0 MB
   and 0.4 MB: within 0.01% of the kernel's interface counters with `NET_ADMIN`; with `NET_RAW` only, 13 packets are
   still dropped in that burst and the sensor says so.
2. ruff's autofix (the repo targets Python 3.11) had rewritten `timezone.utc` to `datetime.UTC`, silently breaking
   the 3.9 support the sensor claims. Found by running it on a real Python 3.9; now 3.9 and 3.13 give byte-identical
   records, a test guards the imports (checked by reintroducing the bug), and CI replays the capture on 3.9.
3. The browser test found the `/32` inconsistency, and a pre-existing race in the detections test (it counted a
   live list while the worker was still adding to it, made visible by the larger worker batches of ADR-025).

**Also measured**: about 177,000 packets per second per core for parsing, filtering and flow building (offline);
the end-to-end test through the real stack (container downloads the sensor from the API, captures 40 HTTP
connections, reports to the real ingest endpoint) shows both hosts with mirrored sent and received bytes.

**Not verified, and open.** Live capture on **Windows** (needs an elevated terminal; this machine's session was
not, and the user's own setup is the first real test); macOS (unsupported); IPv6 on Windows; long soak runs;
mirror-port and NAT topologies. Detection quality on real traffic is still unproven (ADR-023/024): a user's own
machine will be scored by a model trained on lab datasets, so expect false alarms; the window and share rules
limit them. The API key travels in an HTTP header, so use HTTPS beyond a trusted LAN. The sensor needs
administrator rights on the machine it watches and must only be run on machines and networks the user
administers; it is passive, so the scanning rule (ADR-006) is not touched.

---

## Addendum to ADR-025 and ADR-026 (same day): what real use on the user's laptop found

**Redis kept every finished message.** The worker acknowledged messages but never deleted them, so the stream
held up to `stream_maxlen` (500,000) processed messages for ever: measured 500,003 of them, 180 MB of Redis memory.
The worker now deletes a message once it is acknowledged (stored, or copied to the dead-letter stream); after
clearing the old backlog Redis used 1.7 MB. A test checks the stream is empty after a drain.

**Redis stalls surfaced as 503 on ingest.** redis-py 8's default socket timeout is 5 s. During repeated browser runs
Redis logged "Asynchronous AOF fsync is taking too long (disk is busy?)" (14 delayed fsyncs) and ingest answered 503
(`Timeout reading from redis`). The client now waits 30 s (explicit, configurable) and Redis does not fsync during
AOF rewrites. Afterwards two consecutive browser runs passed 5 of 5 at about 50 s each and no fsync was delayed.
A known weakness remains: if Redis executes a batch after the client has already timed out, a retry (the sensor
retries on 503) can store it twice; ingest has no idempotency key yet.

**Hardware, not software, caused the remaining flakiness.** The laptop's CPU (i7-4600U) ran at 1,000 of 2,701 MHz
under 100% load after many back-to-back runs, and CPU-only stages slowed 5 to 10 times (prediction 50 ms became up
to 9.5 s for 500 flows) until some browser tests timed out. I first suspected the per-minute risk snapshots; measured,
they take 1.1 s for 41 organisations, so they are not the cause. Treat timing results from a throttled machine with
suspicion, as with the faulty RAM (ADR-024).

**The sensor on the user's real Windows machine** (elevated tests, counts only):
the self-test passed; an IPv4-only request was captured in both directions (9 packets out, 9 in) and a live run
reported 14 flows to the real API with exact ICMP byte counts; but a normal HTTPS request produced **no** packets,
because the machine has global IPv6 and Windows used it. Windows delivers IPv6 raw packets without the IPv6 header, a
TCP-specific IPv6 raw socket cannot be opened, and a protocol-neutral one gives header-less payloads (addresses and
protocol would have to be guessed), so IPv6 is not captured on Windows. The sensor now says so at start-up on a
machine that has IPv6, says why when it sees no packets in its first ten seconds or none for the address it was given,
and warns when that address belongs to a virtual adapter (Hyper-V, WSL, Docker) rather than the one internet traffic
uses, which was the user's first mistake. Options for IPv6 on Windows, none built: capture through Npcap (accurate,
needs an install), reconstruct addresses from header-less packets (approximate), or capture on a Linux gateway or
mirror port.

---

## ADR-027: IPv6 on Windows through libpcap/Npcap, removing a source, resend-proof ingest

**Why.** Real use on a dual-stack Windows laptop showed the Windows sensor missing most of its browsing (IPv6),
the user could not delete the sources created while finding their way, and ADR-025 had left a known weakness: a
batch resent after a lost reply could be stored twice.

**IPv6 on Windows: options weighed.**

| Option | Verdict |
|---|---|
| Windows raw socket, IPv6 | Rejected, measured: packets arrive without their IPv6 header (the first bytes are the TCP header), a TCP-specific IPv6 raw socket cannot be opened, and the protocol and the destination of outgoing packets would have to be guessed |
| `pktmon` (built into Windows) | Rejected: no live stream; it writes capture files, so live use would mean stop, convert, restart cycles with gaps, or parsing a text format that varies between builds |
| libpcap/Npcap through `ctypes` | **Chosen.** Full headers for IPv4 and IPv6, exact lengths, a kernel drop counter, the same code path on Windows, macOS and (optionally) Linux, and still one dependency-free file because `ctypes` is in the standard library |

Npcap is a kernel driver with its own licence: the free edition allows installs on up to 5 systems, forbids
redistribution and has no silent installer, so it is **not bundled** and cannot be installed for the user. The sensor
finds it in either install location, selects the device that owns the watched address, and when it is missing it
falls back to the raw socket and says exactly what is lost and where to get Npcap. For uses beyond Npcap's free
licence, capture on Linux, which needs nothing extra.

**Verification.** The ctypes wrapper was run against real libpcap on Linux (a container with the library
installed, capturing IPv4 and IPv6 transfers of 2 MB down and 0.3 MB up on a dual-stack Docker network): device
and address discovery worked, the self-test passed, the libpcap backend and the native backend produced
**byte-identical** flows for both families, and both were within 0.021% (transmit) and 0.006% (receive) of the
kernel's interface counters. Pure logic (address parsing, link layers, device choice, backend selection and
fallback) is unit-tested with a stand-in library. **Not verified:** the Windows-specific part (loading
`wpcap.dll` from `System32\Npcap`, Npcap device names, `timeval` layout on Windows) because Npcap was not
installed on the test machine; macOS is untested too.

**A way for the user to verify it themselves.** `--check` runs the self-test, then one short HTTP request over IPv4
and one over IPv6 from the machine, and counts the packets of each that the capture saw in each direction. A
family the machine cannot reach (no route) is reported as "not testable", not as a capture fault; a family that
worked but was not seen is reported as missing, with the Npcap pointer when the Windows raw socket is the backend.
Run on Linux with both backends on a dual-stack network it reported IPv4 and IPv6 OK (5 packets each way), and on
unelevated Windows it refused with a clear message; it has not yet run on Windows with Npcap, which is the one step
that needs the user (installing the driver and accepting its licence).

**Removing a source.** `DELETE /sources/{id}` (administrators, own organisation only; other organisations get 404).
The API key stops working at once because it is looked up from the source row. Assets in the source are removed
(cascade), alerts keep their data and lose the link (`SET NULL`), stored flows are kept as history, and the source's
range stops counting as a monitored host range, so the Traffic page stops listing those hosts. The dashboard has a
Remove button, shown to administrators, with a confirmation that says all of this. The web proxy needed to forward
`DELETE`.

**Resend-proof ingest.** A batch may carry an `Idempotency-Key`. Redis remembers the key (per source, for an hour)
and queues the whole batch in one Lua script, so the check and the queueing are a single atomic step: a client that
never saw the reply can resend the identical batch and it is acknowledged (`"duplicate": true`) but not queued
again, even if the first attempt reached Redis, and six simultaneous identical requests queue it once. Without a
key nothing changes. The sensor sends a hash of the batch body, so a resend always carries the same key, and reports
how many batches the server had already seen. Consequence to know: replaying the same capture file with the same
timestamps inside an hour is recognised as repeated data (use `--shift-to-now`). The CSV replay tool sends no key,
because replaying the same file on purpose (demos, load tests) must keep working.

**Found while building it.** A Docker build failed on a transient DNS error and my command line printed only the
status lines, so I briefly tested old containers and saw "no deduplication"; checking the container's code and the
build log found it. The lesson applied here: after a rebuild, confirm the running container has the change before
trusting a live test.
