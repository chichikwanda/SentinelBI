# SentinelBI

AI-powered cybersecurity business intelligence for ICT SMEs in Zimbabwe: descriptive,
predictive and prescriptive analytics over network flow data. This is a final-year research
prototype. The engineering plan is `cyber-bi-project-plan.md`; design decisions, measured results
and known gaps are in [docs/DECISIONS.md](docs/DECISIONS.md); datasets and checksums are in
[data/DATASETS.md](data/DATASETS.md).

**Status: working MVP.** Register an organisation and a source, send flows (NetFlow v5/v9/IPFIX,
HTTP API or CSV replay), and get: a trained classifier's detections, risk scores, ranked
recommendations mapped to MITRE ATT&CK / CIS / NIST, a live dashboard, alert triage, PDF and CSV
reports, a model registry, and the SUS/TAM questionnaires for the evaluation.

## What the model can and cannot do (measured)

The active model is a Random Forest trained on two public NetFlow datasets (NF-UNSW-NB15-v2 and
NF-CSE-CIC-IDS2018-v2) with the router-compatible core features, plus an **alert threshold (0.81)
calibrated on validation data**. On the held-out test split, at that threshold:

| | False alarms (benign flows flagged) | Attack flows flagged |
|---|---|---|
| Overall | 0.92% | **44%** |
| UNSW part / CSE-CIC part | 0.27% / 1.97% | 87% / 43% |

So it keeps false alarms low **by missing more than half of attack flows**. Alerting is window-based
(several flagged flows from one source), so sustained attacks still alert; sparse ones will be missed.
Per-class F1 at argmax: BruteForce 1.00, Botnet 0.99, Recon 0.83, DoS/DDoS 0.73, Exploit/Other 0.37,
WebAttack 0.01.

**The important caveat:** attacks learned on one dataset do not transfer to the other. Refitted on
UNSW only and tested on CSE-CIC, the same algorithm raises 65% false alarms (and finds 37% of the
attacks); refitted on CSE-CIC only and tested on UNSW it detects 2.9% of attacks. So **detection on a
new network is unproven and probably poor**; only a consented pilot capture can establish it, and
calibrating on that capture is the next step. Splits are random (the datasets have no timestamps), so
in-distribution scores are optimistic.

Two further facts. Both datasets carry an exporter artefact in the flow duration (wrapped negative
values: 83% of CSE-CIC attack flows against 4% of its benign flows); it had inflated the DoS/DDoS
scores and is now neutralised in the shared feature code (ADR-024). Scoring 500 flows takes about
21 ms (single thread, idle machine; target 50 ms). Everything above is measured, recorded in the
model card (Models page), and was reproduced by a second independent training run (identical
artifact SHA-256), because the development machine has faulty memory (ADR-024).

## Run it

Requires Docker with Compose v2. The ML workflow (`make train`) additionally needs `uv`.

```bash
cp .env.example .env                      # `make up` does this for you
docker compose up -d --build --wait       # or: make up
```

| Service  | URL / port                 |
|----------|----------------------------|
| Web UI   | http://127.0.0.1:3000      |
| API docs | http://127.0.0.1:8000/docs |
| NetFlow  | UDP 2055 (collector)       |

With `SEED_DEMO_DATA=true` (the `.env.example` default, dev only) a demo organisation is seeded:

| Login (password `dev-only-demo-password`) | Role                                   |
|-------------------------------------------|----------------------------------------|
| `admin@demo.sentinelbi.example`           | admin (also platform admin in dev)     |
| `analyst@demo.sentinelbi.example`         | analyst                                |
| `viewer@demo.sentinelbi.example`          | viewer                                 |

### Get a model, then see detections

The trained model is not committed (it is reproducible and ~50 MB). One command downloads the two
datasets (verified sources, ~650 MB, checksummed), compares models, calibrates the alert threshold,
exports the best, benchmarks it and registers it; the next ones make a demo CSV from the held-out
test rows and replay it:

```bash
make train      # ~15 min on 4 cores plus ~15 min of download on a slow link
make sample     # data/processed/demo_sample.csv: ~4,200 REAL flows from the test splits
make replay     # post them through the ingest API with the demo source's key
```

Sign in as the demo admin: within seconds the dashboard shows alerts, the risk gauge, traffic
charts and top attackers; open an alert for evidence, triage and ranked recommendations.
Before a model exists the stack runs on a labelled **placeholder** rule set and says so.

Without `make` (e.g. Windows) run the underlying commands from the Makefile
(`uv run --project ml --extra train python -I -m sentinelbi_ml.train` and so on); use
`MSYS_NO_PATHCONV=1` in Git Bash when a command argument starts with `/repo`.

### Onboard your own network

**Quick start, no router setup.** Enter an IP address when you register (or on the dashboard, or in the
wizard at `/sources/new`) and you get one command to run on that machine: the SentinelBI **sensor**, a
single Python file that reads packet headers (never contents), builds flow records and reports them
(`sensor/README.md`). A server cannot see an arbitrary IP's traffic from the outside, so something has to
run where the packets pass: the machine itself, a gateway, or a mirror port. The wizard prints the commands
for Windows, Linux and Docker with your key and address filled in (on Windows, install Npcap first to capture
IPv6 as well, see `sensor/README.md`), plus a tab that replays a bundled
synthetic capture for trying it without admin rights. Within seconds the **Traffic** page shows how much each
monitored host sent and received, who it talked to and which services it used; the dashboard shows the
volume and a Flows/Data chart; Reports has a per-host CSV and the PDF summary includes the same table.

**Router NetFlow.** For whole networks: the wizard gives copy-paste router config (MikroTik, pfSense,
Cisco) or an HTTP/curl example, then polls until the first flows arrive. NetFlow exporters are accepted only
from the registered address (unknown or ambiguous exporters are dropped and logged, ADR-005); the collector
pairs a router's one-record-per-direction output into bidirectional flows before scoring (ADR-015).

## What is in the UI

Dashboard (risk gauge, KPIs incl. data volume, traffic chart with a Flows/Data switch, top talkers,
protocols, top attackers, monitored hosts, live alerts, sources) · Traffic (data sent and received per
monitored host, over time, with top peers and services) · Alerts (filters, CSV export) and alert detail (evidence, triage, recommendations, why
the model flagged it when the model supports it) · Actions (the ranked to-do list with framework
references and a data-protection note) · Risk (assets, 24 h trend) · Models (registry, comparison,
per-class metrics, limitations, activate) · Reports (PDF summary, alerts CSV, data-volume CSV) · Evaluate (SUS and TAM
forms, aggregate for admins) · Add source (wizard: quick-start sensor, router NetFlow or HTTP API).

## Test

```bash
make test        # pytest in the Linux dev image against a throwaway database
make lint        # ruff + ruff format --check + mypy (strict)
make e2e         # Playwright against the running stack (the real-data spec needs `make sample`)
```

`make test` creates and migrates a scratch database on every run, so the Alembic migrations are
exercised each time. Heavier checks (load tests, cross-dataset generalisation, k-fold CV and
tuning, real-router NetFlow) are deliberately deferred. Without `make`:

```bash
docker compose --profile test run --rm --build test pytest
uvx pre-commit run --all-files
cd tests/e2e && npm ci && E2E_BROWSER_CHANNEL=chrome npx playwright test
```

Host runs (`uv run --project backend pytest` from the repo root, with `docker compose up -d db redis`)
also work. Use `127.0.0.1`, not `localhost`: on Windows `localhost` resolves to `::1` first and
every connection stalls for about two minutes. Do not run two pytest sessions at once: they share
one test database.

## Layout

```
backend/    FastAPI API, Alembic migrations, worker, services (uv project)
collector/  UDP NetFlow v5/v9/IPFIX listener with exporter allow-list and flow pairing
ml/         shared feature module (sentinelbi_ml) + download, preprocess, train, evaluate, export, sample
frontend/   Next.js 16 (App Router, TypeScript, Tailwind, TanStack Query, SVG charts)
tests/      pytest (backend, collector, ml), Playwright (e2e)
data/       datasets (gitignored) + DATASETS.md ledger + synthetic sample
docs/       DECISIONS.md (ADRs)
```

Data path: `router/replay/sensor -> collector or POST /ingest/flows -> Redis Stream flows.raw ->
worker (features -> model -> persist -> windowed alerting -> recommendations) -> Postgres/Timescale
-> API -> web`. Training and serving share one feature module, `ml/src/features.py`; a test proves
both paths build identical vectors.

## Security and privacy defaults

- Every tenant table carries `org_id` and every query is scoped by it (tested, incl. recommendations,
  reports and evaluation data).
- API keys are SHA-256 hashed and shown once; passwords use argon2id; JWTs stay in an httpOnly
  cookie behind the web app's server-side proxy.
- No payload capture: the ingest schema rejects unknown fields. `PSEUDONYMIZE_IPS=true` replaces
  internal addresses with keyed per-organisation pseudonyms before storage.
- Flows and predictions are retained 30 days (Timescale retention policies).
- Model artifacts are checksum-verified before loading; switching the platform-wide model needs a
  platform administrator (`PLATFORM_ADMIN_EMAILS`).
- CSV exports neutralise spreadsheet formulas. Active scanning is not implemented.
- `ENV=prod` refuses to start with dev-only secrets, demo seeding or the demo platform admin, and
  logs a warning if open registration is left on.
- Sign-in locks an account for 15 minutes after 8 failed attempts (per account, not per address:
  browsers reach the API through the web container, so an address limit would lock everyone out);
  open sign-up is capped at 20 organisations per hour across the deployment (ADR-025).

## Operations

Start, stop, train, back up and troubleshoot: see [startup.md](startup.md). `scripts/backup.sh` writes a
database dump and the trained models; `scripts/restore.sh` restores into a scratch database so a backup
can be verified without touching live data (row counts and hypertables were checked after a real restore).
Container logs are capped at 3 x 10 MB each. Ingest capacity on a 4-core laptop, measured by draining a
queued backlog: about 1,700 flows/s on benign traffic and 1,350 on attack-heavy traffic with one worker;
about 2,400 and 2,050 with two (`WORKER_REPLICAS=2`). GitHub Actions runs lint, mypy, the pytest suite
against real TimescaleDB and Redis, and the frontend build on every push.

## Known gaps

Detection quality on a new network is unproven (see the model section and ADR-023/024); more than half
of attack flows go unflagged at the calibrated threshold; the Random Forest cannot explain individual
alerts; ingest capacity was measured by draining a queued backlog on one laptop, not by a long soak or a
load test from real exporters; the CIS Controls and NIST CSF titles are unverified (the ATT&CK ones are
checked against the official data); no real-router NetFlow test has been run; the sensor's live capture was verified on Linux (byte counts matched the kernel's own counters, IPv4 and
IPv6, with both capture backends) and on Windows for IPv4 through its raw-socket fallback; the Windows
Npcap path, which adds IPv6, is untested because Npcap is a driver the user installs and its licence forbids
bundling it, and macOS is untested; the UI polls every 3 s (no
SSE); sign-in throttling is per account only, and a known account can be locked for 15 minutes by
someone who fails on purpose; open registration is on by default (set `ALLOW_REGISTRATION=false` for a
public deployment); the Playwright specs need a trained model and are not run in CI; there is no
off-machine backup schedule, only the scripts. See ADR-014..027 for the rest.
