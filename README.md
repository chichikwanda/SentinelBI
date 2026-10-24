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

The active model is a Random Forest trained on NF-UNSW-NB15-v2 with the NetFlow-compatible core
features. On its held-out test split it flags attacks very well (99.8% of attack flows flagged, 0.5%
of benign flows falsely flagged, macro ROC-AUC 0.996) and recognises exploits (F1 0.88) and scans
(F1 0.86), but is **weak at telling DoS (0.48), backdoor (0.30) and web attacks (0.14) apart**. The
split is random (the dataset has no timestamps), so scores are optimistic; there is no
cross-dataset test and no evaluation on real SME traffic yet. **Expect false alarms on real
networks:** an informal probe (hand-made flows, not a benchmark) showed typical HTTPS, HTTP,
SMTP, DNS, UDP and ICMP flows being labelled as attacks (probability 0.34-0.81), because the
benign traffic in the training data comes from one lab testbed. The fix is more diverse training
data plus calibration on a consented pilot capture; it is the first thing to do next. Details, limitations and what was
deliberately not done: the model card (Models page) and ADR-016b.

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

The trained model is not committed (it is reproducible and 29 MB). One command downloads the
dataset (verified source, checksummed), compares five models, exports the best, benchmarks it and
registers it; the next ones make a demo CSV from the held-out test rows and replay it:

```bash
make train      # ~15 min on 4 cores: download + train + benchmark + register
make sample     # data/processed/demo_sample.csv: 2,962 REAL flows from the test split
make replay     # post them through the ingest API with the demo source's key
```

Sign in as the demo admin: within seconds the dashboard shows alerts, the risk gauge, traffic
charts and top attackers; open an alert for evidence, triage and ranked recommendations.
Before a model exists the stack runs on a labelled **placeholder** rule set and says so.

Without `make` (e.g. Windows) run the underlying commands from the Makefile
(`uv run --project ml --extra train python -I -m sentinelbi_ml.train` and so on); use
`MSYS_NO_PATHCONV=1` in Git Bash when a command argument starts with `/repo`.

### Onboard your own network

`/sources/new` is the wizard. An IP address alone gives the platform no traffic, so it creates the
source, shows a one-time API key and the collector address, and gives copy-paste router config
(MikroTik, pfSense, Cisco) or an HTTP/curl example, then polls until the first flows arrive.
NetFlow exporters are accepted only from the registered address (unknown or ambiguous exporters
are dropped and logged, ADR-005); the collector pairs a router's one-record-per-direction output
into bidirectional flows before scoring (ADR-015).

## What is in the UI

Dashboard (risk gauge, KPIs, traffic chart, top talkers, protocols, top attackers, live alerts,
sources) · Alerts (filters, CSV export) and alert detail (evidence, triage, recommendations, why
the model flagged it when the model supports it) · Actions (the ranked to-do list with framework
references and a data-protection note) · Risk (assets, 24 h trend) · Models (registry, comparison,
per-class metrics, limitations, activate) · Reports (PDF summary, CSV) · Evaluate (SUS and TAM
forms, aggregate for admins) · Add source (wizard).

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
- `ENV=prod` refuses to start with dev-only secrets, demo seeding or the demo platform admin.

## Known gaps

The CIS Controls and NIST CSF reference titles are unverified (the ATT&CK ones are checked against the
official data); the selected Random Forest cannot explain individual alerts; classification of
DoS/backdoor/web attacks is weak; no real-router NetFlow test has been run; the UI polls every 3 s
(no SSE); no login rate-limiting; open registration by default. See ADR-014..022 for the rest.
