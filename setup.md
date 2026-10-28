# Setting up SentinelBI on a new machine

Follow this top to bottom on a machine that has none of the project yet. Commands are given for Windows
(PowerShell) and for Linux or macOS (bash) wherever they differ. Steps that were not run on a real machine say so.

At the end you have: the web app on http://127.0.0.1:3000, the API on http://127.0.0.1:8000, the NetFlow
collector on UDP 2055, the database, and (if you bring the model, step 3) real detections.

## 0. Before you start

| You need | Notes |
|---|---|
| **Git** | to clone the project |
| **Docker with Compose v2** | Docker Desktop on Windows or macOS; Docker Engine plus the compose plugin on Linux. Check: `docker compose version` |
| **Memory for Docker** | the running stack uses about 1.3 GB when idle (measured). Give Docker at least 4 GB (Docker Desktop: Settings, Resources); the build needs more than running does (not measured) |
| **Disk** | the images are a few GB; keep about 10 GB free |
| **Free ports** | 3000 (web), 8000 (API), UDP 2055 (NetFlow). Change them in `.env` if taken (step 2) |
| **Internet** | the first build downloads base images, Python packages and npm packages, and needs Docker Hub reachable (Docker also fetches its Dockerfile builder from there) |
| **Python 3.9 or newer** | only on a machine whose traffic you want to watch with the sensor (step 8); nothing to install |
| **uv** | only if you train a model yourself (step 3, option B): https://docs.astral.sh/uv/ |

Tested on Windows 11 with Docker Desktop. Linux, macOS and Apple Silicon (arm64) were **not** tested; nothing
in the project is Windows-specific except the sensor's Npcap note in step 8.

## 1. Get the code

```bash
git clone https://github.com/Tomlimsonmoses/NetworkMonitor.git
cd NetworkMonitor
```

The repository is private, so Git asks you to sign in. On Windows a browser window opens (Git Credential
Manager). Elsewhere, sign in with `gh auth login` first, or use a GitHub personal access token when Git asks for
a password (your account password does not work). Do not paste the token into a file or a shared chat.

Check you got the latest: `git log --oneline -1`. Line endings need no setup (`.gitattributes` keeps them LF).

## 2. Create the settings file

`.env` holds local settings and is never committed.

```powershell
# Windows PowerShell
if (-not (Test-Path .env)) { Copy-Item .env.example .env }
```

```bash
# Linux or macOS (or: make env)
cp -n .env.example .env
```

The defaults work for trying it on one machine. Their `dev-only` values are deliberate: the app **refuses**
them when `ENV=prod`. **Before the first start**, and before exposing it beyond your own machine, change
`SECRET_KEY` (`openssl rand -hex 32`), `POSTGRES_PASSWORD`, `PSEUDONYM_KEY`, `DEMO_PASSWORD` and `DEMO_API_KEY`,
and set `ENV=prod`, `SEED_DEMO_DATA=false` and `ALLOW_REGISTRATION=false`. The comments in `.env.example` say
which is which. Changing `POSTGRES_PASSWORD` after the first start does not change the stored password: the
database then refuses the app (see Troubleshooting).

If a port is taken, set `WEB_PORT`, `API_PORT` or `COLLECTOR_PUBLIC_PORT` here (and `API_PUBLIC_URL` to match
the API port).

## 3. Bring the trained model (recommended)

The model is not in git (large, built from licensed datasets, reproducible). Without it the app runs on a
labelled **placeholder** rule set: monitoring, data volumes and reports work the same, but detections are
placeholder rules, not the trained model.

**Option A: copy it from the old machine (about a minute).** On the old machine, in its project folder:

```bash
ls ml/models          # note the folder name, for example rf-nfmulti2-20261024-8b787681
tar -czf sentinelbi-model.tar.gz -C ml/models rf-nfmulti2-20261024-8b787681
```

(`tar` is built into Windows 10 and later, in PowerShell as well. In Git Bash use relative paths like these: its
GNU `tar` reads `C:\...` as a remote machine and fails.) Move `sentinelbi-model.tar.gz` to the new machine (USB
drive, cloud drive, `scp`). The archive is about 49 MB (the folder is 54 MB); unpacking it gave a byte-identical
`model.joblib` in a test. Keep it private: it is not published on purpose. Then, on the new machine, in the
project folder:

```bash
tar -xzf sentinelbi-model.tar.gz -C ml/models
```

Optional, for the demo in step 7: also copy `data/processed/demo_sample.csv` (0.3 MB) from the old machine to the
same path in the new project folder.

**Option B: train it here (needs `uv`).** About 650 MB of dataset downloads (each file is checked against its
recorded SHA-256) and about 15 minutes on 4 cores, measured on the old laptop:

```powershell
uv run --project ml --extra train python -I -m sentinelbi_ml.download nf-unsw-nb15-v2 --out data/raw
uv run --project ml --extra train python -I -m sentinelbi_ml.download nf-cse-cic-ids2018-v2 --out data/raw
uv run --project ml --extra train python -I -m sentinelbi_ml.train
uv run --project ml --extra train python -I -m sentinelbi_ml.sample ml/models/<version> --out data/processed/demo_sample.csv
```

Replace `<version>` with the folder name that `train` prints. (With `make`: `make train` then `make sample`.)

The first start in step 4 registers and activates the model it finds in `ml/models/`.

## 4. Build and start

From the project folder:

```bash
docker compose up -d --build --wait      # or: make up
```

The first run downloads and builds everything; `--wait` returns when every service reports healthy. If it stops
on a network or build error, run the same command again: it continues from what is already built.

## 5. Check that it works

```bash
docker compose ps
```

Every service should be `healthy`, and `migrate` should be `Exited (0)` (it is a one-shot step).

| What | Where |
|---|---|
| Web app | http://127.0.0.1:3000 |
| API documentation | http://127.0.0.1:8000/docs |
| NetFlow collector | UDP 2055 |

Use `127.0.0.1`, not `localhost`: on Windows `localhost` resolves to IPv6 first and pages stall for minutes.

Which model is active (the line starting with `*`):

```bash
docker compose run --rm migrate python -m app.services.inference.registry list
```

You should see the model folder name from step 3. If you only see `placeholder-heuristic-v0`, the model is
missing: finish step 3, then run `docker compose run --rm migrate python -m app.services.inference.registry sync`;
the worker switches within about 30 seconds.

Database schema version (expect `0003`, marked `(head)`):

```bash
docker compose run --rm migrate alembic current
```

## 6. Sign in

Open http://127.0.0.1:3000. Either use the seeded demo accounts (`SEED_DEMO_DATA=true`, the default), password
`dev-only-demo-password`:

| Login | Role |
|---|---|
| `admin@demo.sentinelbi.example` | admin (also platform admin in dev) |
| `analyst@demo.sentinelbi.example` | analyst |
| `viewer@demo.sentinelbi.example` | viewer |

or choose **Create account** and make your own organisation (you can enter an IP to monitor on that form).
Eight failed sign-ins lock an account for 15 minutes.

## 7. See detections with the demo data (optional)

Needs the model (step 3) and `data/processed/demo_sample.csv`. It replays about 4,200 real held-out flows
through the ingest API as the demo organisation:

```powershell
docker compose run --rm -v "./data:/repo/data:ro" migrate python -m app.services.ingestion.csv_replay --file /repo/data/processed/demo_sample.csv --api-url http://api:8000 --api-key sbi_demo_dev_only_api_key_0000000000000000
```

(With `make`: `make replay`. In Git Bash put `MSYS_NO_PATHCONV=1` in front.) Sign in as the demo admin: within a
minute the dashboard shows alerts, the risk gauge and traffic charts.

## 8. Watch an IP address with the sensor

A server cannot see another machine's traffic from outside, so a small program, the sensor, runs on the machine
you want to watch and reports packet headers (never contents) to this server.

1. Register with an IP in the optional field, or use the box on an empty dashboard, or **Add source**.
2. The wizard shows commands with your API key and address filled in. **The key is shown once and is stored only
   as a hash, so save the command.** Run the first line (`--self-test`) to prove capture works, then the last.
3. **Windows:** install Npcap first (https://npcap.com, free for personal use; it cannot be bundled or installed
   silently) or the sensor sees IPv4 only, and most browsing is IPv6. Use an **Administrator** PowerShell, and
   run `cd` into the folder that holds `sentinelbi_sensor.py` before the command. **Linux:** use `sudo`.
4. After installing Npcap, `python sentinelbi_sensor.py --list-devices` then `--check` tells you whether IPv4 and
   IPv6 are both seen.

Details, accuracy figures and limits: `startup.md` (section 5b) and `sensor/README.md`.

## 9. Reaching it from other machines

A sensor or router on another machine must reach this machine. In `.env` set `API_PUBLIC_URL` to
`http://<this machine's LAN address>:8000` and `COLLECTOR_PUBLIC_HOST` to the same address, then run
`docker compose up -d`. Allow TCP 8000 (API) and UDP 2055 (NetFlow) through this machine's firewall, and TCP 3000
only if other people need the web app. Windows (Administrator PowerShell), **not run here**:

```powershell
New-NetFirewallRule -DisplayName "SentinelBI API" -Direction Inbound -Protocol TCP -LocalPort 8000 -Action Allow
New-NetFirewallRule -DisplayName "SentinelBI NetFlow" -Direction Inbound -Protocol UDP -LocalPort 2055 -Action Allow
```

## 10. Everyday commands

```bash
docker compose ps                         # state and health
docker compose logs -f api worker         # follow logs
docker compose down                       # stop; data is kept
docker compose up -d --wait               # start again (about 1.5 minutes)
git pull && docker compose up -d --build --wait    # update to new code (also applies database changes)
docker compose down -v                    # stop AND DELETE all data (database, queue): a full reset
```

After `git pull`, always use the full `up -d --build --wait`: it re-runs the `migrate` step that applies database
changes. Rebuilding only some services does not.

## 11. Run the tests (optional)

```bash
docker compose --profile test run --rm --build test pytest
```

The browser tests (Playwright) need the stack running and a trained model: see `startup.md`, "Run the tests".

## 12. What the clone does not contain

| Not in git | Why | What to do |
|---|---|---|
| `.env` | local settings and secrets | step 2 |
| `ml/models/` (trained model) | large, built from licensed data | step 3 |
| `data/processed/demo_sample.csv` | derived from the datasets | copy it or `sentinelbi_ml.sample` (step 3) |
| `data/raw/` (datasets, about 4 GB unpacked) | licensed | only for training; the download commands fetch them |
| Database: accounts, sources, flows | stored in a Docker volume on the old machine | the new machine starts **empty**: register again and create sources again. API keys cannot be copied (only hashes are stored), so each sensor needs a new source and key |

## 13. Troubleshooting a new install

| Symptom | What to do |
|---|---|
| `git clone` asks for a password and rejects it | Use a personal access token, or sign in with `gh auth login` first (step 1) |
| `docker compose` cannot connect to the engine, or mentions `dockerDesktopLinuxEngine` | Start Docker Desktop and wait until it says it is running; check with `docker info` |
| The build stops on a download or build error, or says `frontend grpc server closed unexpectedly` | Usually Docker Hub or the network dropped for a moment. Run `docker compose up -d --build --wait` again: it continues from what is already built. If it keeps happening, restart Docker Desktop |
| The build is killed or very slow | Give Docker more memory (Docker Desktop: Settings, Resources) and close other heavy programs |
| Port 3000, 8000 or 2055 already in use | Change `WEB_PORT`, `API_PORT` or `COLLECTOR_PUBLIC_PORT` in `.env`, then `docker compose up -d` |
| Pages hang for minutes | You used `localhost`; use `127.0.0.1` |
| The model list shows only `placeholder-heuristic-v0` | The model is missing: step 3, then the `registry sync` command in step 5 |
| The API cannot connect to the database after you changed `POSTGRES_PASSWORD` | The database keeps its first password. Either put the old password back, or, if nothing in it matters, `docker compose down -v` and start again |
| Login fails right after the first start | `docker compose ps`: `migrate` should have exited cleanly and `api` be healthy; `docker compose logs migrate` shows the seed line |
| A sensor on another machine cannot connect | Step 9: `API_PUBLIC_URL`, the firewall, and a LAN address instead of `127.0.0.1` |

More: `startup.md` (day-to-day use on Windows, more troubleshooting), `README.md` (architecture, security,
known gaps), `sensor/README.md`, and `docs/DECISIONS.md` (decisions and measured results).
