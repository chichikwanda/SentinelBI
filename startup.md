# Starting SentinelBI

Everything runs in Docker. These steps are for Windows (PowerShell) from the project folder; there is no
`make` on this machine, so the commands below are the plain equivalents of the Makefile targets. The
shell scripts (`scripts/*.sh`) run in Git Bash or on any Linux VM.

## 1. Start Docker Desktop

Open Docker Desktop and wait until it says the engine is running. Check from a terminal:

```powershell
docker info
```

If it prints a `Server:` section the engine is up. If it prints an error about
`dockerDesktopLinuxEngine`, Docker is still starting or needs a restart (see Troubleshooting).

## 2. Launch the app

From the project folder:

```powershell
if (-not (Test-Path .env)) { Copy-Item .env.example .env }
docker compose up -d --build --wait
```

The first build takes several minutes on a slow link. `--wait` returns when every service reports
healthy. With the images already built, `docker compose down` took 13 s and starting again took about
1.5 minutes.

| What | Where |
|---|---|
| Web UI | http://127.0.0.1:3000 |
| API docs | http://127.0.0.1:8000/docs |
| NetFlow collector | UDP 2055 on this machine |

Use `127.0.0.1`, not `localhost`: on this machine `localhost` resolves to IPv6 first and each connection
stalls for about two minutes.

## 3. Sign in

Open http://127.0.0.1:3000. The demo organisation is seeded automatically (development setting
`SEED_DEMO_DATA=true`). The password for all three accounts is `dev-only-demo-password`.

| Login | Role |
|---|---|
| `admin@demo.sentinelbi.example` | admin, and platform admin (may switch the active model) |
| `analyst@demo.sentinelbi.example` | analyst |
| `viewer@demo.sentinelbi.example` | viewer |

Eight failed sign-ins on one account lock it for 15 minutes (`LOGIN_MAX_FAILURES`, `LOGIN_LOCKOUT_SECONDS`);
a successful sign-in resets the count. The page shows how long to wait.

## 4. Check that a trained model is active

```powershell
docker compose run --rm migrate python -m app.services.inference.registry list
```

The line starting with `*` is the active model. Trained models live in `ml\models\` (not committed to git).
On every start the `migrate` step registers the models it finds there and activates the newest one if only
the placeholder is active. If you see only `placeholder-heuristic-v0`, the stack runs on a labelled rule set,
not a trained model; train one (section 6).

A model trained before feature spec v2 is refused at load time with a clear error (ADR-024). Retrain it.

## 5. Load demo traffic and see detections

The demo file is built from real held-out test rows. If `data\processed\demo_sample.csv` is missing, create it
(section 6). Then post it to the ingest API with the demo source's key:

```powershell
docker compose run --rm -v "./data:/repo/data:ro" migrate python -m app.services.ingestion.csv_replay --file /repo/data/processed/demo_sample.csv --api-url http://api:8000 --api-key sbi_demo_dev_only_api_key_0000000000000000
```

Wait 30 to 60 seconds, then open the Dashboard, Alerts, Actions and Risk pages. The page polls every 3 seconds.
The Models page, under Details, shows the alert threshold, the per-dataset and cross-dataset results and the
probe. Read them: detection on a new network is unproven (README, ADR-023 and ADR-024).

## 5b. Monitor an IP address without a router (the sensor)

This is the "just give me an IP" path. A server cannot see an address's traffic from outside, so a small
program, the sensor, runs on the machine you want to watch and reports what it sees. It reads packet headers
only, never contents.

1. Register with an IP in the optional field (or use the box on an empty dashboard, or **Add source**).
2. **On Windows, install Npcap first** (https://npcap.com, free for personal use; download it yourself and accept
   the defaults, it cannot be bundled or installed silently). Without it the sensor still works but sees IPv4
   only, and most browsing on a modern machine is IPv6. The wizard shows commands for Windows, Linux and Docker
   with your API key and address filled in. Run the
   `--self-test` line first: it proves capture works on that machine. Run the last line to start reporting.
   Windows needs an **Administrator** PowerShell; Linux needs `sudo`. Python 3.9 or newer, nothing to install.
3. Within seconds the wizard says "First flows received". Open **Traffic** to see how much that host sent and
   received, who it talked to and which services it used. **Reports** has the per-host CSV and the PDF.

No admin rights, or just trying it? From the project folder, replay the bundled synthetic capture onto your own
address (the wizard's last tab prints this with your key):

```powershell
python sensor\sentinelbi_sensor.py --read-pcap data\samples\sensor_demo.pcap --shift-to-now --map-ip 10.20.0.5=YOUR-IP --api-url http://127.0.0.1:8000 --api-key sbi_...
```

Details, accuracy figures and limits are in `sensor/README.md`. The sensor script is served by the API itself
(`/api/v1/sensor/sentinelbi_sensor.py`, with its SHA-256 shown in the wizard), so another machine on your
network only needs to reach the API address in `API_PUBLIC_URL` (set it to this machine's LAN address in `.env`
when the sensor runs elsewhere).

### Remove a source

Dashboard, Sources table, **Remove** (administrators only). The API key stops working immediately, so a sensor
or router using it stops reporting; the flows and alerts already stored are kept (alerts just lose the link to
the source), and the source's address range is no longer a monitored host range, so the Traffic page stops
listing those hosts.

## 6. Train a model (only when none exists)

Needs `uv` and about 650 MB of dataset downloads on the first run. The training script checks every dataset file
against its recorded SHA-256 and refuses a damaged one.

```powershell
uv run --project ml --extra train python -I -m sentinelbi_ml.download nf-unsw-nb15-v2 --out data/raw
uv run --project ml --extra train python -I -m sentinelbi_ml.download nf-cse-cic-ids2018-v2 --out data/raw
uv run --project ml --extra train python -I -m sentinelbi_ml.train
uv run --project ml --extra train python -I -m sentinelbi_ml.evaluate ml/models/<version>
uv run --project ml --extra train python -I -m sentinelbi_ml.sample ml/models/<version> --out data/processed/demo_sample.csv
docker compose run --rm migrate python -m app.services.inference.registry sync
```

Replace `<version>` with the folder name `train` prints (for example `rf-nfmulti2-...`). Training takes about
15 minutes on 4 cores. The worker switches to a newly activated model within about 30 seconds.

## Back up and restore

```bash
bash scripts/backup.sh                       # database dump + trained models into backups/<UTC time>/
bash scripts/restore.sh backups/<UTC time>   # restores into a SCRATCH database to prove the backup works
```

The backup lists the dump back before trusting it and writes a SHA256SUMS file. Restoring into the live
database needs `FORCE=1` and the writers stopped first; the header of `scripts/restore.sh` has the exact steps.
`backups/` holds password hashes and every organisation's flow data: it is gitignored; keep it private.

## Throughput

Workers share one Redis stream, so more of them drain it faster. Measured on a 4-core laptop by queueing a
backlog and timing the drain (about +/-15% between runs):

| Workers | Benign traffic | Attack-heavy replay (many alert groups) |
|---|---|---|
| 1 (default) | about 1,700 flows/s | about 1,350 flows/s |
| 2 | about 2,400 flows/s | about 2,050 flows/s |

Set `WORKER_REPLICAS=2` in `.env` and run `docker compose up -d`. `WORKER_BATCH_SIZE` (default 2000) is how many
flows a worker takes per round. Each worker's log line shows where a batch spent its time, for example
`[features=24 predict=45 flows=73 predictions=48 alerts=73]` in milliseconds.

## Stop and reset

```powershell
docker compose down        # stop; the database keeps its data
docker compose down -v     # stop and WIPE the database (the demo data is re-seeded on the next start)
```

## Run the tests (optional)

```powershell
docker compose --profile test run --rm --build test pytest
cd tests\e2e; npx playwright install chromium --only-shell; npx playwright test; cd ..\..
```

The Playwright specs need the stack running and a trained model, and each run registers several new organisations, so keep `REGISTER_MAX_PER_HOUR=200` (the `.env.example` value) or the sign-up cap of 20 per hour will stop them (the page then says "Too many sign-ups"). Do not run two pytest sessions at once; they
share one test database. GitHub Actions runs lint, mypy, the pytest suite and the frontend build on every push
(`.github/workflows/ci.yml`); it does not run the Playwright specs.

## Troubleshooting

| Symptom | What to do |
|---|---|
| `docker compose` prints a 500 or "cannot find the file specified" for `dockerDesktopLinuxEngine` | The engine is not up. Start or restart Docker Desktop and wait; if it stays down, run `wsl --shutdown` and start Docker Desktop again (this stops every WSL distro). |
| Pages hang for minutes | You used `localhost`. Use `127.0.0.1`. |
| Port 3000, 8000 or 2055 already in use | Change `WEB_PORT` or `API_PORT` in `.env`, then run `docker compose up -d` again. |
| Login fails right after the first start | Check `docker compose ps` shows `migrate` exited cleanly and `api` healthy; `docker compose logs migrate` shows the seed line. |
| "Too many failed sign-in attempts" | The account is locked for the time shown. Wait, or clear the counter: `docker compose exec redis redis-cli --scan --pattern "rl:*"` lists the keys, `DEL` removes one. |
| The sensor's `--self-test` says it needs Administrator or root | Open an Administrator PowerShell (Windows) or use `sudo` (Linux). In Docker add `--cap-add=NET_RAW --cap-add=NET_ADMIN`. |
| The self-test opens capture but does not see its own packet | Linux: add `--iface <name>`. Windows: add `--interface-ip <this machine's address>`. Windows capture is untested by the author: if it still fails, use Linux or replay a capture with `--read-pcap`. |
| The sensor starts with a WARNING that the address is "not the one your internet traffic uses" | You entered a virtual adapter's address (vEthernet, WSL, Docker). Use the address of the adapter with a Default Gateway (`ipconfig` on Windows, `ip route get 1.1.1.1` on Linux), and register that address, because the Traffic page only lists hosts inside a registered source. |
| On Windows the sensor runs but your browsing does not show up | Without Npcap, Windows capture reads IPv4 only, and a dual-stack machine sends most browsing over IPv6 (the sensor says so at start-up). Install Npcap from https://npcap.com and run the sensor again: it then says "capturing via libpcap/Npcap". `--list-devices` shows its capture devices; `--iface` picks one. To confirm the rest works first, generate IPv4 traffic: `ping -4 -n 5 1.1.1.1`. |
| The sensor runs but the wizard never says "First flows received" | Check the sensor prints no "cannot reach" or "rejected the API key" lines, that `--api-url` is reachable from that machine, and that traffic involving the watched IP is actually passing that machine. Flows are reported when a connection ends or after 15 s of silence. |
| The sensor warns that the kernel dropped packets | Byte counts are then a lower bound. Run as root, or add `--cap-add=NET_ADMIN` in Docker, so it can enlarge the capture buffer. |
| No alerts after the replay | Wait a minute. Check `docker compose ps` (worker healthy), that a model is active (section 4), and `docker compose logs worker`. |
| The web image build fails with a TypeScript or "Unexpected identifier" error | This happened here without any source change and passed on retry. Run the build again. |
| Odd one-off failures: corrupted files, hash mismatches, crashes in training | This laptop has faulty memory (ADR-024). Run Windows Memory Diagnostic or MemTest86 on each RAM stick, and until then re-run anything that matters and compare. |
| Builds fail for lack of space | Docker keeps its disk image under `%LOCALAPPDATA%\Docker\wsl\disk\docker_data.vhdx`, which grows to tens of GB. `docker system df` shows what is reclaimable (here about 12 GB of unused images and 12 GB of build cache); `docker builder prune` clears the build cache (the next build is slower). The image file may not shrink until Docker Desktop compacts it; check its Resources settings. |

More detail: `README.md` (architecture, security, known gaps) and `docs/DECISIONS.md` (decisions and measured results).
