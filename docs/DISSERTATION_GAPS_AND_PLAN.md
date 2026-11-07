# Dissertation gaps and the plan to close them

Written after the red-flagged sections of `Dissertation_Ch1-5_Alignment_Review_Annotated.docx` were
rewritten to match the system (output: `Dissertation_Ch1-5_Aligned.docx`). Everything the dissertation
still requires that the system does not do is listed here with an ID (G1 to G15). Red `[FLAG Gx]` lines
in the Word file point back to these IDs.

## 0. Status after the build (2026-11-07)

Built and exercised on the running stack (and covered by tests): **G1** self-assessment, **G2** governance
indicators, **G3** fifteen threat-by-maturity rules, **G4** MLP plus a six-model comparison, **G5** optional
stratified cross-validation, **G9** rules view/edit/switch-off, **G10** measured queued-to-stored delay (System
health), **G12** training from the web interface, **G13** Settings (health, alerting, risk, baseline, privacy and
retention, access, people, rules, backups). Design: `docs/DECISIONS.md` ADR-031.
Still open: **G6** (SMOTE is not used: remove the wording), **G7** (explanations only for boosted-tree models:
train "Explainable only" and activate it), **G8** (practitioner walkthrough), **G14** (authorship, department,
ethics letter), **G15** (text outside the red areas; check the document), and screenshots/CI evidence (**G11**).

## 1. Gap register

| ID | The dissertation requires | State of the system | Decision needed |
|---|---|---|---|
| G1 | A self-assessment (18 items, Table 4.2) turned into maturity levels per control area | Not built | Build (recommended) or drop from Ch 1, 3, 4, 5 |
| G2 | Four governance indicators (CDPA / SI 155: licence, DPO, 24 h breach procedure, privacy notice) | Not built; rules only carry a generic compliance note | Build with G1 (they are four more self-assessment items) |
| G3 | 15 threat-by-maturity rules (R01 to R15) | 10 YAML rules that react to alerts only | Add maturity conditions to the YAML rules once G1 exists |
| G4 | Four models compared: Logistic Regression, Random Forest, XGBoost, MLP | LR, DT, RF, LightGBM, XGBoost implemented; the recorded run compared DT, RF, LightGBM; no MLP | Add `mlp` to the training options and re-run a comparison, or reword Objective 2 and RQ2 |
| G5 | Five-fold stratified cross-validation, tuned models | Not done (single validation split, fixed settings) | Add CV as a training option (costly: about 5x training time) or say it was not done |
| G6 | SMOTE inside the pipeline (Ch 2.4.1, 4.4 table text, Appendix F.2) | Not used; training-only class caps instead | Recommended: delete SMOTE wording rather than add it |
| G7 | SHAP explanations in plain language (Table 5.5) | Native tree contributions exist for LightGBM/XGBoost only; the deployed Random Forest shows "no explanation available" | Serve LightGBM, or add `shap`, or delete the claim |
| G8 | A walkthrough with five ICT practitioners (SUS/TAM, Tables 5.11, 5.12) | Questionnaires are built (Evaluate page); no sessions held | You must run the sessions; needs ethics clearance first (G14) |
| G9 | FR12: an administrator updates the rules without changing code | Rules are YAML files; changing one needs a file edit and redeploy | Rules view/editor in Settings |
| G10 | Evidence for "near-real-time": sensor to dashboard delay | Not measured | Add a timing test (sensor record to alert visible) and report it |
| G11 | Results with data: Tables 5.6, 5.7, screenshots, CI run screenshot | Screenshots show an empty system | Replay the demo capture shifted to now, then re-capture |
| G12 | (Your request) train models from the front end | Only by terminal (`make train`) | Training page, see section 2 |
| G13 | (Your request) configuration from the system, not terminal commands | Everything is `.env` and `docker compose` commands | Settings area, see section 2 |
| G14 | Department, supervisor e-mail, ethics clearance letter (Appendix C), authorship statement | Not in the code | Yours to supply; the repository is under `Tomlimsonmoses`, so the authorship statement must be exact |
| G15 | Text outside the red areas still describing the old design | Untouched by request | Sweep after G1 to G7 are decided (list below) |

### G15: text outside the red areas that no longer matches (left unchanged on purpose)

* Abstract: CICIDS2017, four classifiers, MySQL, Power BI, fifteen rules, five pages.
* 1.5 and 1.6: Objective 2 and RQ2 ("compare ... models"), Objective 4 (BI system) wording is fine only if G4 is done.
* 1.9 "Dataset quality" bullet and 1.10 assumptions: CICIDS2017, Power BI.
* 2.4.1: TensorFlow/Keras, imbalanced-learn, SMOTE, Power BI; 2.8 and Figure 2.1: CICIDS2017, Power BI, four models.
* 2.6: the paragraphs after Table 2.2 ("No (batch)", "does not compete on real-time detection").
* 3.2 to 3.3, 3.5, 3.7, Table 3.3: CICIDS2017, "about 2.8 million flows", four-model evaluation, ROC-AUC wording.
* 3.11 (proposed system, ten modules, Power BI), Table 3.5 (Power BI refresh), Table 3.7 (sprints), 3.15, 3.16.
* 4.1, 4.11, 5.1 (CICIDS2017), 5.2.3 Table 5.5 (SHAP, G7), 5.2.6 and Tables 5.11/5.12 (UAT4 "governance obligations"),
  5.3 to 5.10 (four models, MySQL, Power BI, fifteen rules, "did not test a second dataset": it now did).
* Table 4.2 and 4.5.7/4.5.9 text describe G1/G2 as if built; they carry a red flag.
* References: Lemaître et al. (2017) is no longer cited in 4.6; Sarhan et al. (2022) was added (check volume and
  pages 27, 357-370 against the publisher page).

Numbers now in the document come from `model_card.json` of `rf-nfmulti2-20261028-8b787681`, the
GitHub Actions workflow and one local run of `make test` (357 passed in 100 s). The CI checks (ruff,
mypy, sensor on Python 3.9, frontend, compose) and the Playwright tests were not run for this document: their
rows say `[Insert]`.

## 2. Plan: Settings and training from the web interface

Principle: everything an administrator does today with `.env`, `docker compose` or `make` becomes a page,
with the terminal kept only to start the stack.

### 2.1 Settings area (new "Settings" item in the navigation, admin only; platform-wide parts only for `PLATFORM_ADMIN_EMAILS`)

| Section | What it controls | Source today |
|---|---|---|
| Organisation and users | members, roles, registration on/off | `ALLOW_REGISTRATION`, users API |
| Alerting | min probability, min share, min flows, window, merge window | `ALERT_*` |
| Baseline and quarantine | learning days, auto-quarantine, minimum severity | `BASELINE_DAYS`, `AUTO_QUARANTINE`, `QUARANTINE_MIN_SEVERITY` |
| Risk | half-life, class impact weights, criticality factors | constants in `risk/scoring.py` |
| Privacy and retention | pseudonymise IPs, retention days | `PSEUDONYMIZE_IPS`, Timescale policy |
| Models | active model, per-model alert threshold, delete old models | Models page, `registry` CLI |
| Training | see 2.2 | `make train` |
| Rules | view, enable/disable, edit YAML rules with validation (G9) | `rules/*.yaml` |
| Self-assessment and governance | answer the 18 + 4 items, see maturity (G1, G2) | not built |
| Backups | create, list, verify a backup; restore into a scratch database | `scripts/backup.sh`, `restore.sh` |
| System health | services up, schema version, worker heartbeat, disk, Redis stream depth | `docker compose ps`, `registry list` |

Design: a `app_settings` table (key, value JSON, updated_by, updated_at) read through a cached
`get_runtime_settings()` that falls back to the environment value, so existing deployments keep working.
Secrets (`SECRET_KEY`, DB password) are never editable or displayed. Each change is audit-logged.

### 2.2 Training from the front end

New page `Settings > Training` (platform admin):

1. **Datasets.** Cards for NF-UNSW-NB15-v2 and NF-CSE-CIC-IDS2018-v2: present / missing / checksum verified,
   a Download and Verify button (about 650 MB), progress and the licence/citation text.
2. **New training run.** Form: datasets, algorithms (DT, RF, LightGBM, XGBoost, LR, and MLP once added),
   benign keep fraction, training caps, seed, alert-threshold target (default 2%), optional k-fold (G5).
   Button "Start training".
3. **Run view.** Live status and log, stage (download, load, dedupe, split, fit each model, evaluate,
   calibrate threshold, export), elapsed time, Cancel.
4. **Result.** The comparison table (as Table 5.3), per-class test results, confusion matrix, threshold curve,
   latency, probe, limitations, with buttons "Register" and "Activate" (platform admin) and "Download model card".
5. **History.** All runs with parameters, so a dissertation table can be reproduced.

Backend:

* New table `training_jobs` (id, status, params JSON, log tail, result version, started/finished, created_by).
* New `trainer` Compose service built from the backend image plus the `ml` train extra (adds xgboost). It polls
  `training_jobs` (or a Redis list), runs one job at a time, mounts `ml/models` and `data/raw` read-write, and
  has a memory limit so it cannot starve the stack (training peaks high; the dev laptop has 15.6 GB).
* Refactor `ml/src/train.py` into `run_training(config, progress)`; keep the CLI as a thin wrapper so
  `make train` still works. Same for `download.py` and `export.py`.
* API: `POST /api/v1/training/jobs`, `GET /training/jobs[/{id}]`, `POST /training/jobs/{id}/cancel`,
  `POST /training/datasets/{key}/download`, `GET /training/datasets`. Platform-admin only, one job at a time,
  parameters validated against allowed ranges.
* Registration and activation reuse the existing registry (`sync`, `activate`); the worker already hot-swaps within
  `MODEL_REFRESH_SECONDS` (30 s). The API container keeps `ml/models` read-only; only `trainer` writes.
* Safety: the existing SHA-256 artifact check stays; a failed run never replaces the active model; the selection
  rule (best validation macro-F1) and "test split evaluated once" stay fixed and are shown on the page.

Tests: unit tests for the job state machine and parameter validation; an integration test that runs a tiny
`--smoke` training on `data/samples` through the API; Playwright test of the page (start, progress, result).

## 3. Order of work

| Step | Work | Closes |
|---|---|---|
| 1 | Run the stack, replay the demo capture shifted to now, capture Dashboard / Alerts / Actions / Risk, record CI screenshot, fill Tables 5.6, 5.7 and the CI rows | G11 |
| 2 | Settings backend (`app_settings`, runtime settings, audit log) and Settings page: Alerting, Baseline, Privacy, Models, Users, Health | G13 |
| 3 | `trainer` service, training API and Training page (datasets, run, results, history) | G12 |
| 4 | Add `mlp` and optional k-fold to the trainer; run the 4-model comparison from the page; update Tables 5.3 and 5.4 | G4, G5 |
| 5 | Self-assessment (18 items) and governance (4 items) with maturity per control area and a page; threat-by-maturity rule conditions; rules editor in Settings | G1, G2, G3, G9 |
| 6 | Decide explanations: serve LightGBM or add `shap`; sensor-to-dashboard timing test | G7, G10 |
| 7 | Backups and system health in Settings | G13 |
| 8 | Sweep the Word file for G15, delete SMOTE wording (G6), then the walkthrough sessions and ethics letter | G6, G8, G14, G15 |

Steps 2 and 3 answer your request and can start first; step 1 is quick and unblocks the evidence tables.
Step 5 is the largest decision: the dissertation's novelty claim leans on the self-assessment and the
threat-by-maturity rules, so dropping G1 to G3 means rewriting the abstract, objectives and Chapters 3 to 5.
