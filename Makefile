.DEFAULT_GOAL := help
COMPOSE ?= docker compose
TEST    := $(COMPOSE) --profile test run --rm --build test
ML      := uv run --project ml --extra train python -I -m
# newest exported model directory (override with MODEL=<version>)
MODEL   ?= $(shell ls -1t ml/models 2>/dev/null | grep -v '^\.' | head -1)
FILE    ?= data/processed/demo_sample.csv
DEMO_API_KEY ?= sbi_demo_dev_only_api_key_0000000000000000

.PHONY: help env up down logs ps migrate seed test lint fmt typecheck data train sample models replay e2e psql

help: ## Show targets
	@grep -E '^[a-z-]+:.*## ' $(MAKEFILE_LIST) | awk -F':.*## ' '{printf "  %-10s %s\n", $$1, $$2}'

env: ## Create .env from .env.example if missing
	@test -f .env || (cp .env.example .env && echo "created .env from .env.example")

up: env ## Build and start every service, wait until healthy
	$(COMPOSE) up -d --build --wait

down: ## Stop services (data volumes are kept)
	$(COMPOSE) down

logs: ## Tail logs
	$(COMPOSE) logs -f --tail=100

ps: ## Service status / health
	$(COMPOSE) ps

migrate: env ## Apply migrations, demo seed (if enabled) and register models found in ml/models
	$(COMPOSE) run --rm --build migrate

seed: env ## Re-run the idempotent demo seed
	$(COMPOSE) run --rm migrate python -m app.db.seed

test: env ## pytest (backend, collector, ml) inside the dev image against a throwaway test DB
	$(TEST) pytest

lint: env ## ruff + mypy
	$(TEST) sh -c "ruff check . && ruff format --check . && mypy --config-file backend/pyproject.toml backend/app collector"

fmt: env ## Auto-format and fix
	$(TEST) sh -c "ruff check --fix . && ruff format ."

typecheck: env ## mypy only
	$(TEST) mypy --config-file backend/pyproject.toml backend/app collector

data: ## Download NF-UNSW-NB15-v2 (verified source; SHA-256 recorded in its MANIFEST.json)
	@test -d data/raw/nf-unsw-nb15-v2 || $(ML) sentinelbi_ml.download nf-unsw-nb15-v2 --out data/raw

train: data ## Compare 5 models, export the best, benchmark serving latency, register it (needs `uv`)
	$(ML) sentinelbi_ml.train
	$(ML) sentinelbi_ml.evaluate ml/models/$(MODEL)
	$(COMPOSE) run --rm migrate python -m app.services.inference.registry sync

sample: ## Demo replay CSV from the model's HELD-OUT test rows (gitignored; derived from the dataset)
	$(ML) sentinelbi_ml.sample ml/models/$(MODEL) --out $(FILE)

models: ## List registered models (* = active)
	$(COMPOSE) run --rm migrate python -m app.services.inference.registry list

replay: env ## Replay a CSV through the ingest API (default: the demo sample; FILE=... to change)
	$(COMPOSE) run --rm -v ./data:/repo/data:ro migrate python -m app.services.ingestion.csv_replay \
	  --file /repo/$(FILE) --api-url http://api:8000 --api-key "$(DEMO_API_KEY)"

e2e: ## Playwright smoke tests against the running stack (needs `make up`)
	cd tests/e2e && npm ci && npx playwright install chromium && npx playwright test

psql: ## psql shell into the database
	$(COMPOSE) exec db sh -c 'psql -U "$$POSTGRES_USER" -d "$$POSTGRES_DB"'
