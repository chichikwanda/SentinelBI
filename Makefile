.DEFAULT_GOAL := help
COMPOSE ?= docker compose
TEST    := $(COMPOSE) --profile test run --rm --build test

.PHONY: help env up down logs ps migrate seed test lint fmt typecheck train replay e2e psql

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

migrate: env ## Apply database migrations (and seed demo data if SEED_DEMO_DATA=true)
	$(COMPOSE) run --rm --build migrate

seed: env ## Re-run the idempotent demo seed
	$(COMPOSE) run --rm migrate python -m app.db.seed

test: env ## pytest (backend, collector, ml) inside the dev image against a throwaway test DB
	$(TEST) pytest

lint: env ## ruff + mypy
	$(TEST) sh -c "ruff check /repo && ruff format --check /repo && mypy app ../collector"

fmt: env ## Auto-format and fix
	$(TEST) sh -c "ruff check --fix /repo && ruff format /repo"

typecheck: env ## mypy only
	$(TEST) mypy app ../collector

train: env ## Train/compare models (Phase 2; currently a stub that exits non-zero)
	$(TEST) python -m sentinelbi_ml.train

replay: env ## Replay the synthetic sample CSV through the ingest API (needs `make up`)
	$(COMPOSE) run --rm --build migrate python -m app.services.ingestion.csv_replay \
	  --file /repo/data/samples/synthetic_flows.csv --api-url http://api:8000 \
	  --api-key "$${DEMO_API_KEY:-sbi_demo_dev_only_api_key_0000000000000000}"

e2e: ## Playwright smoke test against the running stack (needs `make up`)
	cd tests/e2e && npm ci && npx playwright install chromium && npx playwright test

psql: ## psql shell into the database
	$(COMPOSE) exec db sh -c 'psql -U "$$POSTGRES_USER" -d "$$POSTGRES_DB"'
