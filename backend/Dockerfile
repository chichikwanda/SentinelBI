# syntax=docker/dockerfile:1.7
# Build context is the REPO ROOT (the backend depends on ../ml via a uv path dependency):
#   docker build -f backend/Dockerfile --target runtime .
FROM python:3.12-slim AS base
ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    UV_PROJECT_ENVIRONMENT=/opt/venv \
    UV_LINK_MODE=copy \
    PATH="/opt/venv/bin:$PATH"
RUN pip install --no-cache-dir uv==0.11.32

WORKDIR /repo

# ---- runtime: API, worker, migrate ---------------------------------------------------
FROM base AS runtime
COPY ml ml
COPY backend/pyproject.toml backend/uv.lock backend/
WORKDIR /repo/backend
# dependencies first (cached unless the lockfile changes)
RUN uv sync --frozen --no-dev --no-install-project
COPY backend/ ./
RUN uv sync --frozen --no-dev \
 && useradd --system --uid 10001 --no-create-home app \
 && mkdir -p /repo/data/samples
COPY data/samples /repo/data/samples
# LightGBM (and any OpenMP-linked model) needs the OpenMP runtime, which python:slim lacks.
# scikit-learn bundles its own, so a Random Forest loads without it and this bug stayed hidden
# until a LightGBM artifact was loaded inside the container.
RUN apt-get update \
 && apt-get install -y --no-install-recommends libgomp1 postgresql-client \
 && rm -rf /var/lib/apt/lists/*
USER app
EXPOSE 8000
CMD ["uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "8000"]

# ---- dev: adds test/lint tooling; source is bind-mounted by compose ------------------
FROM runtime AS dev
USER root
RUN uv sync --frozen
COPY collector /repo/collector
COPY tests /repo/tests
COPY ruff.toml /repo/ruff.toml
