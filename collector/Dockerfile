# syntax=docker/dockerfile:1.7
# Build context: REPO ROOT.  docker build -f collector/Dockerfile .
FROM python:3.12-slim
ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    UV_PROJECT_ENVIRONMENT=/opt/venv \
    UV_LINK_MODE=copy \
    PATH="/opt/venv/bin:$PATH"
RUN pip install --no-cache-dir uv==0.11.32
WORKDIR /app
COPY collector/pyproject.toml collector/uv.lock ./
RUN uv sync --frozen --no-dev
COPY collector/*.py ./
RUN useradd --system --uid 10001 --no-create-home app
USER app
EXPOSE 2055/udp
CMD ["python", "collector.py"]
