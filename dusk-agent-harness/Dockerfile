# dusk-gate: the deterministic /v1/gate HTTP service and optional integration clients.
FROM python:3.13.11-slim-bookworm@sha256:20080e807bfc404f8450b185cf0fc95d553462673598549613735f70a5b4d5d0

WORKDIR /app

RUN apt-get update \
    && apt-get upgrade --yes \
    && rm -rf /var/lib/apt/lists/*

COPY pyproject.toml README.md ./
COPY src/ ./src/

RUN pip install --no-cache-dir --upgrade pip==26.2.1 setuptools==83.0.0 wheel==0.47.0 \
    && pip install --no-cache-dir -e . \
    && pip uninstall --yes setuptools wheel pip \
    && useradd --create-home --uid 1000 dusk \
    && mkdir -p /app/state \
    && chown -R dusk:dusk /app

USER dusk

ENV FLASK_HOST=0.0.0.0 \
    FLASK_PORT=8000 \
    DUSK_DEMO_INTEGRATIONS=false \
    PYTHONDONTWRITEBYTECODE=1

EXPOSE 8000

HEALTHCHECK --interval=10s --timeout=3s --start-period=5s --retries=3 \
    CMD ["python", "-c", "import urllib.request; urllib.request.urlopen('http://localhost:8000/health', timeout=3)"]

CMD ["gunicorn", "--bind", "0.0.0.0:8000", "--workers", "1", "--threads", "4", "--worker-tmp-dir", "/tmp", "--no-control-socket", "dusk.api:app"]
