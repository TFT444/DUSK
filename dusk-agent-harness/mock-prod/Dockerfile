# mock-prod: dummy downstream controller/DB target for the DUSK example.
FROM python:3.13.11-slim-bookworm@sha256:20080e807bfc404f8450b185cf0fc95d553462673598549613735f70a5b4d5d0

WORKDIR /app

RUN apt-get update \
    && apt-get upgrade --yes \
    && rm -rf /var/lib/apt/lists/*

COPY requirements.txt .
RUN pip install --no-cache-dir --upgrade pip==26.2.1 setuptools==83.0.0 wheel==0.47.0 \
    && pip install --no-cache-dir -r requirements.txt \
    && pip uninstall --yes setuptools wheel pip \
    && useradd --create-home --uid 1000 mockprod \
    && chown -R mockprod:mockprod /app

USER mockprod

COPY app.py .

ENV MOCK_PROD_HOST=0.0.0.0 \
    MOCK_PROD_PORT=9000 \
    PYTHONDONTWRITEBYTECODE=1

EXPOSE 9000

HEALTHCHECK --interval=10s --timeout=3s --start-period=5s --retries=3 \
    CMD ["python", "-c", "import urllib.request; urllib.request.urlopen('http://localhost:9000/health', timeout=3)"]

CMD ["gunicorn", "--bind", "0.0.0.0:9000", "--workers", "1", "--threads", "2", "--worker-tmp-dir", "/tmp", "--no-control-socket", "app:app"]
