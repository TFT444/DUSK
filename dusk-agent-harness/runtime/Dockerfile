# runtime: model -> extract action -> /v1/gate -> mock-PROD.
# USE_REAL_BEDROCK=false (compose default) needs no AWS credentials.
# Build context is this example's own root (see compose.yml) since
# harness.py needs the dusk package (BedrockAdapter) installed alongside
# its own deps.
FROM python:3.13.11-slim-bookworm@sha256:20080e807bfc404f8450b185cf0fc95d553462673598549613735f70a5b4d5d0

WORKDIR /app

RUN apt-get update \
    && apt-get upgrade --yes \
    && rm -rf /var/lib/apt/lists/*

COPY pyproject.toml README.md ./
COPY src/ ./src/
RUN pip install --no-cache-dir --upgrade pip==26.2.1 setuptools==83.0.0 wheel==0.47.0 \
    && pip install --no-cache-dir -e .

COPY runtime/requirements.txt ./runtime/requirements.txt
RUN pip install --no-cache-dir -r runtime/requirements.txt \
    && pip uninstall --yes setuptools wheel pip \
    && useradd --create-home --uid 1000 agentdemo \
    && chown -R agentdemo:agentdemo /app

USER agentdemo

COPY models/ ./models/
COPY runtime/bedrock_client.py runtime/mock_bedrock.py runtime/harness.py \
    runtime/load_driver.py runtime/run_scenario.py ./

ENV PYTHONDONTWRITEBYTECODE=1

CMD ["python", "run_scenario.py"]
