# syntax=docker/dockerfile:1.7
ARG PYTHON_IMAGE=python:3.13.11-slim-trixie@sha256:2b9c9803c6a287cafa0a8c917211dddd23dcd2016f049690ee5219f5d3f1636e

# hadolint ignore=DL3006
FROM ${PYTHON_IMAGE} AS builder

ENV PIP_DISABLE_PIP_VERSION_CHECK=1 \
    PIP_NO_CACHE_DIR=1 \
    PYTHONDONTWRITEBYTECODE=1

WORKDIR /build

COPY services/control-plane/runtime-requirements.lock ./runtime-requirements.lock
RUN python -m pip install --require-hashes --no-deps -r runtime-requirements.lock

COPY pyproject.toml README.md /build/dusk-package/
COPY src/ /build/dusk-package/src/
COPY services/control-plane/pyproject.toml services/control-plane/README.md /build/control-plane/
COPY services/control-plane/alembic.ini /build/control-plane/
COPY services/control-plane/src/ /build/control-plane/src/

RUN python -m pip install --no-build-isolation --no-compile --no-deps /build/dusk-package \
    && python -m pip install --no-build-isolation --no-compile --no-deps /build/control-plane

# hadolint ignore=DL3006
FROM ${PYTHON_IMAGE} AS runtime

ARG SOURCE_DATE_EPOCH=0
ARG OCI_VERSION=0.0.0
ARG OCI_REVISION=unknown
ARG DEBIAN_SNAPSHOT=20260905T000000Z

LABEL org.opencontainers.image.title="DUSK control plane" \
    org.opencontainers.image.description="Multi-tenant security decision control plane" \
    org.opencontainers.image.source="https://github.com/ShieldTech-Ltd/DUSK" \
    org.opencontainers.image.version="${OCI_VERSION}" \
    org.opencontainers.image.revision="${OCI_REVISION}" \
    org.opencontainers.image.licenses="Apache-2.0"

RUN sed --in-place \
      --expression="s|http://deb.debian.org/debian-security|https://snapshot.debian.org/archive/debian-security/${DEBIAN_SNAPSHOT}|g" \
      --expression="s|http://deb.debian.org/debian|https://snapshot.debian.org/archive/debian/${DEBIAN_SNAPSHOT}|g" \
      /etc/apt/sources.list.d/debian.sources \
    && apt-get -o Acquire::Check-Valid-Until=false update \
    && apt-get upgrade --yes \
    && rm -rf /var/lib/apt/lists/* \
    && groupadd --gid 10001 dusk \
    && useradd --no-create-home --uid 10001 --gid 10001 --shell /usr/sbin/nologin dusk \
    && mkdir --mode=0555 /app \
    && chown 10001:10001 /app

COPY --from=builder /usr/local/lib/python3.13/site-packages/ /usr/local/lib/python3.13/site-packages/
COPY --from=builder /usr/local/bin/dusk-control-plane /usr/local/bin/dusk-control-plane
COPY --from=builder /usr/local/bin/dusk-control-plane-migrate /usr/local/bin/dusk-control-plane-migrate
COPY --from=builder /usr/local/bin/alembic /usr/local/bin/alembic
COPY --chown=10001:10001 --chmod=0444 services/control-plane/alembic.ini /app/alembic.ini

RUN rm -rf /usr/local/lib/python3.13/site-packages/pip* \
    /usr/local/lib/python3.13/site-packages/setuptools* \
    /usr/local/lib/python3.13/site-packages/wheel* \
    /usr/local/bin/pip /usr/local/bin/pip3 /usr/local/bin/pip3.13 \
    /usr/local/bin/wheel /root/.cache

WORKDIR /app
USER 10001:10001

ENV DUSK_CP_ENVIRONMENT=production \
    DUSK_CP_HOST=0.0.0.0 \
    DUSK_CP_PORT=8080 \
    DUSK_CP_API_DOCS_ENABLED=false \
    DUSK_CP_V2_ENABLED=false \
    PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1

EXPOSE 8080

HEALTHCHECK --interval=10s --timeout=3s --start-period=5s --retries=3 \
    CMD ["python", "-c", "import urllib.request; urllib.request.urlopen('http://localhost:8080/livez', timeout=3)"]

CMD ["dusk-control-plane"]
