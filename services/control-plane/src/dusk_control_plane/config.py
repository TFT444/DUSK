"""Validated runtime configuration for the production control plane."""

from __future__ import annotations

import math
from enum import StrEnum
from typing import Literal
from urllib.parse import urlsplit

from pydantic import Field, SecretStr, model_validator
from pydantic_settings import BaseSettings, SettingsConfigDict

from dusk_control_plane import __version__


class Environment(StrEnum):
    """Supported deployment classes."""

    LOCAL = "local"
    TEST = "test"
    DEVELOPMENT = "development"
    STAGING = "staging"
    PRODUCTION = "production"


class Settings(BaseSettings):
    """Control-plane settings loaded exclusively from ``DUSK_CP_*`` variables."""

    model_config = SettingsConfigDict(
        env_prefix="DUSK_CP_",
        case_sensitive=False,
        extra="ignore",
        frozen=True,
    )

    environment: Environment = Environment.LOCAL
    service_name: str = Field(default="dusk-control-plane", min_length=1, max_length=64)
    service_version: str = Field(default=__version__, min_length=1, max_length=32)
    host: str = Field(default="127.0.0.1", min_length=1, max_length=255)
    port: int = Field(default=8080, ge=1, le=65535)
    log_level: str = Field(default="INFO", pattern=r"^(DEBUG|INFO|WARNING|ERROR|CRITICAL)$")
    api_docs_enabled: bool = False
    v2_enabled: bool = False
    readiness_timeout_ms: int = Field(default=1000, ge=50, le=5000)
    evaluation_timeout_seconds: float = Field(default=10.0, ge=0.1, le=30.0)
    max_request_body_bytes: int = Field(default=1024 * 1024, ge=1024, le=10 * 1024 * 1024)
    oidc_issuer: str | None = Field(default=None, min_length=1, max_length=512)
    oidc_audience: str | None = Field(default=None, min_length=1, max_length=256)
    oidc_jwks_uri: str | None = Field(default=None, min_length=1, max_length=1024)
    oidc_algorithms: tuple[Literal["RS256", "RS384", "RS512", "ES256", "ES384", "ES512"], ...] = (
        "RS256",
    )
    oidc_tenant_claim: str = Field(default="dusk_tenant_id", pattern=r"^[A-Za-z0-9_.-]{1,64}$")
    oidc_identity_kind_claim: str = Field(
        default="dusk_identity_kind", pattern=r"^[A-Za-z0-9_.-]{1,64}$"
    )
    oidc_roles_claim: str = Field(default="dusk_roles", pattern=r"^[A-Za-z0-9_.-]{1,64}$")
    oidc_workload_claim: str = Field(default="dusk_workload_id", pattern=r"^[A-Za-z0-9_.-]{1,64}$")
    oidc_clock_skew_seconds: int = Field(default=30, ge=0, le=120)
    oidc_max_token_age_seconds: int = Field(default=3600, ge=60, le=86400)
    oidc_jwks_ttl_seconds: int = Field(default=300, ge=30, le=900)
    oidc_jwks_min_refresh_seconds: int = Field(default=5, ge=1, le=60)
    oidc_http_timeout_seconds: float = Field(default=2.0, ge=0.1, le=10.0)
    oidc_max_jwks_bytes: int = Field(default=262_144, ge=1024, le=1_048_576)
    oidc_max_jwks_keys: int = Field(default=32, ge=1, le=128)
    oidc_max_token_bytes: int = Field(default=16_384, ge=1024, le=65_536)
    storage_enabled: bool = False
    database_url: SecretStr | None = None
    database_pool_size: int = Field(default=10, ge=1, le=100)
    database_max_overflow: int = Field(default=10, ge=0, le=100)
    database_pool_timeout_seconds: float = Field(default=5.0, ge=0.1, le=30.0)
    database_statement_timeout_ms: int = Field(default=5000, ge=100, le=60_000)
    decision_read_api_enabled: bool = False
    dashboard_read_api_enabled: bool = False
    operations_read_api_enabled: bool = False
    integration_health_stale_after_seconds: int = Field(default=120, ge=30, le=3600)
    observability_enabled: bool = False
    otlp_endpoint: str | None = Field(default=None, min_length=1, max_length=1024)
    otlp_headers: SecretStr | None = Field(default=None, max_length=4096)
    telemetry_queue_size: int = Field(default=2048, ge=128, le=16_384)
    telemetry_batch_size: int = Field(default=256, ge=1, le=2048)
    telemetry_export_interval_ms: int = Field(default=5000, ge=1000, le=60_000)
    telemetry_export_timeout_ms: int = Field(default=1000, ge=100, le=10_000)
    privacy_lifecycle_enabled: bool = False
    retention_batch_size: int = Field(default=100, ge=1, le=500)
    decision_cursor_signing_key: SecretStr | None = Field(
        default=None, min_length=32, max_length=512
    )
    outbox_worker_enabled: bool = False
    outbox_batch_size: int = Field(default=20, ge=1, le=200)
    outbox_max_concurrency: int = Field(default=4, ge=1, le=32)
    outbox_poll_interval_seconds: float = Field(default=1.0, ge=0.1, le=60.0)
    outbox_lease_seconds: int = Field(default=30, ge=5, le=600)
    outbox_connect_timeout_seconds: float = Field(default=3.0, ge=0.1, le=10.0)
    outbox_response_timeout_seconds: float = Field(default=5.0, ge=0.1, le=30.0)
    outbox_retry_base_seconds: float = Field(default=1.0, ge=0.1, le=60.0)
    outbox_retry_max_seconds: float = Field(default=300.0, ge=1.0, le=3600.0)
    outbox_acknowledgement_max_age_seconds: int = Field(default=300, ge=30, le=3600)
    enforcement_broker_enabled: bool = False
    enforcement_broker_destination_key: str = Field(
        default="provider-enforcement-broker", min_length=1, max_length=128
    )

    @model_validator(mode="after")
    def protect_non_local_deployments(self) -> Settings:
        """Keep interactive API documentation outside staging and production."""
        if self.environment in {Environment.STAGING, Environment.PRODUCTION}:
            if self.api_docs_enabled:
                raise ValueError("api_docs_enabled must be false in staging and production")
            if self.log_level == "DEBUG":
                raise ValueError("log_level must not be DEBUG in staging and production")
        if self.v2_enabled:
            missing = [
                name
                for name, value in (
                    ("oidc_issuer", self.oidc_issuer),
                    ("oidc_audience", self.oidc_audience),
                    ("oidc_jwks_uri", self.oidc_jwks_uri),
                )
                if value is None
            ]
            if missing:
                raise ValueError(f"v2_enabled requires {', '.join(missing)}")
        trusted_urls = (("oidc_issuer", self.oidc_issuer), ("oidc_jwks_uri", self.oidc_jwks_uri))
        for name, value in trusted_urls:
            if value is not None and not _is_trusted_https_url(value, issuer=name == "oidc_issuer"):
                raise ValueError(f"{name} must use https")
        if not self.oidc_algorithms or len(set(self.oidc_algorithms)) != len(self.oidc_algorithms):
            raise ValueError("oidc_algorithms must be non-empty and unique")
        claim_names = {
            self.oidc_tenant_claim,
            self.oidc_identity_kind_claim,
            self.oidc_roles_claim,
            self.oidc_workload_claim,
        }
        if len(claim_names) != 4:
            raise ValueError("OIDC custom claim names must be distinct")
        self._validate_storage()
        self._validate_decision_reads()
        self._validate_dashboard_reads()
        self._validate_operations_reads()
        self._validate_observability()
        self._validate_privacy_lifecycle()
        self._validate_outbox()
        return self

    def _validate_decision_reads(self) -> None:
        if not self.decision_read_api_enabled:
            return
        if not self.v2_enabled or not self.storage_enabled:
            raise ValueError("decision_read_api_enabled requires v2_enabled and storage_enabled")
        if self.decision_cursor_signing_key is None:
            raise ValueError("decision_read_api_enabled requires decision_cursor_signing_key")

    def _validate_dashboard_reads(self) -> None:
        if not self.dashboard_read_api_enabled:
            return
        if not self.v2_enabled or not self.storage_enabled:
            raise ValueError("dashboard_read_api_enabled requires v2_enabled and storage_enabled")
        if self.decision_cursor_signing_key is None:
            raise ValueError("dashboard_read_api_enabled requires decision_cursor_signing_key")

    def _validate_operations_reads(self) -> None:
        if not self.operations_read_api_enabled:
            return
        if not self.v2_enabled or not self.storage_enabled:
            raise ValueError("operations_read_api_enabled requires v2_enabled and storage_enabled")
        if self.decision_cursor_signing_key is None:
            raise ValueError("operations_read_api_enabled requires decision_cursor_signing_key")

    def _validate_observability(self) -> None:
        if not self.observability_enabled:
            return
        if self.otlp_endpoint is None:
            raise ValueError("observability_enabled requires otlp_endpoint")
        try:
            parsed = urlsplit(self.otlp_endpoint)
            _ = parsed.port
        except ValueError as exc:
            raise ValueError("otlp_endpoint must be a valid HTTPS URL") from exc
        if (
            parsed.scheme != "https"
            or not parsed.hostname
            or parsed.username is not None
            or parsed.password is not None
            or parsed.query
            or parsed.fragment
        ):
            raise ValueError("otlp_endpoint must be an HTTPS URL without credentials or query")
        if self.telemetry_batch_size > self.telemetry_queue_size:
            raise ValueError("telemetry_batch_size must not exceed telemetry_queue_size")

    def _validate_outbox(self) -> None:
        if self.outbox_worker_enabled and not self.storage_enabled:
            raise ValueError("outbox_worker_enabled requires storage_enabled")
        if self.outbox_max_concurrency > self.outbox_batch_size:
            raise ValueError("outbox_max_concurrency must not exceed outbox_batch_size")
        if self.outbox_retry_max_seconds < self.outbox_retry_base_seconds:
            raise ValueError("outbox_retry_max_seconds must be at least outbox_retry_base_seconds")
        minimum_lease = (
            math.ceil(
                3 * self.outbox_connect_timeout_seconds + 2 * self.outbox_response_timeout_seconds
            )
            + 1
        )
        if self.outbox_lease_seconds < minimum_lease:
            raise ValueError("outbox_lease_seconds must cover the bounded delivery attempt")
        if self.enforcement_broker_enabled and (
            not self.v2_enabled or not self.storage_enabled or not self.outbox_worker_enabled
        ):
            raise ValueError(
                "enforcement_broker_enabled requires v2, storage, and the outbox worker"
            )

    def _validate_privacy_lifecycle(self) -> None:
        if self.privacy_lifecycle_enabled and (not self.v2_enabled or not self.storage_enabled):
            raise ValueError("privacy_lifecycle_enabled requires v2_enabled and storage_enabled")

    def _validate_storage(self) -> None:
        if not self.storage_enabled:
            return
        if self.database_url is None:
            raise ValueError("storage_enabled requires database_url")
        database_url = self.database_url.get_secret_value()
        if not database_url.startswith("postgresql+asyncpg://"):
            raise ValueError("database_url must use postgresql+asyncpg")


def _is_trusted_https_url(value: str, *, issuer: bool) -> bool:
    try:
        parsed = urlsplit(value)
        _ = parsed.port
    except ValueError:
        return False
    if (
        parsed.scheme != "https"
        or not parsed.hostname
        or parsed.username is not None
        or parsed.password is not None
        or parsed.fragment
    ):
        return False
    return not issuer or not parsed.query
