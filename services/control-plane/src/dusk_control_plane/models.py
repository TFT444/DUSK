"""Public operational response models."""

from __future__ import annotations

from typing import Literal

from pydantic import BaseModel, ConfigDict


class StrictModel(BaseModel):
    """Response model that rejects accidental fields during construction."""

    model_config = ConfigDict(extra="forbid")


class ErrorDetail(StrictModel):
    code: str
    message: str
    request_id: str
    retryable: bool


class ErrorEnvelope(StrictModel):
    error: ErrorDetail


class LivenessResponse(StrictModel):
    status: Literal["live"]
    service: str
    version: str


class ComponentHealth(StrictModel):
    name: str
    status: Literal["ready", "unavailable"]
    critical: bool


class ReadinessResponse(StrictModel):
    status: Literal["ready", "not_ready"]
    service: str
    version: str
    components: list[ComponentHealth]
