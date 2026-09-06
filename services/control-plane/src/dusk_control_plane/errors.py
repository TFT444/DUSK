"""Safe, standardized API error handling."""

from __future__ import annotations

import logging

from fastapi import FastAPI, Request
from fastapi.exceptions import RequestValidationError
from fastapi.responses import JSONResponse
from starlette.exceptions import HTTPException as StarletteHTTPException

from dusk_control_plane.dashboard import (
    AgentNotFoundError,
    DashboardQueryUnavailableError,
    InvalidAgentRiskCursorError,
)
from dusk_control_plane.decisions import (
    DecisionNotFoundError,
    DecisionQueryUnavailableError,
    InvalidDecisionCursorError,
)
from dusk_control_plane.evaluations import EvaluationUnavailableError
from dusk_control_plane.identity import (
    AuthenticationRejectedError,
    AuthorizationDeniedError,
    IdentityProviderUnavailableError,
)
from dusk_control_plane.models import ErrorDetail, ErrorEnvelope
from dusk_control_plane.operations import (
    InvalidOperationsCursorError,
    OperationsQueryUnavailableError,
)
from dusk_control_plane.policy import EvidenceRejectedError, PolicyUnavailableError
from dusk_control_plane.request_context import get_request_id

logger = logging.getLogger(__name__)


def error_response(*, status_code: int, code: str, message: str, retryable: bool) -> JSONResponse:
    """Build a response containing no exception or dependency detail."""
    request_id = get_request_id()
    body = ErrorEnvelope(
        error=ErrorDetail(
            code=code,
            message=message,
            request_id=request_id,
            retryable=retryable,
        )
    )
    return JSONResponse(
        status_code=status_code,
        content=body.model_dump(mode="json"),
        headers={
            "X-Request-ID": request_id,
            "Cache-Control": "no-store",
            "X-Content-Type-Options": "nosniff",
        },
    )


def install_error_handlers(app: FastAPI) -> None:
    """Install handlers with stable public codes and sanitized messages."""

    @app.exception_handler(RequestValidationError)
    async def validation_error(_request: Request, _exc: RequestValidationError) -> JSONResponse:
        return error_response(
            status_code=422,
            code="REQUEST_VALIDATION_FAILED",
            message="Request validation failed",
            retryable=False,
        )

    @app.exception_handler(StarletteHTTPException)
    async def http_error(_request: Request, exc: StarletteHTTPException) -> JSONResponse:
        if exc.status_code == 404:
            return error_response(
                status_code=404,
                code="NOT_FOUND",
                message="Resource not found",
                retryable=False,
            )
        if exc.status_code == 405:
            return error_response(
                status_code=405,
                code="METHOD_NOT_ALLOWED",
                message="Method not allowed",
                retryable=False,
            )
        return error_response(
            status_code=exc.status_code,
            code="HTTP_ERROR",
            message="Request could not be completed",
            retryable=exc.status_code >= 500,
        )

    @app.exception_handler(Exception)
    async def unhandled_error(_request: Request, _exc: Exception) -> JSONResponse:
        logger.error(
            "unhandled control-plane request failure",
            extra={"event_code": "request.unhandled_failure"},
        )
        return error_response(
            status_code=500,
            code="INTERNAL_ERROR",
            message="Internal service error",
            retryable=True,
        )

    @app.exception_handler(AuthenticationRejectedError)
    async def authentication_error(
        _request: Request, _exc: AuthenticationRejectedError
    ) -> JSONResponse:
        response = error_response(
            status_code=401,
            code="AUTHENTICATION_REQUIRED",
            message="Valid authentication is required",
            retryable=False,
        )
        response.headers["WWW-Authenticate"] = "Bearer"
        return response

    @app.exception_handler(IdentityProviderUnavailableError)
    async def identity_unavailable(
        _request: Request, _exc: IdentityProviderUnavailableError
    ) -> JSONResponse:
        return error_response(
            status_code=503,
            code="IDENTITY_PROVIDER_UNAVAILABLE",
            message="Identity verification is temporarily unavailable",
            retryable=True,
        )

    @app.exception_handler(AuthorizationDeniedError)
    async def authorization_error(
        _request: Request, _exc: AuthorizationDeniedError
    ) -> JSONResponse:
        return error_response(
            status_code=403,
            code="FORBIDDEN",
            message="Access is forbidden",
            retryable=False,
        )

    @app.exception_handler(EvaluationUnavailableError)
    async def evaluation_unavailable(
        _request: Request, _exc: EvaluationUnavailableError
    ) -> JSONResponse:
        return error_response(
            status_code=503,
            code="EVALUATION_UNAVAILABLE",
            message="Evaluation is temporarily unavailable",
            retryable=True,
        )

    _install_evaluation_error_handlers(app)
    _install_decision_error_handlers(app)
    _install_dashboard_error_handlers(app)
    _install_operations_error_handlers(app)


def _install_operations_error_handlers(app: FastAPI) -> None:
    @app.exception_handler(InvalidOperationsCursorError)
    async def invalid_operations_cursor(
        _request: Request, _exc: InvalidOperationsCursorError
    ) -> JSONResponse:
        return error_response(
            status_code=422,
            code="INVALID_CURSOR",
            message="Pagination cursor is invalid for this query",
            retryable=False,
        )

    @app.exception_handler(OperationsQueryUnavailableError)
    async def operations_unavailable(
        _request: Request, _exc: OperationsQueryUnavailableError
    ) -> JSONResponse:
        return error_response(
            status_code=503,
            code="OPERATIONAL_DATA_UNAVAILABLE",
            message="Operational data is temporarily unavailable",
            retryable=True,
        )


def _install_dashboard_error_handlers(app: FastAPI) -> None:
    @app.exception_handler(InvalidAgentRiskCursorError)
    async def invalid_agent_risk_cursor(
        _request: Request, _exc: InvalidAgentRiskCursorError
    ) -> JSONResponse:
        return error_response(
            status_code=422,
            code="INVALID_CURSOR",
            message="Pagination cursor is invalid for this query",
            retryable=False,
        )

    @app.exception_handler(AgentNotFoundError)
    async def agent_not_found(_request: Request, _exc: AgentNotFoundError) -> JSONResponse:
        return error_response(
            status_code=404,
            code="AGENT_NOT_FOUND",
            message="Agent was not found",
            retryable=False,
        )

    @app.exception_handler(DashboardQueryUnavailableError)
    async def dashboard_query_unavailable(
        _request: Request, _exc: DashboardQueryUnavailableError
    ) -> JSONResponse:
        return error_response(
            status_code=503,
            code="DASHBOARD_QUERY_UNAVAILABLE",
            message="Dashboard data is temporarily unavailable",
            retryable=True,
        )


def _install_decision_error_handlers(app: FastAPI) -> None:
    @app.exception_handler(InvalidDecisionCursorError)
    async def invalid_decision_cursor(
        _request: Request, _exc: InvalidDecisionCursorError
    ) -> JSONResponse:
        return error_response(
            status_code=422,
            code="INVALID_CURSOR",
            message="Pagination cursor is invalid for this query",
            retryable=False,
        )

    @app.exception_handler(DecisionNotFoundError)
    async def decision_not_found(_request: Request, _exc: DecisionNotFoundError) -> JSONResponse:
        return error_response(
            status_code=404,
            code="DECISION_NOT_FOUND",
            message="Decision was not found",
            retryable=False,
        )

    @app.exception_handler(DecisionQueryUnavailableError)
    async def decision_query_unavailable(
        _request: Request, _exc: DecisionQueryUnavailableError
    ) -> JSONResponse:
        return error_response(
            status_code=503,
            code="DECISION_QUERY_UNAVAILABLE",
            message="Decision data is temporarily unavailable",
            retryable=True,
        )


def _install_evaluation_error_handlers(app: FastAPI) -> None:
    """Install v2 evaluation handlers without exposing dependency details."""

    @app.exception_handler(EvidenceRejectedError)
    async def evidence_rejected(_request: Request, _exc: EvidenceRejectedError) -> JSONResponse:
        return error_response(
            status_code=422,
            code="EVIDENCE_REJECTED",
            message="Evidence could not be trusted",
            retryable=False,
        )

    @app.exception_handler(PolicyUnavailableError)
    async def policy_unavailable(_request: Request, _exc: PolicyUnavailableError) -> JSONResponse:
        return error_response(
            status_code=503,
            code="POLICY_UNAVAILABLE",
            message="Policy evaluation is temporarily unavailable",
            retryable=True,
        )
