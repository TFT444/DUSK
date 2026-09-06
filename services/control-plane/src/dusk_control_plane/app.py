"""FastAPI application factory for the isolated production service."""

from __future__ import annotations

import asyncio
import logging
import time
from collections.abc import AsyncIterator, Awaitable, Callable, Sequence
from contextlib import AbstractAsyncContextManager, asynccontextmanager
from typing import Annotated, Any
from uuid import UUID

from fastapi import Depends, FastAPI, Path, Query, Request, Response
from fastapi.responses import JSONResponse

from dusk_control_plane.audit import DurableEvaluationService
from dusk_control_plane.dashboard import (
    ActionBreakdown,
    AgentDetail,
    AgentRiskPage,
    AgentRiskQuery,
    DashboardQueryUnavailableError,
    DashboardReader,
    DashboardSummary,
    DashboardWindowQuery,
    DecisionVolume,
)
from dusk_control_plane.decisions import (
    DecisionDetail,
    DecisionListQuery,
    DecisionPage,
    DecisionQueryUnavailableError,
)
from dusk_control_plane.dependencies import AppContainer, DependencyProbe
from dusk_control_plane.errors import error_response, install_error_handlers
from dusk_control_plane.evaluations import (
    EvaluationRequest,
    EvaluationResponse,
    EvaluationUnavailableError,
)
from dusk_control_plane.identity import Principal, require_route_policy
from dusk_control_plane.models import (
    ComponentHealth,
    ErrorEnvelope,
    LivenessResponse,
    ReadinessResponse,
)
from dusk_control_plane.operations import (
    IntegrationHealthPage,
    IntegrationHealthQuery,
    OperationsQueryUnavailableError,
    OperationsReader,
    PolicyListQuery,
    PolicyPage,
    PolicySummary,
    ServiceStatus,
)
from dusk_control_plane.request_context import (
    new_request_id,
    reset_decision_trace_id,
    reset_request_id,
    set_decision_trace_id,
    set_request_id,
)

REQUEST_ID_HEADER = "X-Request-ID"
logger = logging.getLogger(__name__)
_evaluation_authorization = require_route_policy("POST", "/v2/evaluations")
_decision_list_authorization = require_route_policy("GET", "/v2/decisions")
_decision_detail_authorization = require_route_policy("GET", "/v2/decisions/{trace_id}")
_dashboard_summary_authorization = require_route_policy("GET", "/v2/dashboard/summary")
_dashboard_volume_authorization = require_route_policy("GET", "/v2/dashboard/decision-volume")
_dashboard_breakdown_authorization = require_route_policy("GET", "/v2/dashboard/action-breakdown")
_agent_risk_authorization = require_route_policy("GET", "/v2/agents/risk")
_agent_detail_authorization = require_route_policy("GET", "/v2/agents/{agent_id}")
_policies_authorization = require_route_policy("GET", "/v2/policies")
_policy_summary_authorization = require_route_policy("GET", "/v2/policies/summary")
_integration_health_authorization = require_route_policy("GET", "/v2/integrations/health")
_service_status_authorization = require_route_policy("GET", "/v2/service/status")


async def _bounded_evaluate(
    service: DurableEvaluationService,
    body: EvaluationRequest,
    principal: Principal,
    timeout_seconds: float,
) -> EvaluationResponse:
    try:
        return await asyncio.wait_for(
            service.evaluate(body, principal),
            timeout=timeout_seconds,
        )
    except TimeoutError as exc:
        raise EvaluationUnavailableError from exc


def _install_v2_routes(
    app: FastAPI,
    container: AppContainer,
    common_errors: dict[int | str, dict[str, Any]],
) -> None:
    @app.post(
        "/v2/evaluations",
        response_model=EvaluationResponse,
        tags=["evaluations"],
        responses={
            401: {"model": ErrorEnvelope},
            403: {"model": ErrorEnvelope},
            503: {"model": ErrorEnvelope},
            **common_errors,
        },
    )
    async def evaluate_action(
        body: EvaluationRequest,
        principal: Annotated[Principal, Depends(_evaluation_authorization)],
    ) -> EvaluationResponse:
        service = container.evaluation_service
        if service is None or not isinstance(service, DurableEvaluationService):
            raise EvaluationUnavailableError
        response = await _bounded_evaluate(
            service,
            body,
            principal,
            container.settings.evaluation_timeout_seconds,
        )
        set_decision_trace_id(response.trace_id)
        return response

    if container.settings.dashboard_read_api_enabled:
        _install_dashboard_routes(app, container, common_errors)

    if container.settings.operations_read_api_enabled:
        _install_operations_routes(app, container, common_errors)

    if not container.settings.decision_read_api_enabled:
        return

    @app.get(
        "/v2/decisions",
        response_model=DecisionPage,
        tags=["decisions"],
        responses={
            401: {"model": ErrorEnvelope},
            403: {"model": ErrorEnvelope},
            422: {
                "model": ErrorEnvelope,
                "description": "Request validation failed",
            },
            503: {"model": ErrorEnvelope},
            **common_errors,
        },
    )
    async def list_decisions(
        query: Annotated[DecisionListQuery, Query()],
        principal: Annotated[Principal, Depends(_decision_list_authorization)],
    ) -> DecisionPage:
        reader = container.decision_reader
        if reader is None:
            raise DecisionQueryUnavailableError
        return await reader.list_decisions(query, principal)

    @app.get(
        "/v2/decisions/{trace_id}",
        response_model=DecisionDetail,
        tags=["decisions"],
        responses={
            401: {"model": ErrorEnvelope},
            403: {"model": ErrorEnvelope},
            404: {"model": ErrorEnvelope},
            422: {
                "model": ErrorEnvelope,
                "description": "Request validation failed",
            },
            503: {"model": ErrorEnvelope},
            **common_errors,
        },
    )
    async def get_decision(
        trace_id: UUID,
        principal: Annotated[Principal, Depends(_decision_detail_authorization)],
    ) -> DecisionDetail:
        reader = container.decision_reader
        if reader is None:
            raise DecisionQueryUnavailableError
        return await reader.get_decision(trace_id, principal)


def _install_dashboard_routes(
    app: FastAPI,
    container: AppContainer,
    common_errors: dict[int | str, dict[str, Any]],
) -> None:
    standard_responses: dict[int | str, dict[str, Any]] = {
        401: {"model": ErrorEnvelope},
        403: {"model": ErrorEnvelope},
        422: {"model": ErrorEnvelope, "description": "Request validation failed"},
        503: {"model": ErrorEnvelope},
        **common_errors,
    }

    def reader() -> DashboardReader:
        value = container.dashboard_reader
        if value is None:
            raise DashboardQueryUnavailableError
        return value

    @app.get(
        "/v2/dashboard/summary",
        response_model=DashboardSummary,
        tags=["dashboard"],
        responses=standard_responses,
    )
    async def dashboard_summary(
        query: Annotated[DashboardWindowQuery, Query()],
        principal: Annotated[Principal, Depends(_dashboard_summary_authorization)],
    ) -> DashboardSummary:
        return await reader().summary(query, principal)

    @app.get(
        "/v2/dashboard/decision-volume",
        response_model=DecisionVolume,
        tags=["dashboard"],
        responses=standard_responses,
    )
    async def dashboard_decision_volume(
        query: Annotated[DashboardWindowQuery, Query()],
        principal: Annotated[Principal, Depends(_dashboard_volume_authorization)],
    ) -> DecisionVolume:
        return await reader().decision_volume(query, principal)

    @app.get(
        "/v2/dashboard/action-breakdown",
        response_model=ActionBreakdown,
        tags=["dashboard"],
        responses=standard_responses,
    )
    async def dashboard_action_breakdown(
        query: Annotated[DashboardWindowQuery, Query()],
        principal: Annotated[Principal, Depends(_dashboard_breakdown_authorization)],
    ) -> ActionBreakdown:
        return await reader().action_breakdown(query, principal)

    @app.get(
        "/v2/agents/risk",
        response_model=AgentRiskPage,
        tags=["agents"],
        responses=standard_responses,
    )
    async def agent_risk(
        query: Annotated[AgentRiskQuery, Query()],
        principal: Annotated[Principal, Depends(_agent_risk_authorization)],
    ) -> AgentRiskPage:
        return await reader().agent_risk(query, principal)

    @app.get(
        "/v2/agents/{agent_id}",
        response_model=AgentDetail,
        tags=["agents"],
        responses={404: {"model": ErrorEnvelope}, **standard_responses},
    )
    async def agent_detail(
        agent_id: Annotated[str, Path(min_length=1, max_length=256)],
        query: Annotated[DashboardWindowQuery, Query()],
        principal: Annotated[Principal, Depends(_agent_detail_authorization)],
    ) -> AgentDetail:
        return await reader().agent_detail(agent_id, query, principal)


def _install_operations_routes(
    app: FastAPI,
    container: AppContainer,
    common_errors: dict[int | str, dict[str, Any]],
) -> None:
    standard_responses: dict[int | str, dict[str, Any]] = {
        401: {"model": ErrorEnvelope},
        403: {"model": ErrorEnvelope},
        422: {"model": ErrorEnvelope, "description": "Request validation failed"},
        503: {"model": ErrorEnvelope},
        **common_errors,
    }

    def reader() -> OperationsReader:
        value = container.operations_reader
        if value is None:
            raise OperationsQueryUnavailableError
        return value

    @app.get(
        "/v2/policies",
        response_model=PolicyPage,
        tags=["policies"],
        responses=standard_responses,
    )
    async def policies(
        query: Annotated[PolicyListQuery, Query()],
        principal: Annotated[Principal, Depends(_policies_authorization)],
    ) -> PolicyPage:
        return await reader().policies(query, principal)

    @app.get(
        "/v2/policies/summary",
        response_model=PolicySummary,
        tags=["policies"],
        responses=standard_responses,
    )
    async def policy_summary(
        principal: Annotated[Principal, Depends(_policy_summary_authorization)],
    ) -> PolicySummary:
        return await reader().policy_summary(principal)

    @app.get(
        "/v2/integrations/health",
        response_model=IntegrationHealthPage,
        tags=["operations"],
        responses=standard_responses,
    )
    async def integration_health(
        query: Annotated[IntegrationHealthQuery, Query()],
        principal: Annotated[Principal, Depends(_integration_health_authorization)],
    ) -> IntegrationHealthPage:
        return await reader().integration_health(query, principal)

    @app.get(
        "/v2/service/status",
        response_model=ServiceStatus,
        tags=["operations"],
        responses=standard_responses,
    )
    async def service_status(
        principal: Annotated[Principal, Depends(_service_status_authorization)],
    ) -> ServiceStatus:
        return await reader().service_status(principal)


async def _probe_component(probe: DependencyProbe, timeout_seconds: float) -> ComponentHealth:
    try:
        await asyncio.wait_for(probe.check(), timeout=timeout_seconds)
    except Exception:  # noqa: BLE001 - dependency detail must not cross the health boundary
        return ComponentHealth(name=probe.name, status="unavailable", critical=probe.critical)
    return ComponentHealth(name=probe.name, status="ready", critical=probe.critical)


def _create_lifespan(
    container: AppContainer,
) -> Callable[[FastAPI], AbstractAsyncContextManager[None]]:
    @asynccontextmanager
    async def lifespan(application: FastAPI) -> AsyncIterator[None]:
        application.state.started = True
        outbox_task: asyncio.Task[None] | None = None
        if container.settings.outbox_worker_enabled and container.outbox_worker is not None:
            outbox_task = asyncio.create_task(
                container.outbox_worker.run_forever(), name="dusk-outbox-worker"
            )
        try:
            yield
        finally:
            if container.outbox_worker is not None:
                container.outbox_worker.stop()
            if outbox_task is not None:
                try:
                    await asyncio.wait_for(outbox_task, timeout=5)
                except TimeoutError:
                    outbox_task.cancel()
                    await asyncio.gather(outbox_task, return_exceptions=True)
            if container.database is not None:
                await container.database.close()
            if container.telemetry_runtime is not None:
                container.telemetry_runtime.shutdown()
            application.state.started = False

    return lifespan


def create_app(  # noqa: C901
    *,
    container: AppContainer | None = None,
    readiness_probes: Sequence[DependencyProbe] = (),
) -> FastAPI:
    """Construct an isolated application with explicit dependencies."""
    resolved = (
        container
        if container is not None
        else AppContainer.build(readiness_probes=readiness_probes)
    )
    settings = resolved.settings

    docs_url = "/docs" if settings.api_docs_enabled else None
    openapi_url = "/openapi.json" if settings.api_docs_enabled else None
    app = FastAPI(
        title="DUSK Control Plane API",
        summary="Production security decision control plane",
        description=(
            "A separately deployed, multi-tenant service. The legacy Flask /v1/gate "
            "boundary is not part of this application."
        ),
        version=settings.service_version,
        docs_url=docs_url,
        redoc_url=None,
        openapi_url=openapi_url,
        lifespan=_create_lifespan(resolved),
    )
    app.state.container = resolved
    app.state.started = False
    install_error_handlers(app)

    @app.middleware("http")
    async def request_context(
        request: Request, call_next: Callable[[Request], Awaitable[Response]]
    ) -> Response:
        request_id = new_request_id()
        token = set_request_id(request_id)
        trace_token = set_decision_trace_id(None)
        started = time.perf_counter()
        telemetry = (
            resolved.telemetry_runtime.telemetry if resolved.telemetry_runtime is not None else None
        )

        async def dispatch() -> Response:
            try:
                content_length = request.headers.get("content-length")
                if (
                    content_length is not None
                    and content_length.isdecimal()
                    and int(content_length) > settings.max_request_body_bytes
                ):
                    response: Response = error_response(
                        status_code=413,
                        code="REQUEST_TOO_LARGE",
                        message="Request body exceeds the configured limit",
                        retryable=False,
                    )
                else:
                    response = await call_next(request)
            except Exception:  # noqa: BLE001 - map unexpected failures to a safe boundary
                logger.error(
                    "unhandled control-plane request failure",
                    extra={"event_code": "request.unhandled_failure"},
                )
                response = error_response(
                    status_code=500,
                    code="INTERNAL_ERROR",
                    message="Internal service error",
                    retryable=True,
                )
            if telemetry is None:
                response.headers[REQUEST_ID_HEADER] = request_id
                response.headers["Cache-Control"] = "no-store"
                response.headers["X-Content-Type-Options"] = "nosniff"
            else:
                with telemetry.stage("response"):
                    response.headers[REQUEST_ID_HEADER] = request_id
                    response.headers["Cache-Control"] = "no-store"
                    response.headers["X-Content-Type-Options"] = "nosniff"
                route = getattr(request.scope.get("route"), "path", "unmatched")
                telemetry.record_request(
                    method=request.method,
                    route=route,
                    status_code=response.status_code,
                    duration_ms=(time.perf_counter() - started) * 1000,
                )
            return response

        try:
            if telemetry is None:
                return await dispatch()
            with telemetry.request(method=request.method, headers=request.headers):
                return await dispatch()
        finally:
            reset_decision_trace_id(trace_token)
            reset_request_id(token)

    common_errors: dict[int | str, dict[str, Any]] = {500: {"model": ErrorEnvelope}}

    @app.get(
        "/livez",
        response_model=LivenessResponse,
        tags=["operations"],
        responses=common_errors,
    )
    async def liveness() -> LivenessResponse:
        return LivenessResponse(
            status="live",
            service=settings.service_name,
            version=settings.service_version,
        )

    @app.get(
        "/readyz",
        response_model=ReadinessResponse,
        tags=["operations"],
        responses={
            503: {
                "model": ReadinessResponse,
                "description": "A critical dependency is unavailable",
            },
            **common_errors,
        },
    )
    async def readiness() -> Response | ReadinessResponse:
        timeout_seconds = settings.readiness_timeout_ms / 1000
        components = await asyncio.gather(
            *(_probe_component(probe, timeout_seconds) for probe in resolved.readiness_probes)
        )
        ready = bool(app.state.started) and not any(
            component.critical and component.status != "ready" for component in components
        )
        body = ReadinessResponse(
            status="ready" if ready else "not_ready",
            service=settings.service_name,
            version=settings.service_version,
            components=list(components),
        )
        if ready:
            return body
        return JSONResponse(status_code=503, content=body.model_dump(mode="json"))

    if settings.v2_enabled:
        _install_v2_routes(app, resolved, common_errors)

    return app
