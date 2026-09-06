"""Strict normalization of provider events into non-sensitive policy evidence."""

from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass
from datetime import datetime

from dusk_control_plane.policy import EvidenceRejectedError

MAX_EVENT_DEPTH = 12
MAX_COLLECTION_ITEMS = 500


@dataclass(frozen=True)
class NormalizedProviderEvent:
    """Canonical fields derived from one provider event without retaining it."""

    source_identity: str
    provenance: str
    observed_at: datetime
    nonce: str
    action: Mapping[str, object]
    domains: Mapping[str, Mapping[str, object]]


def normalize_aws_cloudtrail(
    event: Mapping[str, object], *, source_identity: str
) -> NormalizedProviderEvent:
    """Normalize a CloudTrail management event used by the certification matrix."""
    _validate_shape(event)
    name = _text(event, "eventName")
    observed_at = _timestamp(event, "eventTime")
    nonce = _text(event, "eventID")
    account = _text(event, "recipientAccountId")
    request = _mapping(event.get("requestParameters"))
    action_type = _aws_action_type(name)
    target = _aws_target(event, request)
    action: dict[str, object] = {
        "type": action_type,
        "target": target,
        "consequential": True,
        "protected_target": True,
    }
    cloud: dict[str, object] = {
        "provider": "aws",
        "source_boundary": account,
        "target_boundary": str(request.get("targetAccountId", account)),
        "environment": str(request.get("environment", "unknown")),
        "public_exposure": _aws_public_exposure(request),
    }
    if action_type == "iam.role.assign":
        action.update(
            target_identity=str(request.get("roleName", target)),
            role=_aws_role(request),
        )
    if action_type == "cloud.control.update":
        cloud.update(control=_aws_control(name), enabled=False)
    return NormalizedProviderEvent(
        source_identity,
        "aws:cloudtrail:management-event",
        observed_at,
        nonce,
        action,
        {"cloud": cloud},
    )


def normalize_azure_activity(
    event: Mapping[str, object], *, source_identity: str, observed_at: datetime | None = None
) -> NormalizedProviderEvent:
    """Normalize a signed Azure Activity Log record for role and network controls."""
    _validate_shape(event)
    operation_value = event.get("operationName")
    operation = (
        str(_mapping(operation_value).get("value", ""))
        if isinstance(operation_value, Mapping)
        else str(operation_value or "")
    )
    if not operation:
        raise EvidenceRejectedError("Azure event is missing operationName")
    resource_id = _text(event, "resourceId")
    timestamp = observed_at or _timestamp(event, "eventTimestamp")
    nonce = str(event.get("eventDataId") or event.get("correlationId") or "")
    if not nonce:
        raise EvidenceRejectedError("Azure event is missing an immutable event identifier")
    subscription = _azure_subscription(resource_id)
    properties = _mapping(event.get("properties"))
    role = str(properties.get("roleName", properties.get("roleDefinitionId", "unknown")))
    action_type = "iam.role.assign" if "roleassignments/write" in operation.lower() else "unknown"
    action = {
        "type": action_type,
        "target": resource_id,
        "consequential": True,
        "protected_target": True,
        "target_identity": str(properties.get("principalId", "unknown")),
        "role": role,
    }
    target_subscription = str(properties.get("targetSubscriptionId", subscription))
    cloud = {
        "provider": "azure",
        "source_boundary": subscription,
        "target_boundary": target_subscription,
        "public_exposure": bool(properties.get("publicExposure", False)),
    }
    return NormalizedProviderEvent(
        source_identity,
        "azure:activity-log:management-event",
        timestamp,
        nonce,
        action,
        {"cloud": cloud},
    )


def normalize_kubernetes_admission(
    review: Mapping[str, object],
    *,
    source_identity: str,
    observed_at: datetime,
    public_ingress_classes: frozenset[str] = frozenset(),
) -> NormalizedProviderEvent:
    """Normalize an AdmissionReview request without retaining the Kubernetes object."""
    _validate_shape(review)
    request = _mapping(review.get("request"))
    nonce = _required_mapping_text(request, "uid", "Kubernetes admission request")
    operation = _required_mapping_text(request, "operation", "Kubernetes admission request")
    kind = _mapping(request.get("kind"))
    kind_name = _required_mapping_text(kind, "kind", "Kubernetes admission kind")
    obj = _mapping(request.get("object"))
    metadata = _mapping(obj.get("metadata"))
    namespace = str(request.get("namespace") or metadata.get("namespace") or "cluster")
    resource_name = str(request.get("name") or metadata.get("name") or "unknown")
    canonical_operation, attributes = _kubernetes_semantics(
        kind_name, operation, obj, public_ingress_classes
    )
    action = {
        "type": "kubernetes.admission",
        "target": f"{namespace}/{kind_name}/{resource_name}",
        "consequential": True,
        "protected_target": True,
    }
    kubernetes = {
        "operation": canonical_operation,
        "namespace": namespace,
        **attributes,
    }
    return NormalizedProviderEvent(
        source_identity,
        "kubernetes:admissionreview:v1",
        observed_at,
        nonce,
        action,
        {"kubernetes": kubernetes},
    )


def _validate_shape(value: object, *, depth: int = 0) -> None:
    if depth > MAX_EVENT_DEPTH:
        raise EvidenceRejectedError("provider event exceeds maximum nesting depth")
    if isinstance(value, Mapping):
        if len(value) > MAX_COLLECTION_ITEMS:
            raise EvidenceRejectedError("provider event mapping is too large")
        for key, child in value.items():
            if not isinstance(key, str):
                raise EvidenceRejectedError("provider event keys must be strings")
            _validate_shape(child, depth=depth + 1)
    elif isinstance(value, (list, tuple)):
        if len(value) > MAX_COLLECTION_ITEMS:
            raise EvidenceRejectedError("provider event collection is too large")
        for child in value:
            _validate_shape(child, depth=depth + 1)


def _mapping(value: object) -> Mapping[str, object]:
    return value if isinstance(value, Mapping) else {}


def _text(value: Mapping[str, object], key: str) -> str:
    raw = value.get(key)
    if not isinstance(raw, str) or not raw:
        raise EvidenceRejectedError(f"provider event is missing {key}")
    return raw


def _required_mapping_text(value: Mapping[str, object], key: str, label: str) -> str:
    raw = value.get(key)
    if not isinstance(raw, str) or not raw:
        raise EvidenceRejectedError(f"{label} is missing {key}")
    return raw


def _timestamp(value: Mapping[str, object], key: str) -> datetime:
    raw = _text(value, key)
    try:
        parsed = datetime.fromisoformat(raw.replace("Z", "+00:00"))
    except ValueError as exc:
        raise EvidenceRejectedError(f"provider event contains an invalid {key}") from exc
    if parsed.tzinfo is None or parsed.utcoffset() is None:
        raise EvidenceRejectedError(f"provider event {key} must be timezone-aware")
    return parsed


def _aws_action_type(name: str) -> str:
    lowered = name.lower()
    if lowered.startswith("delete"):
        return "cloud.resource.delete"
    if lowered in {"stoplogging", "deletebackupvault", "disablekeyrotation"}:
        return "cloud.control.update"
    if lowered in {
        "attachrolepolicy",
        "putrolepolicy",
        "updateassumerolepolicy",
        "createpolicyversion",
    }:
        return "iam.role.assign"
    if lowered in {"authorizesecuritygroupingress", "revokesecuritygroupingress"}:
        return "network.firewall.update"
    return "unknown"


def _aws_target(event: Mapping[str, object], request: Mapping[str, object]) -> str:
    for key in ("roleName", "groupId", "resourceArn", "trailName"):
        value = request.get(key)
        if isinstance(value, str) and value:
            return value
    resources = event.get("resources")
    if isinstance(resources, list) and resources:
        arn = _mapping(resources[0]).get("ARN")
        if isinstance(arn, str) and arn:
            return arn
    raise EvidenceRejectedError("AWS event is missing a target resource identifier")


def _aws_role(request: Mapping[str, object]) -> str:
    policy = str(request.get("policyArn", request.get("policyName", "unknown"))).lower()
    return "administrator" if "administratoraccess" in policy else "scoped"


def _aws_control(name: str) -> str:
    return {
        "stoplogging": "audit",
        "deletebackupvault": "backup",
        "disablekeyrotation": "encryption",
    }.get(name.lower(), "unknown")


def _aws_public_exposure(request: Mapping[str, object]) -> bool:
    return _contains_value(request, frozenset({"0.0.0.0/0", "::/0"}))


def _contains_value(value: object, expected: frozenset[str]) -> bool:
    if isinstance(value, Mapping):
        return any(_contains_value(child, expected) for child in value.values())
    if isinstance(value, (list, tuple)):
        return any(_contains_value(child, expected) for child in value)
    return isinstance(value, str) and value in expected


def _azure_subscription(resource_id: str) -> str:
    parts = resource_id.strip("/").split("/")
    for index, part in enumerate(parts[:-1]):
        if part.lower() == "subscriptions" and parts[index + 1]:
            return parts[index + 1]
    raise EvidenceRejectedError("Azure resourceId is missing its subscription boundary")


def _kubernetes_semantics(
    kind: str,
    operation: str,
    obj: Mapping[str, object],
    public_ingress_classes: frozenset[str],
) -> tuple[str, dict[str, object]]:
    verb = "create" if operation.upper() == "CREATE" else "update"
    if kind in {"ClusterRoleBinding", "RoleBinding"}:
        role = str(_mapping(obj.get("roleRef")).get("name", "unknown"))
        return "rbac.grant", {"role": role, "privileged": False, "public_exposure": False}
    if kind in {"Pod", "Deployment", "DaemonSet", "StatefulSet", "Job", "CronJob"}:
        return "workload.create", {
            "role": "none",
            "privileged": _kubernetes_privileged(obj),
            "public_exposure": False,
        }
    if kind == "Service":
        spec = _mapping(obj.get("spec"))
        annotations = _mapping(_mapping(obj.get("metadata")).get("annotations"))
        internal = any(
            "internal" in key and str(value).lower() == "true" for key, value in annotations.items()
        )
        return f"service.{verb}", {
            "role": "none",
            "privileged": False,
            "public_exposure": spec.get("type") == "LoadBalancer" and not internal,
        }
    if kind == "Ingress":
        spec = _mapping(obj.get("spec"))
        ingress_class = spec.get("ingressClassName")
        if not isinstance(ingress_class, str) or ingress_class not in public_ingress_classes:
            raise EvidenceRejectedError(
                "Kubernetes ingress exposure is not classified by the trusted collector"
            )
        return f"ingress.{verb}", {
            "role": "none",
            "privileged": False,
            "public_exposure": True,
        }
    return f"resource.{verb}", {
        "role": "none",
        "privileged": False,
        "public_exposure": False,
    }


def _kubernetes_privileged(obj: Mapping[str, object]) -> bool:
    spec = _mapping(obj.get("spec"))
    template = _mapping(spec.get("template"))
    pod_spec = _mapping(template.get("spec")) if template else spec
    containers = pod_spec.get("containers")
    if not isinstance(containers, list):
        return False
    return any(
        _mapping(_mapping(container).get("securityContext")).get("privileged") is True
        for container in containers
    )
