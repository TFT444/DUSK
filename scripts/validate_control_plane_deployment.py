#!/usr/bin/env python3
"""Fail closed on unsafe control-plane Helm values and promotion records."""

from __future__ import annotations

import argparse
import ipaddress
import json
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

import yaml

PLACEHOLDER_HOSTS = {"control-plane.example.invalid", "identity.example.invalid"}
DOCUMENTATION_NETWORKS: tuple[ipaddress.IPv4Network, ...] = (
    ipaddress.IPv4Network("192.0.2.0/24"),
    ipaddress.IPv4Network("198.51.100.0/24"),
    ipaddress.IPv4Network("203.0.113.0/24"),
)


def _mapping(value: object, label: str) -> dict[str, Any]:
    if not isinstance(value, dict):
        raise ValueError(f"{label} must be an object")
    return value


def _validate_production_endpoints(config: dict[str, Any], ingress: dict[str, Any]) -> None:
    for field in ("oidcIssuer", "oidcJwksUri"):
        value = str(config.get(field, ""))
        if any(host in value for host in PLACEHOLDER_HOSTS) or not value.startswith("https://"):
            raise ValueError(f"production {field} must be a real HTTPS endpoint")
    if not ingress.get("enabled") or not ingress.get("tlsSecretName"):
        raise ValueError("production ingress must enable TLS with an existing secret")


def validate_values(path: Path, *, production: bool) -> None:
    values = _mapping(yaml.safe_load(path.read_text(encoding="utf-8")), "values")
    image = _mapping(values.get("image"), "image")
    digest = image.get("digest")
    if not isinstance(digest, str) or not digest.startswith("sha256:") or len(digest) != 71:
        raise ValueError("image.digest must be an exact SHA-256 digest")
    if production and digest == "sha256:" + ("0" * 64):
        raise ValueError("production cannot use the placeholder image digest")

    config = _mapping(values.get("config"), "config")
    ingress = _mapping(values.get("ingress"), "ingress")
    if production:
        _validate_production_endpoints(config, ingress)

    policy = _mapping(values.get("networkPolicy"), "networkPolicy")
    if not policy.get("enabled"):
        raise ValueError("NetworkPolicy cannot be disabled")
    egress = policy.get("approvedEgress")
    if not isinstance(egress, list) or not egress:
        raise ValueError("at least one approved egress destination is required")
    for item in egress:
        destination = _mapping(item, "approvedEgress item")
        network = ipaddress.ip_network(str(destination.get("cidr")), strict=False)
        if (
            production
            and isinstance(network, ipaddress.IPv4Network)
            and any(network.subnet_of(block) for block in DOCUMENTATION_NETWORKS)
        ):
            raise ValueError("production egress cannot use documentation-only networks")


PROMOTION_ORDER = ("development", "staging", "production")


def validate_promotion(
    path: Path,
    *,
    target_environment: str = "production",
    expected_digest: str | None = None,
) -> None:
    record = _mapping(json.loads(path.read_text(encoding="utf-8")), "promotion record")
    digest = record.get("image_digest")
    if not isinstance(digest, str) or not digest.startswith("sha256:") or len(digest) != 71:
        raise ValueError("promotion image_digest must be an exact SHA-256 digest")
    if expected_digest is not None and digest != expected_digest:
        raise ValueError("promotion evidence does not match the requested image digest")
    environments = record.get("environments")
    if target_environment not in PROMOTION_ORDER:
        raise ValueError("unknown promotion target environment")
    required = list(PROMOTION_ORDER[: PROMOTION_ORDER.index(target_environment)])
    if not isinstance(environments, list):
        raise ValueError("promotion environments must be an array")
    actual = [item.get("name") for item in environments]
    if actual != required:
        raise ValueError(
            f"promotion to {target_environment} requires ordered evidence for: "
            + (", ".join(required) if required else "no prior environments")
        )
    for item in environments:
        environment = _mapping(item, "environment evidence")
        if environment.get("image_digest") != digest:
            raise ValueError("every environment must use the same image digest")
        checks = ("signature_verified", "sbom_verified", "provenance_verified")
        if not all(environment.get(key) is True for key in checks):
            raise ValueError("signature, SBOM, and provenance verification are mandatory")
        if not environment.get("evidence_uri") or not environment.get("approved_at"):
            raise ValueError("immutable evidence and approval timestamps are mandatory")


def record_promotion(
    path: Path, *, target_environment: str, image_digest: str, evidence_uri: str
) -> None:
    """Append a completed deployment to the runner-owned promotion state."""
    validate_promotion(path, target_environment=target_environment, expected_digest=image_digest)
    record = _mapping(json.loads(path.read_text(encoding="utf-8")), "promotion record")
    environments = record["environments"]
    environments.append(
        {
            "name": target_environment,
            "image_digest": image_digest,
            "signature_verified": True,
            "sbom_verified": True,
            "provenance_verified": True,
            "evidence_uri": evidence_uri,
            "approved_at": datetime.now(UTC).isoformat(),
        }
    )
    temporary = path.with_suffix(path.suffix + ".tmp")
    temporary.write_text(json.dumps(record, indent=2) + "\n", encoding="utf-8")
    temporary.replace(path)


def validate_first_install(path: Path) -> None:
    """Verify rendered pre-install resources satisfy the migration dependencies."""
    documents = [item for item in yaml.safe_load_all(path.read_text(encoding="utf-8")) if item]
    by_kind = {str(item.get("kind")): _mapping(item, "manifest") for item in documents}
    required = {"ServiceAccount": -30, "ExternalSecret": -20, "Job": -10}
    for kind, weight in required.items():
        resource = by_kind.get(kind)
        if resource is None:
            raise ValueError(f"first-install render is missing {kind}")
        metadata = _mapping(resource.get("metadata"), f"{kind} metadata")
        annotations = _mapping(metadata.get("annotations"), f"{kind} annotations")
        if annotations.get("helm.sh/hook") != "pre-install,pre-upgrade":
            raise ValueError(f"{kind} must be a pre-install and pre-upgrade hook")
        if int(annotations.get("helm.sh/hook-weight", 0)) != weight:
            raise ValueError(f"{kind} has unsafe first-install ordering")

    job = by_kind["Job"]
    pod_spec = job["spec"]["template"]["spec"]
    if pod_spec["serviceAccountName"] != by_kind["ServiceAccount"]["metadata"]["name"]:
        raise ValueError("migration Job does not use the provisioned ServiceAccount")
    secret_name = pod_spec["containers"][0]["env"][0]["valueFrom"]["secretKeyRef"]["name"]
    if secret_name != by_kind["ExternalSecret"]["spec"]["target"]["name"]:
        raise ValueError("migration Job does not consume the ExternalSecret target")


def main() -> None:
    parser = argparse.ArgumentParser()
    subparsers = parser.add_subparsers(dest="command", required=True)
    values_parser = subparsers.add_parser("values")
    values_parser.add_argument("path", type=Path)
    values_parser.add_argument("--production", action="store_true")
    promotion_parser = subparsers.add_parser("promotion")
    promotion_parser.add_argument("path", type=Path)
    promotion_parser.add_argument(
        "--target-environment", choices=PROMOTION_ORDER, default="production"
    )
    promotion_parser.add_argument("--image-digest")
    first_install_parser = subparsers.add_parser("first-install")
    first_install_parser.add_argument("path", type=Path)
    record_parser = subparsers.add_parser("record-promotion")
    record_parser.add_argument("path", type=Path)
    record_parser.add_argument("--target-environment", choices=PROMOTION_ORDER, required=True)
    record_parser.add_argument("--image-digest", required=True)
    record_parser.add_argument("--evidence-uri", required=True)
    args = parser.parse_args()
    if args.command == "values":
        validate_values(args.path, production=args.production)
    elif args.command == "promotion":
        validate_promotion(
            args.path,
            target_environment=args.target_environment,
            expected_digest=args.image_digest,
        )
    elif args.command == "first-install":
        validate_first_install(args.path)
    else:
        record_promotion(
            args.path,
            target_environment=args.target_environment,
            image_digest=args.image_digest,
            evidence_uri=args.evidence_uri,
        )


if __name__ == "__main__":
    main()
