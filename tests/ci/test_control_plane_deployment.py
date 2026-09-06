from __future__ import annotations

import json
from pathlib import Path

import pytest
import yaml

from scripts.validate_control_plane_deployment import (
    record_promotion,
    validate_promotion,
    validate_values,
)

ROOT = Path(__file__).resolve().parents[2]
CHART = ROOT / "deploy/helm/dusk-control-plane"


def test_chart_defaults_pin_digest_and_enable_runtime_safeguards() -> None:
    values = yaml.safe_load((CHART / "values.yaml").read_text(encoding="utf-8"))
    assert values["image"]["digest"].startswith("sha256:")
    assert ":" not in values["image"]["repository"]
    assert values["autoscaling"]["enabled"] is True
    assert values["networkPolicy"]["enabled"] is True
    assert values["migration"]["enabled"] is True


def test_workload_and_migration_use_restricted_runtime() -> None:
    deployment = (CHART / "templates/deployment.yaml").read_text(encoding="utf-8")
    migration = (CHART / "templates/migration-job.yaml").read_text(encoding="utf-8")
    for manifest in (deployment, migration):
        assert "readOnlyRootFilesystem: true" in manifest
        assert "allowPrivilegeEscalation: false" in manifest
        assert 'drop: ["ALL"]' in manifest
        assert "runAsNonRoot: true" in manifest
        assert 'include "dusk-control-plane.image"' in manifest
    assert "pg_try_advisory_lock" in (
        ROOT / "services/control-plane/src/dusk_control_plane/migration.py"
    ).read_text(encoding="utf-8")


def test_first_install_hooks_create_dependencies_before_migration() -> None:
    service_account = (CHART / "templates/serviceaccount.yaml").read_text(encoding="utf-8")
    external_secret = (CHART / "templates/externalsecret.yaml").read_text(encoding="utf-8")
    migration = (CHART / "templates/migration-job.yaml").read_text(encoding="utf-8")
    for manifest in (service_account, external_secret, migration):
        assert '"helm.sh/hook": pre-install,pre-upgrade' in manifest
    assert '"helm.sh/hook-weight": "-30"' in service_account
    assert '"helm.sh/hook-weight": "-20"' in external_secret
    assert '"helm.sh/hook-weight": "-10"' in migration
    assert "serviceAccountName:" in migration
    assert "secretKeyRef:" in migration


def test_ingress_validations_do_not_render_as_yaml_content() -> None:
    ingress = (CHART / "templates/ingress.yaml").read_text(encoding="utf-8")
    assert '$_ := required "ingress.className is required"' in ingress
    assert '$_ := required "ingress.tlsSecretName is required"' in ingress
    workflow = (ROOT / ".github/workflows/dusk.yml").read_text(encoding="utf-8")
    assert "--set ingress.enabled=true" in workflow
    assert "--set ingress.className=nginx" in workflow
    assert "--set ingress.tlsSecretName=dusk-tls" in workflow


def test_ci_executes_migrations_from_built_image_against_postgresql() -> None:
    workflow = yaml.safe_load((ROOT / ".github/workflows/dusk.yml").read_text(encoding="utf-8"))
    containers = workflow["jobs"]["containers"]
    assert containers["services"]["postgresql"]["image"].startswith("postgres:")
    controls = (ROOT / "scripts/ci/container_controls.sh").read_text(encoding="utf-8")
    assert '"$control_plane_id" dusk-control-plane-migrate' in controls


def test_runtime_image_has_no_mutable_os_package_operations() -> None:
    dockerfile = (ROOT / "services/control-plane/Dockerfile").read_text(encoding="utf-8")
    assert "FROM ${PYTHON_IMAGE}" in dockerfile
    assert "@sha256:" in dockerfile
    assert "ARG DEBIAN_SNAPSHOT=" in dockerfile
    assert "snapshot.debian.org/archive/debian/${DEBIAN_SNAPSHOT}" in dockerfile
    assert "apt-get upgrade --yes" in dockerfile
    assert "apt-get dist-upgrade" not in dockerfile


def test_manifests_do_not_embed_kubernetes_secrets() -> None:
    manifests = "\n".join(
        path.read_text(encoding="utf-8") for path in (CHART / "templates").glob("*.yaml")
    )
    assert "kind: Secret\n" not in manifests
    assert "stringData:" not in manifests
    assert "secretKeyRef:" in manifests


def test_image_admission_is_fail_closed_and_repository_bound() -> None:
    policy = yaml.safe_load(
        (ROOT / "deploy/policies/control-plane-image-policy.yaml").read_text(encoding="utf-8")
    )
    assert policy["kind"] == "ImageValidatingPolicy"
    assert policy["spec"]["failurePolicy"] == "Fail"
    assert policy["spec"]["validationConfigurations"] == {
        "mutateDigest": False,
        "required": True,
        "verifyDigest": True,
    }
    identity = policy["spec"]["attestors"][0]["cosign"]["keyless"]["identities"][0]
    assert identity["issuer"] == "https://token.actions.githubusercontent.com"
    assert "ShieldTech-Ltd/DUSK" in identity["subjectRegExp"]


def test_production_values_reject_placeholders() -> None:
    with pytest.raises(ValueError, match="placeholder image digest"):
        validate_values(CHART / "values.yaml", production=True)
    validate_values(CHART / "values.yaml", production=False)


def test_promotion_requires_the_same_verified_digest(tmp_path: Path) -> None:
    digest = "sha256:" + ("a" * 64)
    environments = [
        {
            "name": name,
            "image_digest": digest,
            "signature_verified": True,
            "sbom_verified": True,
            "provenance_verified": True,
            "evidence_uri": f"https://evidence.invalid/{name}",
            "approved_at": "2026-09-05T12:00:00Z",
        }
        for name in ("development", "staging")
    ]
    record = tmp_path / "promotion.json"
    record.write_text(json.dumps({"image_digest": digest, "environments": environments}))
    validate_promotion(record)
    environments[1]["image_digest"] = "sha256:" + ("b" * 64)
    record.write_text(json.dumps({"image_digest": digest, "environments": environments}))
    with pytest.raises(ValueError, match="same image digest"):
        validate_promotion(record)


def test_promotion_rejects_skipped_environment(tmp_path: Path) -> None:
    digest = "sha256:" + ("a" * 64)
    record = tmp_path / "promotion.json"
    record.write_text(
        json.dumps(
            {
                "image_digest": digest,
                "environments": [],
            }
        )
    )
    with pytest.raises(ValueError, match="ordered evidence"):
        validate_promotion(record, target_environment="production")


def test_promotion_rejects_requested_digest_change(tmp_path: Path) -> None:
    digest = "sha256:" + ("a" * 64)
    record = tmp_path / "promotion.json"
    record.write_text(json.dumps({"image_digest": digest, "environments": []}))
    with pytest.raises(ValueError, match="requested image digest"):
        validate_promotion(
            record,
            target_environment="development",
            expected_digest="sha256:" + ("b" * 64),
        )


def test_completed_promotion_advances_ordered_state(tmp_path: Path) -> None:
    digest = "sha256:" + ("a" * 64)
    record = tmp_path / "promotion.json"
    record.write_text(json.dumps({"image_digest": digest, "environments": []}))
    record_promotion(
        record,
        target_environment="development",
        image_digest=digest,
        evidence_uri="https://github.com/ShieldTech-Ltd/DUSK/actions/runs/1",
    )
    state = json.loads(record.read_text(encoding="utf-8"))
    assert [item["name"] for item in state["environments"]] == ["development"]
    validate_promotion(record, target_environment="staging", expected_digest=digest)


def test_workflow_enforces_promotion_validator() -> None:
    workflow = (ROOT / ".github/workflows/promote-control-plane.yml").read_text(encoding="utf-8")
    assert "CONTROL_PLANE_PROMOTION_EVIDENCE_PATH" in workflow
    assert "validate_control_plane_deployment.py promotion" in workflow
    assert '--target-environment "$TARGET_ENVIRONMENT"' in workflow
    assert workflow.count('--image-digest "$DIGEST"') == 2
    assert "record-promotion" in workflow
    assert "group: control-plane-promotion" in workflow
    assert "validate_control_plane_deployment.py first-install" in (
        ROOT / ".github/workflows/dusk.yml"
    ).read_text(encoding="utf-8")
