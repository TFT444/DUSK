from __future__ import annotations

import importlib.util
import json
from pathlib import Path

import pytest

_MODULE_PATH = Path(__file__).resolve().parents[1] / "scripts" / "validate_real_agent_evidence.py"
_SPEC = importlib.util.spec_from_file_location("validate_real_agent_evidence", _MODULE_PATH)
assert _SPEC is not None and _SPEC.loader is not None
_MODULE = importlib.util.module_from_spec(_SPEC)
_SPEC.loader.exec_module(_MODULE)

parse_junit_counts = _MODULE.parse_junit_counts
validate_counts = _MODULE.validate_counts
write_validated_manifest = _MODULE.write_validated_manifest


def _write_junit(path, suite_attributes: list[str]) -> None:
    suites = "".join(f"<testsuite {attributes}/>" for attributes in suite_attributes)
    path.write_text(f"<testsuites>{suites}</testsuites>", encoding="utf-8")


@pytest.mark.parametrize(
    ("attributes", "message"),
    [
        ('tests="0" failures="0" errors="0" skipped="0"', "zero tests"),
        ('tests="16" failures="1" errors="0" skipped="0"', "failures"),
        ('tests="16" failures="0" errors="1" skipped="0"', "errors"),
        ('tests="16" failures="0" errors="0" skipped="1"', "skipped"),
    ],
)
def test_invalid_junit_counts_are_rejected(tmp_path, attributes, message):
    junit = tmp_path / "results.xml"
    _write_junit(junit, [attributes])

    with pytest.raises(ValueError, match=message):
        validate_counts(parse_junit_counts(junit))


def test_multiple_leaf_suites_are_summed(tmp_path):
    junit = tmp_path / "results.xml"
    junit.write_text(
        """<testsuites tests="99" failures="99" errors="99" skipped="99">
        <testsuite name="first" tests="7" failures="0" errors="0" skipped="0"/>
        <testsuite name="nested-parent" tests="9" failures="9" errors="9" skipped="9">
          <testsuite name="second" tests="9" failures="0" errors="0" skipped="0"/>
        </testsuite>
        </testsuites>""",
        encoding="utf-8",
    )

    assert parse_junit_counts(junit) == {
        "tests": 16,
        "failures": 0,
        "errors": 0,
        "skipped": 0,
    }


@pytest.mark.parametrize(
    "xml",
    [
        '<testsuites><testsuite tests="x" failures="0" errors="0" skipped="0"/></testsuites>',
        '<testsuites><testsuite tests="1" failures="-1" errors="0" skipped="0"/></testsuites>',
        "<testsuites><testsuite></testsuites>",
    ],
)
def test_malformed_or_invalid_junit_is_rejected(tmp_path, xml):
    junit = tmp_path / "results.xml"
    junit.write_text(xml, encoding="utf-8")

    with pytest.raises(ValueError):
        parse_junit_counts(junit)


def test_missing_junit_is_rejected(tmp_path):
    with pytest.raises(ValueError, match="does not exist"):
        parse_junit_counts(tmp_path / "missing.xml")


def test_junit_with_document_type_is_rejected(tmp_path):
    junit = tmp_path / "results.xml"
    junit.write_text(
        '<!DOCTYPE testsuites [<!ENTITY x "unsafe">]><testsuites>&x;</testsuites>',
        encoding="utf-8",
    )

    with pytest.raises(ValueError, match="DTD or entity"):
        parse_junit_counts(junit)


def test_manifest_contains_model_identity_and_valid_counts(tmp_path):
    junit = tmp_path / "results.xml"
    manifest = tmp_path / "manifest.json"
    _write_junit(junit, ['tests="16" failures="0" errors="0" skipped="0"'])

    write_validated_manifest(
        junit_path=junit,
        output_path=manifest,
        provider="mantle",
        model_id="zai.glm-5",
        model_slug="glm-5",
        commit_sha="abc123",
        run_id="42",
        gate_mode="enforce",
    )

    evidence = json.loads(manifest.read_text(encoding="utf-8"))
    assert evidence == {
        "provider": "mantle",
        "model_id": "zai.glm-5",
        "model_slug": "glm-5",
        "commit_sha": "abc123",
        "run_id": "42",
        "gate_mode": "enforce",
        "tests": 16,
        "failures": 0,
        "errors": 0,
        "skipped": 0,
    }
    forbidden = ("token", "secret", "authorization", "api_key")
    assert not any(term in key.lower() for key in evidence for term in forbidden)


def test_invalid_results_do_not_write_a_manifest(tmp_path):
    junit = tmp_path / "results.xml"
    manifest = tmp_path / "manifest.json"
    _write_junit(junit, ['tests="16" failures="0" errors="0" skipped="1"'])

    with pytest.raises(ValueError, match="skipped"):
        write_validated_manifest(
            junit_path=junit,
            output_path=manifest,
            provider="mantle",
            model_id="moonshotai.kimi-k2.5",
            model_slug="kimi-k2-5",
            commit_sha="abc123",
            run_id="42",
            gate_mode="enforce",
        )

    assert not manifest.exists()
