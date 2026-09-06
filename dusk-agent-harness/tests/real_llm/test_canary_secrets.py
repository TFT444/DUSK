"""Canary-secret tests for real-LLM gate test suite (finding 3).

Verifies that raw model-derived values (target, change.before, change.after)
cannot appear verbatim in JUnit-compatible failure messages or gate log output.

These tests run unconditionally as part of the standard CI suite.  They do
NOT require AWS credentials and do NOT call Bedrock.
"""

from __future__ import annotations

import re
from pathlib import Path

_TEST_FILE = Path(__file__).parent / "test_real_llm_gate.py"

# Patterns that expose raw LLM-derived values in JUnit XML failure messages.
# f-string interpolations like `target={target!r}` expand to the actual value
# and are captured verbatim by pytest's JUnit reporter.
_FORBIDDEN_RAW_VALUE_PATTERNS = [
    # Raw change.after content in assertion messages
    r"after=\{change_after",
    r"after=\{change_before",
    # Raw target values logged from result dict
    r"target=\{target!r\}",
    r"got target=\{target!r\}",
    # Raw reason list (may contain score details or injected tokens)
    r"reasons=\{result\[.reasons.\]\}",
]


def test_no_raw_change_after_in_assertion_messages() -> None:
    """Assertion failure messages must not log raw change.after values."""
    text = _TEST_FILE.read_text(encoding="utf-8")
    for pattern in _FORBIDDEN_RAW_VALUE_PATTERNS:
        matches = re.findall(pattern, text)
        assert not matches, (
            f"Forbidden raw-value pattern {pattern!r} found in "
            f"{_TEST_FILE.name}; use a bounded hash or field-name list instead. "
            "Raw change.before/change.after values may contain injected credentials "
            "or other sensitive data that must not appear in JUnit XML artifacts."
        )


def test_no_raw_target_repr_in_assertion_messages() -> None:
    """Assertion failure messages must not log the raw target string."""
    text = _TEST_FILE.read_text(encoding="utf-8")
    # Look for any assertion f-string that embeds {target!r} directly
    matches = re.findall(r"f\"[^\"]*\{target!r\}[^\"]*\"", text)
    matches += re.findall(r"f\'[^\']*\{target!r\}[^\']*\'", text)
    assert not matches, (
        f"Found {len(matches)} assertion message(s) in {_TEST_FILE.name} "
        "that embed {target!r} verbatim; replace with _safe_repr(target)"
    )


def test_no_raw_reasons_list_in_assertion_messages() -> None:
    """Assertion failure messages must not dump the full reasons list.

    Gate reasons may contain scored token details from the payload.  Log
    trace_id and reason count instead.
    """
    text = _TEST_FILE.read_text(encoding="utf-8")
    # Look for pytest.fail() calls or assert ...() message strings that embed
    # result['reasons'] on the SAME line as an f-string prefix.
    # We only check single-line patterns to avoid matching multi-line docstrings
    # or function bodies that legitimately reference reasons for other purposes.
    bad_lines = [
        line
        for line in text.splitlines()
        if (
            # Must be an f-string line that embeds result['reasons'] DIRECTLY
            # (not wrapped in len() which is safe -- it only exposes the count).
            re.search(r'f["\']', line)
            and re.search(r"result\[.reasons.\]", line)
            and not re.search(r"len\(result\[.reasons.\]\)", line)
        )
    ]
    assert not bad_lines, (
        f"Found {len(bad_lines)} assertion message line(s) that embed "
        "result['reasons'] verbatim; use trace_id + reason_count instead.\n" + "\n".join(bad_lines)
    )


def test_authorization_header_not_logged_in_test_output() -> None:
    """Authorization headers must not appear in logged output or assertion messages."""
    text = _TEST_FILE.read_text(encoding="utf-8")
    # Check for patterns that would print the Authorization header value
    bad_patterns = [
        r"print\(.*[Aa]uthorization",
        r"echo.*[Aa]uthorization",
        r'f["\'].*[Aa]uthorization.*header.*["\']',
    ]
    for pattern in bad_patterns:
        assert not re.search(pattern, text), (
            f"Pattern {pattern!r} suggests Authorization header could appear in output"
        )
