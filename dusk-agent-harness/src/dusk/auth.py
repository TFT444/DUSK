"""Fail-closed authentication for the example gate API."""

from __future__ import annotations

import hmac
import logging
import os

logger = logging.getLogger(__name__)


def gate_request_is_authorized(presented: str) -> bool:
    """Validate a presented Authorization header against gate configuration.

    A configured key requires an exact Bearer token match. Without a key,
    anonymous access is denied unless the operator explicitly sets
    ``DUSK_GATE_ALLOW_ANONYMOUS=true``.
    """
    expected = os.getenv("DUSK_GATE_API_KEY", "")
    if not expected:
        raw_allow_anonymous = os.getenv(
            "DUSK_GATE_ALLOW_ANONYMOUS",
            "",  # pragma: no mutate
        )
        allow_anonymous = raw_allow_anonymous.strip().lower()
        if allow_anonymous == "true":
            return True
        logger.warning(
            "gate request rejected: set DUSK_GATE_API_KEY or "  # pragma: no mutate
            "DUSK_GATE_ALLOW_ANONYMOUS=true"  # pragma: no mutate
        )
        return False

    prefix = "Bearer "
    if not presented.startswith(prefix):
        return False
    return hmac.compare_digest(presented[len(prefix) :], expected)
