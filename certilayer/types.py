"""
types.py — L1 Python SDK
------------------------
All dataclasses and enums for the CertiLayer Python SDK.
Mirrors the type system used across all CertiLayer SDKs.
"""

from __future__ import annotations

from dataclasses import dataclass
from enum import Enum
from typing import Literal, Optional


# ---------------------------------------------------------------------------
# Key type helpers
# ---------------------------------------------------------------------------

class KeyPrefixes:
    """CertiLayer API key prefix constants."""
    PUBLIC_LIVE  = "certilayer_live_pk_"
    PUBLIC_TEST  = "certilayer_test_pk_"
    SECRET_LIVE  = "certilayer_live_sk_"
    SECRET_TEST  = "certilayer_test_sk_"


def is_secret_key(key: str) -> bool:
    """Return True if key is a valid secret key (server-side only)."""
    return key.startswith(KeyPrefixes.SECRET_LIVE) or key.startswith(KeyPrefixes.SECRET_TEST)


def is_public_key(key: str) -> bool:
    """Return True if key is a valid public key (safe for browser/mobile)."""
    return key.startswith(KeyPrefixes.PUBLIC_LIVE) or key.startswith(KeyPrefixes.PUBLIC_TEST)


# ---------------------------------------------------------------------------
# Verdict enum
# ---------------------------------------------------------------------------

class HCSVerdict(str, Enum):
    """
    Human Confidence Score verdict.

    | Verdict          | Score Range | Recommended Action           |
    |------------------|-------------|------------------------------|
    | human_verified   | >= 0.35     | Allow — high confidence       |
    | human_likely     | 0.30–0.35   | Soft friction / step-up auth  |
    | synthetic        | < 0.30      | Block or challenge            |
    """

    HUMAN_VERIFIED = "human_verified"
    HUMAN_LIKELY   = "human_likely"
    SYNTHETIC      = "synthetic"

    @classmethod
    def _missing_(cls, value: object) -> "HCSVerdict":
        """Unknown future verdicts fall back to SYNTHETIC (safe default)."""
        return cls.SYNTHETIC


# ---------------------------------------------------------------------------
# Result types
# ---------------------------------------------------------------------------

@dataclass(frozen=True)
class VerifyResult:
    """
    Full verification result returned by :meth:`CertiLayerClient.verify_session`.

    Attributes:
        score:      Human Confidence Score in [0.0, 1.0].
        verdict:    Verdict derived from score thresholds.
        session_id: Matches the sessionId from the mobile/web SDK.
        scored_at:  UTC ISO-8601 timestamp of score computation.
    """

    score:      float
    verdict:    HCSVerdict
    session_id: str
    scored_at:  str

    _WIRE_VERDICT_MAP = {
        "HumanVerified": HCSVerdict.HUMAN_VERIFIED,
        "HumanLikely":   HCSVerdict.HUMAN_LIKELY,
        "Synthetic":     HCSVerdict.SYNTHETIC,
    }

    @classmethod
    def from_dict(cls, data: dict) -> "VerifyResult":
        """
        Construct a VerifyResult from a raw L8 API response dict.

        The wire format uses snake_case keys and PascalCase verdict strings;
        they are translated here into this SDK's public shape. Unknown
        verdicts map to SYNTHETIC.
        """
        return cls(
            score      = float(data["hcs_score"]),
            verdict    = cls._WIRE_VERDICT_MAP.get(data["verdict"], HCSVerdict.SYNTHETIC),
            session_id = data["session_id"],
            scored_at  = data["scored_at"],
        )


@dataclass(frozen=True)
class QuickCheckResult:
    """
    Lightweight result from :meth:`CertiLayerClient.quick_check`.

    Attributes:
        score:    Human Confidence Score in [0.0, 1.0].
        verdict:  Verdict derived from score thresholds.
        passed:   True only if score >= min_score AND verdict is not SYNTHETIC.
        degraded: True when the guard let the request through WITHOUT a real
                  verification (fail_open during a CertiLayer outage). The
                  score/verdict are placeholders in that case.
    """

    score:    float
    verdict:  HCSVerdict
    passed:   bool
    degraded: bool = False


# ---------------------------------------------------------------------------
# Error types
# ---------------------------------------------------------------------------

CertiLayerErrorCode = Literal[
    "INVALID_API_KEY",
    "SESSION_NOT_FOUND",
    "SESSION_EXPIRED",
    "STEP_UP_REQUIRED",
    "SESSION_TERMINATED",
    "RATE_LIMITED",
    "NETWORK_ERROR",
    "TIMEOUT",
    "UNEXPECTED_ERROR",
]


class CertiLayerError(Exception):
    """
    Raised by the CertiLayer SDK on all non-success outcomes.

    Attributes:
        code:        Machine-readable error code for programmatic handling.
        cause:       Original exception that triggered this error, if any.
        status_code: HTTP status of the API response, if there was one.
    """

    def __init__(
        self,
        message: str,
        code: CertiLayerErrorCode,
        cause: Optional[BaseException] = None,
        status_code: Optional[int] = None,
    ) -> None:
        super().__init__(message)
        self.code        = code
        self.cause       = cause
        self.status_code = status_code

    def __repr__(self) -> str:
        return f"CertiLayerError(code={self.code!r}, message={str(self)!r})"
