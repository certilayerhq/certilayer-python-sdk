"""
client.py — L1 Python SDK
--------------------------
Core async HTTP client for the CertiLayer Python SDK.
Handles authentication, retries with exponential backoff,
timeouts, and maps L8 API responses to typed SDK objects.

Integration point: calls GET /v1/session/:session_id on L8 API (Axum).
NOTE: the wire format uses snake_case field names and PascalCase verdict
strings (session_id, hcs_score, verdict: "HumanVerified") — VerifyResult.from_dict()
translates these into the snake_case-verdict surface this SDK exposes.
"""

from __future__ import annotations

import asyncio
import logging
from typing import Any

import httpx

from .types import (
    CertiLayerError,
    CertiLayerErrorCode,
    HCSVerdict,
    QuickCheckResult,
    VerifyResult,
)

logger = logging.getLogger("certilayer")

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

# Default L8 API base URL
_DEFAULT_BASE_URL = "https://api.certilayer.net/v1"

# Default request timeout in seconds
_DEFAULT_TIMEOUT_S = 10.0

# Default maximum retries on transient (5xx / network) failures
_DEFAULT_MAX_RETRIES = 2

# Default minimum HCS score for quick_check pass/fail
_DEFAULT_MIN_SCORE = 0.30  # matches HCS_THRESHOLD_LIKELY — below this is confirmed synthetic

# Base delay for exponential backoff in seconds
_BACKOFF_BASE_S = 0.2


# ---------------------------------------------------------------------------
# CertiLayerClient
# ---------------------------------------------------------------------------

class CertiLayerClient:
    """
    Async client for server-side CertiLayer integration.

    All methods are async and must be awaited. The client manages an internal
    ``httpx.AsyncClient`` connection pool — call :meth:`aclose` when done,
    or use the client as an async context manager.

    Args:
        api_key:     Your CertiLayer API key (``cl_live_...`` or ``cl_test_...``).
        base_url:    L8 API base URL. Defaults to ``https://api.certilayer.net/v1``.
        timeout_s:   Request timeout in seconds. Defaults to 10.
        max_retries: Max retries on 5xx / network errors. Defaults to 2.

    Raises:
        :class:`CertiLayerError` (INVALID_API_KEY): If ``api_key`` is empty.

    Example — FastAPI::

        client = CertiLayerClient(api_key=settings.CERTILAYER_KEY)

        @app.post("/login")
        async def login(session_id: str = Header(alias="x-certilayer-session")):
            result = await client.verify_session(session_id)
            if result.verdict == HCSVerdict.SYNTHETIC:
                raise HTTPException(403, "bot_detected")
            ...

    Example — Django (sync wrapper)::

        import asyncio
        result = asyncio.run(client.verify_session(session_id))
    """

    def __init__(
        self,
        api_key:     str,
        base_url:    str  = _DEFAULT_BASE_URL,
        timeout_s:   float = _DEFAULT_TIMEOUT_S,
        max_retries: int   = _DEFAULT_MAX_RETRIES,
    ) -> None:
        if not api_key or not api_key.strip():
            raise CertiLayerError(
                "api_key is required. Get yours at https://app.certilayer.net",
                "INVALID_API_KEY",
            )

        self._api_key     = api_key
        self._base_url    = base_url.rstrip("/")
        self._timeout_s   = timeout_s
        self._max_retries = max_retries

        # Shared connection pool — reused across all requests
        self._http = httpx.AsyncClient(
            base_url=self._base_url,
            timeout=httpx.Timeout(self._timeout_s),
            headers={
                "Authorization": f"Bearer {self._api_key}",
                "Content-Type":  "application/json",
                "X-SDK-Version": "1.0.0",
                "X-SDK-Lang":    "python",
            },
        )

    # -------------------------------------------------------------------------
    # Public API
    # -------------------------------------------------------------------------

    async def verify_session(self, session_id: str, critical: bool = False) -> VerifyResult:
        """
        Verify a session and return the full HCS result.

        Call this on your backend when a user attempts a critical action
        (login, checkout, signup). Pass the ``session_id`` from the mobile/web SDK.

        Args:
            session_id: UUID v4 session ID from the CertiLayer mobile/web SDK.
            critical:   Pass ``True`` immediately before a high-stakes action
                        (payment, password change, account mutation). Tells the
                        policy engine to apply the stricter critical-action
                        rules, which can escalate a grey-zone score to a
                        step-up challenge or termination instead of the
                        softer non-critical response (e.g. a silent tarpit).

        Returns:
            :class:`VerifyResult` with score, verdict, and session metadata.

        Raises:
            :class:`CertiLayerError` SESSION_NOT_FOUND:   Session doesn't exist.
            :class:`CertiLayerError` SESSION_EXPIRED:     Session has timed out.
            :class:`CertiLayerError` STEP_UP_REQUIRED:    Policy engine demands
                additional verification for this session — not an invalid key.
            :class:`CertiLayerError` SESSION_TERMINATED:  Policy engine revoked
                this session as confidently synthetic.
            :class:`CertiLayerError` RATE_LIMITED:        Quota exceeded.
            :class:`CertiLayerError` NETWORK_ERROR:       Can't reach the API.
            :class:`CertiLayerError` TIMEOUT:             Request timed out.

        Example::

            result = await client.verify_session(session_id)
            if result.verdict == HCSVerdict.SYNTHETIC:
                raise HTTPException(403, "bot_detected")

            # Before a critical action:
            try:
                await client.verify_session(session_id, critical=True)
            except CertiLayerError as e:
                if e.code == "STEP_UP_REQUIRED":
                    return prompt_webauthn()
                raise
        """
        self._assert_session_id(session_id)
        path = f"/session/{session_id}"
        if critical:
            path += "?critical=true"
        data = await self._request("GET", path)
        return VerifyResult.from_dict(data)

    async def quick_check(
        self,
        session_id: str,
        min_score:  float = _DEFAULT_MIN_SCORE,
        critical:   bool  = False,
    ) -> QuickCheckResult:
        """
        Quick pass/fail check — returns only verdict + score + passed boolean.

        Lighter than :meth:`verify_session` when you only need a gate decision
        without full session metadata.

        Args:
            session_id: UUID v4 session ID from the CertiLayer mobile/web SDK.
            min_score:  Minimum HCS to pass. Defaults to 0.30 (blocks confirmed synthetic).
            critical:   Forwarded to :meth:`verify_session` — pass True before
                        a high-stakes action.

        Returns:
            :class:`QuickCheckResult` with ``passed=True`` if score >= min_score.

        Example::

            check = await client.quick_check(session_id)
            if not check.passed:
                return JSONResponse({"error": "bot_detected"}, status_code=403)
        """
        result = await self.verify_session(session_id, critical=critical)
        return QuickCheckResult(
            score   = result.score,
            verdict = result.verdict,
            passed  = result.score >= min_score,
        )

    # -------------------------------------------------------------------------
    # Framework middleware / dependency helpers
    # -------------------------------------------------------------------------

    def fastapi_dependency(
        self,
        session_header: str   = "x-certilayer-session",
        min_score:      float = _DEFAULT_MIN_SCORE,
    ):
        """
        FastAPI dependency that reads the session header and gates the request.

        Args:
            session_header: Name of the HTTP header carrying the session ID.
            min_score:      Minimum HCS to allow the request through.

        Returns:
            An async FastAPI dependency function.

        Example::

            from fastapi import Depends
            from certilayer import CertiLayerClient

            client = CertiLayerClient(api_key=settings.CERTILAYER_KEY)
            guard  = client.fastapi_dependency(min_score=0.90)

            @app.post("/checkout", dependencies=[Depends(guard)])
            async def checkout(): ...
        """
        # Import lazily — fastapi is not a required dependency
        try:
            from fastapi import Header, HTTPException  # type: ignore[import]
        except ImportError as exc:
            raise ImportError(
                "fastapi is required for fastapi_dependency(). "
                "Install it with: pip install fastapi"
            ) from exc

        client = self

        async def _dependency(
            session_id: str | None = Header(default=None, alias=session_header),
        ) -> QuickCheckResult:
            """FastAPI dependency — raises 403 if session fails HCS check."""
            if not session_id:
                raise HTTPException(
                    status_code=403,
                    detail={"error": "missing_session", "header": session_header},
                )
            try:
                check = await client.quick_check(session_id, min_score)
            except CertiLayerError as exc:
                # Fail open on transient errors to avoid blocking real users
                logger.warning("CertiLayer check failed — failing open: %s", exc)
                return QuickCheckResult(score=1.0, verdict=HCSVerdict.HUMAN_VERIFIED, passed=True)

            if not check.passed:
                raise HTTPException(
                    status_code=403,
                    detail={"error": "bot_detected", "verdict": check.verdict, "score": check.score},
                )
            return check

        return _dependency

    def django_middleware(
        self,
        session_header: str   = "HTTP_X_CERTILAYER_SESSION",
        min_score:      float = _DEFAULT_MIN_SCORE,
        reject_status:  int   = 403,
    ):
        """
        Django middleware class that gates requests via CertiLayer HCS check.

        Args:
            session_header: Django META key for the session ID header.
                            Django converts ``x-certilayer-session`` →
                            ``HTTP_X_CERTILAYER_SESSION`` automatically.
            min_score:      Minimum HCS to allow the request through.
            reject_status:  HTTP status returned on rejection. Defaults to 403.

        Returns:
            A Django middleware class (not an instance).

        Example (settings.py)::

            client = CertiLayerClient(api_key=settings.CERTILAYER_KEY)
            MIDDLEWARE = [
                ...
                client.django_middleware(),
            ]
        """
        client = self

        class _CertiLayerMiddleware:
            def __init__(self, get_response):
                self.get_response = get_response

            def __call__(self, request):
                # Import lazily
                from django.http import JsonResponse  # type: ignore[import]

                session_id = request.META.get(session_header)
                if session_id:
                    try:
                        check = asyncio.run(client.quick_check(session_id, min_score))
                        if not check.passed:
                            return JsonResponse(
                                {"error": "bot_detected", "verdict": check.verdict.value},
                                status=reject_status,
                            )
                    except CertiLayerError as exc:
                        logger.warning("CertiLayer check failed — failing open: %s", exc)

                return self.get_response(request)

        return _CertiLayerMiddleware

    # -------------------------------------------------------------------------
    # Context manager support
    # -------------------------------------------------------------------------

    async def aclose(self) -> None:
        """Close the underlying HTTP connection pool. Call on app shutdown."""
        await self._http.aclose()

    async def __aenter__(self) -> "CertiLayerClient":
        return self

    async def __aexit__(self, *_: Any) -> None:
        await self.aclose()

    # -------------------------------------------------------------------------
    # Private helpers
    # -------------------------------------------------------------------------

    async def _request(self, method: str, path: str) -> dict:
        """
        Make an authenticated HTTP request to the L8 API with retries.

        Args:
            method: HTTP method (GET, POST, …).
            path:   API path (e.g. /sessions/:id/score).

        Returns:
            Parsed JSON response body as a dict.

        Raises:
            :class:`CertiLayerError` on non-2xx responses or network errors.
        """
        last_error: CertiLayerError | None = None

        for attempt in range(self._max_retries + 1):
            # Exponential backoff before each retry (skip on first attempt)
            if attempt > 0:
                await asyncio.sleep(_BACKOFF_BASE_S * (2 ** (attempt - 1)))

            try:
                response = await self._http.request(method, path)

                if response.is_success:
                    return response.json()

                # 4xx errors are not transient — raise immediately, no retry
                if 400 <= response.status_code < 500:
                    body = response.json() if response.content else {}
                    code = _classify_4xx_error(response.status_code, body)
                    raise CertiLayerError(
                        _extract_error_message(body) or f"HTTP {response.status_code}",
                        code,
                    )

                # 5xx — record and retry
                code = _http_status_to_error_code(response.status_code)
                last_error = CertiLayerError(f"HTTP {response.status_code}", code)

            except CertiLayerError:
                raise  # re-raise 4xx immediately

            except httpx.TimeoutException as exc:
                last_error = CertiLayerError(
                    f"Request timed out after {self._timeout_s}s",
                    "TIMEOUT",
                    exc,
                )

            except httpx.RequestError as exc:
                last_error = CertiLayerError(
                    f"Network error: {exc}",
                    "NETWORK_ERROR",
                    exc,
                )

        # All retries exhausted
        raise last_error or CertiLayerError("Unknown error", "UNEXPECTED_ERROR")

    def _assert_session_id(self, session_id: object) -> None:
        """
        Validate that session_id is a non-empty string.

        :raises CertiLayerError: SESSION_NOT_FOUND if invalid.
        """
        if not isinstance(session_id, str) or not session_id.strip():
            raise CertiLayerError(
                "session_id must be a non-empty string.",
                "SESSION_NOT_FOUND",
            )


# ---------------------------------------------------------------------------
# Internal utilities
# ---------------------------------------------------------------------------

def _http_status_to_error_code(status: int) -> CertiLayerErrorCode:
    """Map an HTTP status code to a CertiLayerErrorCode (fallback only — see _classify_4xx_error)."""
    if status in (401, 403): return "INVALID_API_KEY"
    if status == 404:        return "SESSION_NOT_FOUND"
    if status == 410:        return "SESSION_EXPIRED"
    if status == 429:        return "RATE_LIMITED"
    return "UNEXPECTED_ERROR"


def _classify_4xx_error(status: int, body: dict) -> CertiLayerErrorCode:
    """
    Classify a 4xx response into a specific error code by inspecting the
    body, not just the HTTP status. A 401 from the L8 API can mean either
    "your API key is invalid" OR "the policy engine requires step-up
    verification for this session" — both currently return HTTP 401 with the
    same generic ``{"error": {"code": "unauthorized", ...}}`` shape, so
    callers need the message text to tell them apart.
    """
    import re
    message = _extract_error_message(body) or ""

    if status == 401 and re.search(r"step-?up|webauthn|challenge", message, re.I):
        return "STEP_UP_REQUIRED"
    if status == 401 and re.search(r"terminat|revoked", message, re.I):
        return "SESSION_TERMINATED"
    return _http_status_to_error_code(status)


def _extract_error_message(body: dict) -> str | None:
    """Pulls a human-readable message out of either error response shape the API uses."""
    if isinstance(body.get("message"), str):
        return body["message"]
    nested = body.get("error")
    if isinstance(nested, dict) and isinstance(nested.get("message"), str):
        return nested["message"]
    return None
