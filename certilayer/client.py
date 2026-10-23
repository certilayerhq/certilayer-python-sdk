"""
client.py — L1 Python SDK
--------------------------
Core HTTP client for the CertiLayer Python SDK (async + sync).
Handles authentication, retries with exponential backoff, timeouts, and maps
L8 API responses to typed SDK objects. Also ships FastAPI / Django guards.

Integration point: calls GET /v1/session/:session_id on the L8 API (Axum).
NOTE: the wire format uses snake_case field names and PascalCase verdict
strings (session_id, hcs_score, verdict: "HumanVerified") — VerifyResult.from_dict()
translates these into the snake_case-verdict surface this SDK exposes.
"""

from __future__ import annotations

import asyncio
import logging
import re
import threading
import time
from typing import Any, NamedTuple, Optional, Sequence
from urllib.parse import quote

import httpx

from ._version import __version__
from .types import (
    CertiLayerError,
    CertiLayerErrorCode,
    HCSVerdict,
    QuickCheckResult,
    VerifyResult,
)

logger = logging.getLogger("certilayer")

_DEFAULT_BASE_URL    = "https://api.certilayer.net/v1"
_DEFAULT_TIMEOUT_S   = 10.0
_DEFAULT_MAX_RETRIES = 2
_DEFAULT_MIN_SCORE   = 0.30  # matches HCS_THRESHOLD_LIKELY — below this is confirmed synthetic
_BACKOFF_BASE_S      = 0.2


# ---------------------------------------------------------------------------
# Errors / gate decision helpers
# ---------------------------------------------------------------------------

class _RetryableError(CertiLayerError):
    """Internal: a 5xx response that should be retried."""


_TRANSIENT_CODES = ("NETWORK_ERROR", "TIMEOUT")

# Errors that mean "this session must not pass" — never fail open on these.
_CLIENT_REJECT_ERRORS = {
    "SESSION_NOT_FOUND":  "invalid_session",
    "SESSION_EXPIRED":    "session_expired",
    "STEP_UP_REQUIRED":   "step_up_required",
    "SESSION_TERMINATED": "session_terminated",
}


def is_transient_error(exc: CertiLayerError) -> bool:
    """True only for outages: network errors, timeouts and 5xx responses."""
    if exc.code in _TRANSIENT_CODES:
        return True
    return (
        exc.code == "UNEXPECTED_ERROR"
        and exc.status_code is not None
        and exc.status_code >= 500
    )


class _GateReject(NamedTuple):
    status:  int
    error:   str
    verdict: Optional[str] = None

    def body(self) -> dict:
        out = {"error": self.error}
        if self.verdict is not None:
            out["verdict"] = self.verdict
        return out


def _degraded_result() -> QuickCheckResult:
    return QuickCheckResult(
        score=0.0, verdict=HCSVerdict.HUMAN_LIKELY, passed=True, degraded=True,
    )


def _evaluate_gate(
    check: Optional[QuickCheckResult],
    exc: Optional[CertiLayerError],
    *,
    fail_open: bool,
    reject_status: int,
) -> Optional[_GateReject]:
    """Return a rejection, or None if the request may proceed."""
    if exc is not None:
        if fail_open and is_transient_error(exc):
            logger.warning("CertiLayer unavailable — failing open (fail_open=True): %s", exc)
            return None
        if exc.code in _CLIENT_REJECT_ERRORS:
            return _GateReject(reject_status, _CLIENT_REJECT_ERRORS[exc.code])
        if exc.code == "INVALID_API_KEY":
            logger.error("CertiLayer rejected the API key — check your configuration: %s", exc)
            return _GateReject(500, "certilayer_misconfigured")
        logger.warning("CertiLayer check failed — failing closed: %s", exc)
        return _GateReject(503, "verification_unavailable")

    if check is not None and not check.passed:
        return _GateReject(reject_status, "bot_detected", check.verdict.value)
    return None


# ---------------------------------------------------------------------------
# CertiLayerClient
# ---------------------------------------------------------------------------

class CertiLayerClient:
    """
    Client for server-side CertiLayer integration.

    Async methods (``verify_session``, ``quick_check``) use an internal
    ``httpx.AsyncClient``; sync twins (``verify_session_sync``,
    ``quick_check_sync``) use a separate ``httpx.Client`` so WSGI apps never
    share an async connection pool across event loops. Call :meth:`aclose`
    on shutdown, or use ``async with``.

    Args:
        api_key:     Your CertiLayer secret key (``certilayer_live_sk_...``).
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

    Example — sync code (Django/WSGI, scripts)::

        result = client.verify_session_sync(session_id)
    """

    def __init__(
        self,
        api_key:     str,
        base_url:    str   = _DEFAULT_BASE_URL,
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
        self._headers = {
            "Authorization": f"Bearer {self._api_key}",
            "Content-Type":  "application/json",
            "X-SDK-Version": __version__,
            "X-SDK-Lang":    "python",
        }

        self._http = httpx.AsyncClient(
            base_url=self._base_url,
            timeout=httpx.Timeout(self._timeout_s),
            headers=self._headers,
        )
        self._sync_http: Optional[httpx.Client] = None
        self._sync_lock = threading.Lock()

    # -------------------------------------------------------------------------
    # Public API — async
    # -------------------------------------------------------------------------

    async def verify_session(self, session_id: str, critical: bool = False) -> VerifyResult:
        """
        Verify a session and return the full HCS result.

        Args:
            session_id: Session ID from the CertiLayer web/mobile SDK.
            critical:   Pass ``True`` immediately before a high-stakes action
                        (payment, password change, account mutation) so the
                        policy engine applies stricter critical-action rules.

        Raises:
            :class:`CertiLayerError` with one of: SESSION_NOT_FOUND,
            SESSION_EXPIRED, STEP_UP_REQUIRED, SESSION_TERMINATED,
            RATE_LIMITED, INVALID_API_KEY, NETWORK_ERROR, TIMEOUT.

        Example::

            try:
                await client.verify_session(session_id, critical=True)
            except CertiLayerError as e:
                if e.code == "STEP_UP_REQUIRED":
                    return prompt_webauthn()
                raise
        """
        path = self._session_path(session_id, critical)
        data = await self._request("GET", path)
        return VerifyResult.from_dict(data)

    async def quick_check(
        self,
        session_id: str,
        min_score:  float = _DEFAULT_MIN_SCORE,
        critical:   bool  = False,
    ) -> QuickCheckResult:
        """
        Quick pass/fail check.

        ``passed`` is True only if ``score >= min_score`` AND the verdict is
        not SYNTHETIC (an unknown verdict from the API counts as SYNTHETIC).
        """
        result = await self.verify_session(session_id, critical=critical)
        return self._to_quick_check(result, min_score)

    # -------------------------------------------------------------------------
    # Public API — sync
    # -------------------------------------------------------------------------

    def verify_session_sync(self, session_id: str, critical: bool = False) -> VerifyResult:
        """Blocking twin of :meth:`verify_session` (own connection pool)."""
        path = self._session_path(session_id, critical)
        data = self._request_sync("GET", path)
        return VerifyResult.from_dict(data)

    def quick_check_sync(
        self,
        session_id: str,
        min_score:  float = _DEFAULT_MIN_SCORE,
        critical:   bool  = False,
    ) -> QuickCheckResult:
        """Blocking twin of :meth:`quick_check`."""
        result = self.verify_session_sync(session_id, critical=critical)
        return self._to_quick_check(result, min_score)

    # -------------------------------------------------------------------------
    # Framework helpers
    # -------------------------------------------------------------------------

    def fastapi_dependency(
        self,
        session_header:  str   = "x-certilayer-session",
        min_score:       float = _DEFAULT_MIN_SCORE,
        fail_open:       bool  = False,
        require_session: bool  = True,
    ):
        """
        FastAPI dependency that reads the session header and gates the request.

        Args:
            session_header:  Header carrying the session ID.
            min_score:       Minimum HCS to allow the request through.
            fail_open:       If True, let requests through ONLY when CertiLayer
                             is unreachable (network error, timeout, 5xx).
                             Invalid key, unknown/expired/terminated session,
                             step-up and rate-limit errors ALWAYS reject.
                             The returned result has ``degraded=True`` then.
            require_session: If True (default) a missing header returns 403.
                             If False a missing header returns ``None``.

        Example::

            guard = client.fastapi_dependency(min_score=0.35)

            @app.post("/checkout", dependencies=[Depends(guard)])
            async def checkout(): ...
        """
        try:
            from fastapi import Header, HTTPException  # type: ignore[import]
        except ImportError as exc:
            raise ImportError(
                "fastapi is required for fastapi_dependency(). "
                "Install it with: pip install certilayer[fastapi]"
            ) from exc

        client = self

        async def _dependency(
            session_id: Optional[str] = Header(default=None, alias=session_header),
        ) -> Optional[QuickCheckResult]:
            if not session_id:
                if not require_session:
                    return None
                raise HTTPException(
                    status_code=403,
                    detail={"error": "missing_session", "header": session_header},
                )

            check: Optional[QuickCheckResult] = None
            failure: Optional[CertiLayerError] = None
            try:
                check = await client.quick_check(session_id, min_score)
            except CertiLayerError as exc:
                failure = exc

            rejection = _evaluate_gate(
                check, failure, fail_open=fail_open, reject_status=403,
            )
            if rejection is not None:
                raise HTTPException(status_code=rejection.status, detail=rejection.body())
            return check if check is not None else _degraded_result()

        return _dependency

    def django_middleware(
        self,
        session_header:  str   = "HTTP_X_CERTILAYER_SESSION",
        min_score:       float = _DEFAULT_MIN_SCORE,
        reject_status:   int   = 403,
        fail_open:       bool  = False,
        require_session: bool  = True,
        paths:           Optional[Sequence[str]] = None,
    ):
        """
        Django middleware class (sync AND async capable) that gates requests.

        Args:
            session_header:  Django META key (``x-certilayer-session`` becomes
                             ``HTTP_X_CERTILAYER_SESSION``).
            min_score:       Minimum HCS to allow the request through.
            reject_status:   Status returned when a request is rejected.
            fail_open:       Let requests through ONLY on CertiLayer outages
                             (network error, timeout, 5xx). See
                             :meth:`fastapi_dependency`.
            require_session: Reject requests with no session header (default).
            paths:           Only gate requests whose path starts with one of
                             these prefixes, e.g. ``("/api/checkout/",)``.
                             ``None`` gates every request — set this, because
                             plain page loads carry no session header.

        Example (settings.py)::

            client = CertiLayerClient(api_key=settings.CERTILAYER_KEY)
            MIDDLEWARE = [
                ...
                client.django_middleware(paths=("/api/",)),
            ]
        """
        try:
            from asgiref.sync import iscoroutinefunction, markcoroutinefunction  # type: ignore[import]
            from django.http import JsonResponse  # type: ignore[import]
        except ImportError as exc:
            raise ImportError(
                "django is required for django_middleware(). "
                "Install it with: pip install certilayer[django]"
            ) from exc

        client = self
        prefixes = tuple(paths) if paths else None

        def _in_scope(request) -> bool:
            if prefixes is None:
                return True
            return getattr(request, "path", "").startswith(prefixes)

        def _decide(session_id, check, failure) -> Optional[_GateReject]:
            if not session_id:
                return _GateReject(reject_status, "missing_session") if require_session else None
            return _evaluate_gate(
                check, failure, fail_open=fail_open, reject_status=reject_status,
            )

        def _json(rejection: _GateReject):
            return JsonResponse(rejection.body(), status=rejection.status)

        class _CertiLayerMiddleware:
            sync_capable  = True
            async_capable = True

            def __init__(self, get_response):
                self.get_response = get_response
                if iscoroutinefunction(get_response):
                    markcoroutinefunction(self)

            def __call__(self, request):
                if iscoroutinefunction(self):
                    return self.__acall__(request)

                if not _in_scope(request):
                    return self.get_response(request)

                session_id = request.META.get(session_header)
                check = failure = None
                if session_id:
                    try:
                        check = client.quick_check_sync(session_id, min_score)
                    except CertiLayerError as exc:
                        failure = exc

                rejection = _decide(session_id, check, failure)
                if rejection is not None:
                    return _json(rejection)
                return self.get_response(request)

            async def __acall__(self, request):
                if not _in_scope(request):
                    return await self.get_response(request)

                session_id = request.META.get(session_header)
                check = failure = None
                if session_id:
                    try:
                        check = await client.quick_check(session_id, min_score)
                    except CertiLayerError as exc:
                        failure = exc

                rejection = _decide(session_id, check, failure)
                if rejection is not None:
                    return _json(rejection)
                return await self.get_response(request)

        return _CertiLayerMiddleware

    # -------------------------------------------------------------------------
    # Lifecycle
    # -------------------------------------------------------------------------

    def close(self) -> None:
        """Close the sync connection pool (if it was ever used)."""
        with self._sync_lock:
            if self._sync_http is not None:
                self._sync_http.close()
                self._sync_http = None

    async def aclose(self) -> None:
        """Close the async (and sync) connection pools. Call on app shutdown."""
        await self._http.aclose()
        self.close()

    async def __aenter__(self) -> "CertiLayerClient":
        return self

    async def __aexit__(self, *_: Any) -> None:
        await self.aclose()

    # -------------------------------------------------------------------------
    # Private helpers
    # -------------------------------------------------------------------------

    def _get_sync_http(self) -> httpx.Client:
        with self._sync_lock:
            if self._sync_http is None:
                self._sync_http = httpx.Client(
                    base_url=self._base_url,
                    timeout=httpx.Timeout(self._timeout_s),
                    headers=self._headers,
                )
            return self._sync_http

    def _session_path(self, session_id: object, critical: bool) -> str:
        self._assert_session_id(session_id)
        # The session ID often comes straight from a client-controlled header:
        # percent-encode it so it can never alter the request path or query
        # (the request carries our secret key).
        path = f"/session/{quote(str(session_id), safe='')}"
        if critical:
            path += "?critical=true"
        return path

    @staticmethod
    def _to_quick_check(result: VerifyResult, min_score: float) -> QuickCheckResult:
        return QuickCheckResult(
            score   = result.score,
            verdict = result.verdict,
            passed  = result.score >= min_score and result.verdict != HCSVerdict.SYNTHETIC,
        )

    async def _request(self, method: str, path: str) -> dict:
        """Authenticated async request with retries on 5xx / network errors."""
        last_error: Optional[CertiLayerError] = None

        for attempt in range(self._max_retries + 1):
            if attempt > 0:
                await asyncio.sleep(_BACKOFF_BASE_S * (2 ** (attempt - 1)))
            try:
                response = await self._http.request(method, path)
                return _parse_response(response)
            except _RetryableError as exc:
                last_error = exc
            except CertiLayerError:
                raise
            except httpx.TimeoutException as exc:
                last_error = CertiLayerError(
                    f"Request timed out after {self._timeout_s}s", "TIMEOUT", exc,
                )
            except httpx.RequestError as exc:
                last_error = CertiLayerError(f"Network error: {exc}", "NETWORK_ERROR", exc)

        raise last_error or CertiLayerError("Unknown error", "UNEXPECTED_ERROR")

    def _request_sync(self, method: str, path: str) -> dict:
        """Authenticated blocking request with retries on 5xx / network errors."""
        http = self._get_sync_http()
        last_error: Optional[CertiLayerError] = None

        for attempt in range(self._max_retries + 1):
            if attempt > 0:
                time.sleep(_BACKOFF_BASE_S * (2 ** (attempt - 1)))
            try:
                response = http.request(method, path)
                return _parse_response(response)
            except _RetryableError as exc:
                last_error = exc
            except CertiLayerError:
                raise
            except httpx.TimeoutException as exc:
                last_error = CertiLayerError(
                    f"Request timed out after {self._timeout_s}s", "TIMEOUT", exc,
                )
            except httpx.RequestError as exc:
                last_error = CertiLayerError(f"Network error: {exc}", "NETWORK_ERROR", exc)

        raise last_error or CertiLayerError("Unknown error", "UNEXPECTED_ERROR")

    def _assert_session_id(self, session_id: object) -> None:
        if not isinstance(session_id, str) or not session_id.strip():
            raise CertiLayerError(
                "session_id must be a non-empty string.",
                "SESSION_NOT_FOUND",
            )


# ---------------------------------------------------------------------------
# Internal utilities
# ---------------------------------------------------------------------------

def _safe_json(response: httpx.Response) -> dict:
    try:
        data = response.json() if response.content else {}
    except ValueError:
        return {}
    return data if isinstance(data, dict) else {}


def _parse_response(response: httpx.Response) -> dict:
    """Return the JSON body on success, or raise the right CertiLayerError."""
    status = response.status_code

    if response.is_success:
        try:
            data = response.json()
        except ValueError as exc:
            raise CertiLayerError(
                "Invalid JSON in API response", "UNEXPECTED_ERROR", exc, status_code=status,
            ) from exc
        return data

    if 400 <= status < 500:
        body = _safe_json(response)
        raise CertiLayerError(
            _extract_error_message(body) or f"HTTP {status}",
            _classify_4xx_error(status, body),
            status_code=status,
        )

    if status >= 500:
        raise _RetryableError(
            f"HTTP {status}", _http_status_to_error_code(status), status_code=status,
        )

    # 1xx / 3xx — not retryable
    raise CertiLayerError(f"HTTP {status}", "UNEXPECTED_ERROR", status_code=status)


def _http_status_to_error_code(status: int) -> CertiLayerErrorCode:
    """Map an HTTP status code to a CertiLayerErrorCode (fallback only — see _classify_4xx_error)."""
    if status in (401, 403): return "INVALID_API_KEY"
    if status == 404:        return "SESSION_NOT_FOUND"
    if status == 410:        return "SESSION_EXPIRED"
    if status == 429:        return "RATE_LIMITED"
    return "UNEXPECTED_ERROR"


def _classify_4xx_error(status: int, body: dict) -> CertiLayerErrorCode:
    """
    Classify a 4xx response by inspecting the body, not just the status.
    A 401 from the L8 API can mean either "invalid API key" OR "the policy
    engine requires step-up verification / terminated this session" — all
    currently return HTTP 401 with a generic shape, so the message text is
    used to tell them apart.
    """
    message = _extract_error_message(body) or ""

    if status == 401 and re.search(r"step-?up|webauthn|challenge", message, re.I):
        return "STEP_UP_REQUIRED"
    if status == 401 and re.search(r"terminat|revoked", message, re.I):
        return "SESSION_TERMINATED"
    return _http_status_to_error_code(status)


def _extract_error_message(body: dict) -> Optional[str]:
    """Pulls a human-readable message out of either error response shape the API uses."""
    if isinstance(body.get("message"), str):
        return body["message"]
    nested = body.get("error")
    if isinstance(nested, dict) and isinstance(nested.get("message"), str):
        return nested["message"]
    return None
