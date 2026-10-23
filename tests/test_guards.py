"""
test_guards.py — security behaviour of quick_check + FastAPI/Django guards.
"""

import json

import httpx
import pytest
import respx

from certilayer import CertiLayerClient
from certilayer.types import HCSVerdict

BASE_URL = "https://api.certilayer.net/v1"
SID = "550e8400-e29b-41d4-a716-446655440000"
HEADER = "HTTP_X_CERTILAYER_SESSION"

WIRE = {
    "session_id": SID,
    "hcs_score":  0.72,
    "verdict":    "HumanVerified",
    "scored_at":  "2026-06-06T02:24:00Z",
}

# (api status, api body, expected guard status, expected guard error)
ERROR_CASES = [
    (401, {"message": "invalid api key"},             500, "certilayer_misconfigured"),
    (404, {"message": "nope"},                         403, "invalid_session"),
    (410, {"message": "gone"},                         403, "session_expired"),
    (401, {"message": "step-up verification required"}, 403, "step_up_required"),
    (401, {"message": "session terminated"},           403, "session_terminated"),
    (429, {"message": "slow down"},                    503, "verification_unavailable"),
]


def make_client(**kw):
    kw.setdefault("max_retries", 0)
    return CertiLayerClient(api_key="certilayer_live_sk_test", base_url=BASE_URL, **kw)


def _mock_failure(kind):
    route = respx.get(f"{BASE_URL}/session/id")
    if kind == "network":
        return route.mock(side_effect=httpx.ConnectError("down"))
    if kind == "timeout":
        return route.mock(side_effect=httpx.TimeoutException("timed out"))
    return route.mock(return_value=httpx.Response(503))


# ---------------------------------------------------------------------------
# quick_check / request building
# ---------------------------------------------------------------------------

class TestQuickCheckVerdict:
    @respx.mock
    @pytest.mark.asyncio
    @pytest.mark.parametrize("wire_verdict", ["Synthetic", "SomethingNew"])
    async def test_synthetic_never_passes_even_with_high_score(self, wire_verdict):
        c = make_client()
        respx.get(f"{BASE_URL}/session/id").mock(
            return_value=httpx.Response(
                200, json={**WIRE, "hcs_score": 0.95, "verdict": wire_verdict}
            )
        )
        result = await c.quick_check("id", min_score=0.30)
        assert result.verdict == HCSVerdict.SYNTHETIC
        assert result.passed is False
        await c.aclose()

    @respx.mock
    @pytest.mark.asyncio
    async def test_session_id_is_url_encoded(self):
        c = make_client()
        route = respx.route(method="GET", url__startswith=f"{BASE_URL}/session/").mock(
            return_value=httpx.Response(200, json=WIRE)
        )
        await c.verify_session("../admin?x=1")
        raw = route.calls.last.request.url.raw_path
        assert b"%2F" in raw and b"%3F" in raw
        assert b"?" not in raw
        await c.aclose()


# ---------------------------------------------------------------------------
# FastAPI
# ---------------------------------------------------------------------------

class TestFastAPIGuard:
    @respx.mock
    @pytest.mark.asyncio
    @pytest.mark.parametrize("fail_open", [False, True])
    @pytest.mark.parametrize("status,body,http_status,error", ERROR_CASES)
    async def test_policy_and_auth_errors_never_fail_open(
        self, fail_open, status, body, http_status, error
    ):
        pytest.importorskip("fastapi")
        from fastapi import HTTPException

        c = make_client()
        respx.get(f"{BASE_URL}/session/id").mock(
            return_value=httpx.Response(status, json=body)
        )
        guard = c.fastapi_dependency(fail_open=fail_open)
        with pytest.raises(HTTPException) as exc:
            await guard(session_id="id")
        assert exc.value.status_code == http_status
        assert exc.value.detail["error"] == error
        await c.aclose()

    @respx.mock
    @pytest.mark.asyncio
    @pytest.mark.parametrize("failure", ["network", "timeout", "5xx"])
    async def test_outage_fails_closed_by_default(self, failure):
        pytest.importorskip("fastapi")
        from fastapi import HTTPException

        c = make_client()
        _mock_failure(failure)
        guard = c.fastapi_dependency()
        with pytest.raises(HTTPException) as exc:
            await guard(session_id="id")
        assert exc.value.status_code == 503
        assert exc.value.detail["error"] == "verification_unavailable"
        await c.aclose()

    @respx.mock
    @pytest.mark.asyncio
    @pytest.mark.parametrize("failure", ["network", "timeout", "5xx"])
    async def test_outage_passes_only_with_explicit_fail_open(self, failure):
        pytest.importorskip("fastapi")
        c = make_client()
        _mock_failure(failure)
        guard = c.fastapi_dependency(fail_open=True)
        result = await guard(session_id="id")
        assert result.passed is True
        assert result.degraded is True
        await c.aclose()

    @pytest.mark.asyncio
    async def test_missing_session_allowed_only_when_not_required(self):
        pytest.importorskip("fastapi")
        c = make_client()
        guard = c.fastapi_dependency(require_session=False)
        assert await guard(session_id=None) is None
        await c.aclose()


# ---------------------------------------------------------------------------
# Django
# ---------------------------------------------------------------------------

class Req:
    def __init__(self, session=None, path="/"):
        self.META = {HEADER: session} if session else {}
        self.path = path


def _django():
    pytest.importorskip("django")
    from django.conf import settings
    if not settings.configured:
        settings.configure()


def _build(client, **kw):
    _django()
    calls = []

    def get_response(request):
        calls.append(request)
        return "OK"

    return client.django_middleware(**kw)(get_response), calls


def _body(resp):
    return json.loads(resp.content)


class TestDjangoMiddleware:
    def test_missing_header_is_rejected_by_default(self):
        c = make_client()
        mw, calls = _build(c)
        resp = mw(Req())
        assert resp.status_code == 403
        assert _body(resp)["error"] == "missing_session"
        assert calls == []
        c.close()

    def test_missing_header_allowed_when_not_required(self):
        c = make_client()
        mw, calls = _build(c, require_session=False)
        assert mw(Req()) == "OK"
        assert len(calls) == 1
        c.close()

    def test_paths_scope_the_gate(self):
        c = make_client()
        mw, _ = _build(c, paths=("/api/",))
        assert mw(Req(path="/health")) == "OK"
        assert mw(Req(path="/api/pay")).status_code == 403
        c.close()

    @respx.mock
    def test_synthetic_is_rejected(self):
        c = make_client()
        respx.get(f"{BASE_URL}/session/id").mock(
            return_value=httpx.Response(
                200, json={**WIRE, "hcs_score": 0.05, "verdict": "Synthetic"}
            )
        )
        mw, calls = _build(c)
        resp = mw(Req("id"))
        assert resp.status_code == 403
        assert _body(resp)["error"] == "bot_detected"
        assert "score" not in _body(resp)
        assert calls == []
        c.close()

    @respx.mock
    def test_human_passes(self):
        c = make_client()
        respx.get(f"{BASE_URL}/session/id").mock(
            return_value=httpx.Response(200, json=WIRE)
        )
        mw, calls = _build(c)
        assert mw(Req("id")) == "OK"
        assert len(calls) == 1
        c.close()

    @respx.mock
    @pytest.mark.parametrize("fail_open", [False, True])
    @pytest.mark.parametrize("status,body,http_status,error", ERROR_CASES)
    def test_policy_and_auth_errors_never_fail_open(
        self, fail_open, status, body, http_status, error
    ):
        c = make_client()
        respx.get(f"{BASE_URL}/session/id").mock(
            return_value=httpx.Response(status, json=body)
        )
        mw, calls = _build(c, fail_open=fail_open)
        resp = mw(Req("id"))
        assert resp.status_code == http_status
        assert _body(resp)["error"] == error
        assert calls == []
        c.close()

    @respx.mock
    @pytest.mark.parametrize("failure", ["network", "timeout", "5xx"])
    def test_outage_fails_closed_by_default(self, failure):
        c = make_client()
        _mock_failure(failure)
        mw, calls = _build(c)
        resp = mw(Req("id"))
        assert resp.status_code == 503
        assert calls == []
        c.close()

    @respx.mock
    @pytest.mark.parametrize("failure", ["network", "timeout", "5xx"])
    def test_outage_passes_only_with_explicit_fail_open(self, failure):
        c = make_client()
        _mock_failure(failure)
        mw, calls = _build(c, fail_open=True)
        assert mw(Req("id")) == "OK"
        assert len(calls) == 1
        c.close()

    @respx.mock
    @pytest.mark.asyncio
    async def test_async_path(self):
        _django()
        c = make_client()
        respx.get(f"{BASE_URL}/session/id").mock(
            return_value=httpx.Response(200, json=WIRE)
        )

        async def get_response(request):
            return "OK"

        mw = c.django_middleware()(get_response)
        assert await mw(Req("id")) == "OK"
        assert (await mw(Req())).status_code == 403  # missing header
        await c.aclose()
