"""
test_client.py — L1 Python SDK tests
-------------------------------------
Tests against the REAL wire contract: GET /session/:id, snake_case fields,
PascalCase verdict strings translated into this SDK's snake_case-verdict
surface. (Previous test file described the old, incorrect
/sessions/:id/score contract — replaced entirely.)
"""

import pytest
import httpx
import respx

from certilayer import CertiLayerClient, CertiLayerError
from certilayer.types import HCSVerdict, VerifyResult

BASE_URL = "https://api.certilayer.net/v1"

RAW_WIRE_RESPONSE = {
    "session_id": "550e8400-e29b-41d4-a716-446655440000",
    "hcs_score":  0.72,
    "verdict":    "HumanVerified",
    "scored_at":  "2026-06-06T02:24:00Z",
}


@pytest.fixture
async def client():
    c = CertiLayerClient(api_key="certilayer_live_sk_test", base_url=BASE_URL)
    yield c
    await c.aclose()


class TestConstruction:
    def test_empty_api_key_raises(self):
        with pytest.raises(CertiLayerError) as exc:
            CertiLayerClient(api_key="")
        assert exc.value.code == "INVALID_API_KEY"


class TestVerifySession:
    @respx.mock
    @pytest.mark.asyncio
    async def test_calls_correct_endpoint(self, client):
        route = respx.get(f"{BASE_URL}/session/550e8400-e29b-41d4-a716-446655440000").mock(
            return_value=httpx.Response(200, json=RAW_WIRE_RESPONSE)
        )
        await client.verify_session("550e8400-e29b-41d4-a716-446655440000")
        assert route.called

    @respx.mock
    @pytest.mark.asyncio
    async def test_maps_wire_response_to_verify_result(self, client):
        respx.get(f"{BASE_URL}/session/id").mock(
            return_value=httpx.Response(200, json=RAW_WIRE_RESPONSE)
        )
        result = await client.verify_session("id")

        assert isinstance(result, VerifyResult)
        assert result.score == 0.72
        assert result.verdict == HCSVerdict.HUMAN_VERIFIED
        assert result.session_id == "550e8400-e29b-41d4-a716-446655440000"
        assert result.scored_at == "2026-06-06T02:24:00Z"

    @respx.mock
    @pytest.mark.asyncio
    @pytest.mark.parametrize("wire,expected", [
        ("HumanVerified", HCSVerdict.HUMAN_VERIFIED),
        ("HumanLikely",   HCSVerdict.HUMAN_LIKELY),
        ("Synthetic",     HCSVerdict.SYNTHETIC),
    ])
    async def test_verdict_mapping(self, client, wire, expected):
        respx.get(f"{BASE_URL}/session/id").mock(
            return_value=httpx.Response(200, json={**RAW_WIRE_RESPONSE, "verdict": wire})
        )
        result = await client.verify_session("id")
        assert result.verdict == expected

    @respx.mock
    @pytest.mark.asyncio
    async def test_unknown_verdict_falls_back_to_synthetic(self, client):
        respx.get(f"{BASE_URL}/session/id").mock(
            return_value=httpx.Response(200, json={**RAW_WIRE_RESPONSE, "verdict": "SomethingNew"})
        )
        result = await client.verify_session("id")
        assert result.verdict == HCSVerdict.SYNTHETIC

    @pytest.mark.asyncio
    async def test_empty_session_id_rejected_without_request(self, client):
        with pytest.raises(CertiLayerError) as exc:
            await client.verify_session("")
        assert exc.value.code == "SESSION_NOT_FOUND"


class TestQuickCheck:
    @respx.mock
    @pytest.mark.asyncio
    async def test_passed_true_above_threshold(self, client):
        respx.get(f"{BASE_URL}/session/id").mock(
            return_value=httpx.Response(200, json={**RAW_WIRE_RESPONSE, "hcs_score": 0.5})
        )
        result = await client.quick_check("id", min_score=0.30)
        assert result.passed is True

    @respx.mock
    @pytest.mark.asyncio
    async def test_passed_false_below_threshold(self, client):
        respx.get(f"{BASE_URL}/session/id").mock(
            return_value=httpx.Response(200, json={**RAW_WIRE_RESPONSE, "hcs_score": 0.10, "verdict": "Synthetic"})
        )
        result = await client.quick_check("id", min_score=0.30)
        assert result.passed is False
        assert result.verdict == HCSVerdict.SYNTHETIC


class TestErrorMapping:
    @respx.mock
    @pytest.mark.asyncio
    @pytest.mark.parametrize("status,expected_code", [
        (401, "INVALID_API_KEY"),
        (403, "INVALID_API_KEY"),
        (404, "SESSION_NOT_FOUND"),
        (410, "SESSION_EXPIRED"),
        (429, "RATE_LIMITED"),
    ])
    async def test_4xx_maps_to_error_code_no_retry(self, client, status, expected_code):
        route = respx.get(f"{BASE_URL}/session/id").mock(
            return_value=httpx.Response(status, json={"message": "error"})
        )
        with pytest.raises(CertiLayerError) as exc:
            await client.verify_session("id")
        assert exc.value.code == expected_code
        assert route.call_count == 1  # 4xx never retries

    @respx.mock
    @pytest.mark.asyncio
    async def test_5xx_retries_then_raises(self):
        c = CertiLayerClient(api_key="certilayer_live_sk_test", base_url=BASE_URL, max_retries=2)
        route = respx.get(f"{BASE_URL}/session/id").mock(
            return_value=httpx.Response(500)
        )
        with pytest.raises(CertiLayerError) as exc:
            await c.verify_session("id")
        assert exc.value.code == "UNEXPECTED_ERROR"
        assert route.call_count == 3  # 1 initial + 2 retries
        await c.aclose()


class TestFastAPIDependency:
    @respx.mock
    @pytest.mark.asyncio
    async def test_guard_raises_403_for_synthetic(self, client):
        pytest.importorskip("fastapi")
        respx.get(f"{BASE_URL}/session/bot-session").mock(
            return_value=httpx.Response(200, json={**RAW_WIRE_RESPONSE, "hcs_score": 0.05, "verdict": "Synthetic"})
        )
        guard = client.fastapi_dependency(min_score=0.30)

        from fastapi import HTTPException
        with pytest.raises(HTTPException) as exc:
            await guard(session_id="bot-session")
        assert exc.value.status_code == 403


class TestFastAPIDependencyMore:
    @respx.mock
    @pytest.mark.asyncio
    async def test_guard_passes_for_human(self, client):
        pytest.importorskip("fastapi")
        respx.get(f"{BASE_URL}/session/good-session").mock(
            return_value=httpx.Response(200, json={**RAW_WIRE_RESPONSE, "hcs_score": 0.9})
        )
        guard = client.fastapi_dependency(min_score=0.30)
        result = await guard(session_id="good-session")
        assert result.passed is True

    @pytest.mark.asyncio
    async def test_guard_raises_403_missing_session(self, client):
        pytest.importorskip("fastapi")
        guard = client.fastapi_dependency(min_score=0.30)
        from fastapi import HTTPException
        with pytest.raises(HTTPException) as exc:
            await guard(session_id=None)
        assert exc.value.status_code == 403
        assert exc.value.detail["error"] == "missing_session"



class TestDjangoMiddleware:
    def test_creates_middleware_class(self, client):
        # Only tests that the factory returns a usable class without
        # requiring django installed for the full __call__ path — that
        # path is optional-dependency code (see pyproject.toml note on
        # coverage threshold) and isn't exercised in this suite.
        pytest.importorskip("django")
        middleware_cls = client.django_middleware()
        assert callable(middleware_cls)



class TestContextManagerAndClose:
    @pytest.mark.asyncio
    async def test_aclose_does_not_raise(self):
        c = CertiLayerClient(api_key="certilayer_live_sk_test", base_url=BASE_URL)
        await c.aclose()

    @pytest.mark.asyncio
    async def test_async_context_manager(self):
        async with CertiLayerClient(api_key="certilayer_live_sk_test", base_url=BASE_URL) as c:
            assert c is not None


class TestTimeout:
    @respx.mock
    @pytest.mark.asyncio
    async def test_timeout_retries_then_raises_timeout_code(self):
        c = CertiLayerClient(
            api_key="certilayer_live_sk_test", base_url=BASE_URL,
            max_retries=1, timeout_s=0.01,
        )
        respx.get(f"{BASE_URL}/session/id").mock(side_effect=httpx.TimeoutException("timed out"))

        with pytest.raises(CertiLayerError) as exc:
            await c.verify_session("id")
        assert exc.value.code == "TIMEOUT"
        await c.aclose()


class TestKeyPrefixHelpers:
    def test_is_secret_key(self):
        from certilayer.types import is_secret_key, is_public_key
        assert is_secret_key("certilayer_live_sk_abc") is True
        assert is_secret_key("certilayer_live_pk_abc") is False
        assert is_public_key("certilayer_test_pk_abc") is True
        assert is_public_key("certilayer_live_sk_abc") is False


class TestErrorRepr:
    def test_repr_includes_code_and_message(self):
        err = CertiLayerError("boom", "TIMEOUT")
        r = repr(err)
        assert "TIMEOUT" in r
        assert "boom" in r
