# certilayer

**Verify human sessions server-side in 3 lines.**

The official Python SDK for CertiLayer — a fully async client for calling
CertiLayer's HCS (Human Confidence Score) API after your Web, iOS,
Android, or React Native SDK has captured a session. Gate critical
actions — login, checkout, signup, password changes — with a single
`await`.

[![PyPI version](https://img.shields.io/pypi/v/certilayer.svg)](https://pypi.org/project/certilayer/)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)

---

## Installation

```bash
pip install certilayer
```

Framework integrations are optional extras — install only what you need:

```bash
pip install certilayer[fastapi]   # FastAPI dependency helper
pip install certilayer[django]    # Django middleware
```

---

## ⚠️ Secret key — server-side only

`CertiLayerClient` takes your **secret** key
(`certilayer_live_sk_...` or `certilayer_test_sk_...`). This SDK is for
server environments only — never ship this key to a browser, mobile app,
or any client-side code. For the client side, use `@certilayer/web` (or
the iOS/Android/React Native SDK), which takes your public key instead.

---

## Quick start

```python
from certilayer import CertiLayerClient

client = CertiLayerClient(api_key="certilayer_live_sk_...")
result = await client.verify_session(session_id)

if result.verdict == "synthetic":
    raise HTTPException(status_code=403, detail="bot_detected")
```

`session_id` is the session ID produced by whichever client-side SDK
(`@certilayer/web`, iOS, Android, or React Native) is running on the
same page/app the user is on.

Use the client as an async context manager, or call `aclose()` yourself
on shutdown:

```python
async with CertiLayerClient(api_key="certilayer_live_sk_...") as client:
    result = await client.verify_session(session_id)
```

---

## Client configuration

```python
CertiLayerClient(
    api_key: str,
    base_url: str = "https://api.certilayer.net/v1",
    timeout_s: float = 10.0,
    max_retries: int = 2,
)
```

| Parameter     | Default                              | Notes                                                                 |
| -------------- | -------------------------------------- | -------------------------------------------------------------------------- |
| `api_key`      | —                                      | Required. Raises `INVALID_API_KEY` if empty.                              |
| `base_url`     | `https://api.certilayer.net/v1`        | Override only for self-hosted deployments.                                |
| `timeout_s`    | `10.0`                                  | Per-request timeout, in seconds.                                          |
| `max_retries`  | `2`                                      | Retries 5xx and network errors with exponential backoff. 4xx errors are never retried. |

---

## API reference

### `await client.verify_session(session_id, critical=False) -> VerifyResult`

Full verification — returns score, verdict, and session metadata.

```python
@dataclass(frozen=True)
class VerifyResult:
    score: float          # 0.0 – 1.0
    verdict: HCSVerdict   # 'human_verified' | 'human_likely' | 'synthetic'
    session_id: str
    scored_at: str          # UTC ISO-8601
```

Pass `critical=True` immediately before a high-stakes action (payment,
password change, account mutation). This tells the policy engine to
apply stricter critical-action rules, which can escalate a grey-zone
score to a step-up challenge or session termination instead of a softer
response.

```python
try:
    await client.verify_session(session_id, critical=True)
except CertiLayerError as e:
    if e.code == "STEP_UP_REQUIRED":
        return prompt_webauthn()
    raise
```

### `await client.quick_check(session_id, min_score=0.30, critical=False) -> QuickCheckResult`

Lighter than `verify_session()` — just a pass/fail gate decision without
full session metadata.

```python
@dataclass(frozen=True)
class QuickCheckResult:
    score: float
    verdict: HCSVerdict
    passed: bool           # True if score >= min_score
```

```python
check = await client.quick_check(session_id)
if not check.passed:
    return JSONResponse({"error": "bot_detected"}, status_code=403)
```

### HCS verdict thresholds

| Verdict          | Score range | Recommended action           |
| ----------------- | ------------ | ------------------------------ |
| `human_verified`  | ≥ 0.35        | Allow — high confidence         |
| `human_likely`    | 0.30 – 0.35   | Soft friction / step-up auth    |
| `synthetic`       | < 0.30        | Block or challenge              |

Unknown/future verdict strings from the API fall back to `synthetic` as
a safe default.

---

## Framework integrations

### FastAPI

```python
from fastapi import Depends
from certilayer import CertiLayerClient

client = CertiLayerClient(api_key=settings.CERTILAYER_KEY)
guard  = client.fastapi_dependency(min_score=0.90)

@app.post("/checkout", dependencies=[Depends(guard)])
async def checkout(): ...
```

```python
client.fastapi_dependency(
    session_header: str = "x-certilayer-session",
    min_score: float = 0.30,
)
```

Reads the session ID from the given header and raises `HTTPException(403)`
if the check fails. **Fails open** (allows the request) if the CertiLayer
API call itself errors — a transient outage never blocks real users.

### Django

```python
# settings.py
client = CertiLayerClient(api_key=settings.CERTILAYER_KEY)
MIDDLEWARE = [
    ...
    client.django_middleware(),
]
```

```python
client.django_middleware(
    session_header: str = "HTTP_X_CERTILAYER_SESSION",
    min_score: float = 0.30,
    reject_status: int = 403,
)
```

Note the header name uses Django's `META` convention — Django
automatically converts an `x-certilayer-session` HTTP header into
`HTTP_X_CERTILAYER_SESSION`. Like the FastAPI dependency, this **fails
open** on transient CertiLayer API errors.

---

## Error handling

All SDK errors raise `CertiLayerError` with a machine-readable `.code`:

```python
from certilayer import CertiLayerError

try:
    result = await client.verify_session(session_id)
except CertiLayerError as e:
    if e.code == "SESSION_NOT_FOUND":
        return JSONResponse({"error": "session_expired"}, status_code=400)
    raise
```

| Code                 | Meaning                                                             |
| --------------------- | ---------------------------------------------------------------------- |
| `INVALID_API_KEY`     | API key missing, empty, or rejected by the server                     |
| `SESSION_NOT_FOUND`   | No session exists for the given `session_id`                         |
| `SESSION_EXPIRED`     | Session exists but has exceeded its TTL                               |
| `STEP_UP_REQUIRED`    | Policy engine requires additional verification (WebAuthn/OTP)         |
| `SESSION_TERMINATED`  | Policy engine has revoked this session as confidently synthetic       |
| `RATE_LIMITED`        | Too many requests — back off and retry                                |
| `NETWORK_ERROR`       | Could not reach the CertiLayer API                                    |
| `TIMEOUT`             | Request exceeded `timeout_s`                                          |
| `UNEXPECTED_ERROR`    | Unclassified server or SDK error                                      |

---

## Requirements

- Python 3.9+
- `httpx` (installed automatically as a dependency)

---

## License

MIT

## Support

- Docs: [certilayer.net/docs](https://certilayer.net/docs)
- Issues: please contact [contact@certilayer.net](mailto:contact@certilayer.net)