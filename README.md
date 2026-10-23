# certilayer

**Verify human sessions server-side in 3 lines.**

The official Python SDK for CertiLayer — an async-first client (with sync
twins) for calling CertiLayer's HCS (Human Confidence Score) API after your
Web, iOS, Android, or React Native SDK has captured a session. Gate critical
actions — login, checkout, signup, password changes — with a single `await`.

[![PyPI version](https://img.shields.io/pypi/v/certilayer.svg)](https://pypi.org/project/certilayer/)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)

---

## Installation

```bash
pip install certilayer
```

Framework integrations are optional extras — install only what you need:

```bash
pip install "certilayer[fastapi]"   # FastAPI dependency helper
pip install "certilayer[django]"    # Django middleware (sync + async)
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
from certilayer import CertiLayerClient, HCSVerdict

client = CertiLayerClient(api_key="certilayer_live_sk_...")

async def login(session_id: str):
    result = await client.verify_session(session_id)
    if result.verdict == HCSVerdict.SYNTHETIC:
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

Not async? Every call has a blocking twin that uses its own connection pool:

```python
result = client.verify_session_sync(session_id)
check  = client.quick_check_sync(session_id)
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

| Parameter     | Default                         | Notes                                                                                   |
| ------------- | ------------------------------- | --------------------------------------------------------------------------------------- |
| `api_key`     | —                               | Required. Raises `INVALID_API_KEY` if empty.                                            |
| `base_url`    | `https://api.certilayer.net/v1` | Override only for self-hosted deployments.                                              |
| `timeout_s`   | `10.0`                          | Per-request timeout, in seconds.                                                        |
| `max_retries` | `2`                             | Retries 5xx and network errors with exponential backoff. 4xx errors are never retried. |

---

## API reference

### `await client.verify_session(session_id, critical=False) -> VerifyResult`

Full verification — returns score, verdict, and session metadata.
Sync twin: `client.verify_session_sync(...)`.

```python
@dataclass(frozen=True)
class VerifyResult:
    score: float          # 0.0 – 1.0
    verdict: HCSVerdict   # 'human_verified' | 'human_likely' | 'synthetic'
    session_id: str
    scored_at: str        # UTC ISO-8601
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

Lighter than `verify_session()` — just a pass/fail gate decision.
Sync twin: `client.quick_check_sync(...)`.

```python
@dataclass(frozen=True)
class QuickCheckResult:
    score: float
    verdict: HCSVerdict
    passed: bool           # True only if score >= min_score AND verdict != synthetic
    degraded: bool = False # True if a guard let the request through during an outage
```

```python
check = await client.quick_check(session_id)
if not check.passed:
    return JSONResponse({"error": "bot_detected"}, status_code=403)
```

An unknown verdict from the API is treated as `synthetic`, so it never passes —
even if its score is above `min_score`.

### HCS verdict thresholds

| Verdict          | Score range | Recommended action           |
| ---------------- | ----------- | ---------------------------- |
| `human_verified` | ≥ 0.35      | Allow — high confidence      |
| `human_likely`   | 0.30 – 0.35 | Soft friction / step-up auth |
| `synthetic`      | < 0.30      | Block or challenge           |

`min_score` defaults to `0.30`, which blocks confirmed-synthetic sessions
and lets `human_likely` through. Use `min_score=0.35` to require
`human_verified` only. Values far above 0.35 (e.g. `0.90`) will block most
real users.

---

## Framework integrations

Both integrations **fail closed by default**: if CertiLayer can't give a
verdict, the request is rejected. Opt in to `fail_open=True` only if you
prefer availability over protection during a CertiLayer outage.

### FastAPI

```python
from fastapi import Depends
from certilayer import CertiLayerClient

client = CertiLayerClient(api_key=settings.CERTILAYER_KEY)
guard  = client.fastapi_dependency(min_score=0.35)

@app.post("/checkout", dependencies=[Depends(guard)])
async def checkout(): ...
```

```python
client.fastapi_dependency(
    session_header: str = "x-certilayer-session",
    min_score: float = 0.30,
    fail_open: bool = False,
    require_session: bool = True,
)
```

Reads the session ID from the given header and raises `HTTPException` if the
check fails. With `require_session=False` a missing header returns `None`
instead of 403.

### Django

```python
# settings.py
client = CertiLayerClient(api_key=settings.CERTILAYER_KEY)
MIDDLEWARE = [
    ...
    client.django_middleware(paths=("/api/",)),
]
```

```python
client.django_middleware(
    session_header: str = "HTTP_X_CERTILAYER_SESSION",
    min_score: float = 0.30,
    reject_status: int = 403,
    fail_open: bool = False,
    require_session: bool = True,
    paths: Sequence[str] | None = None,
)
```

The middleware works under both WSGI (sync) and ASGI (async). Set `paths` to
the prefixes you want to protect — with the default `None` it gates **every**
request, including plain page loads that carry no session header.

Django converts an `x-certilayer-session` HTTP header into
`HTTP_X_CERTILAYER_SESSION` automatically.

### Guard behavior

| Situation                                                   | Default response                    | With `fail_open=True`                |
| ----------------------------------------------------------- | ----------------------------------- | ------------------------------------ |
| Missing session header                                      | 403 `missing_session`               | same (unless `require_session=False`) |
| Verdict `synthetic` / score below `min_score`               | 403 `bot_detected`                  | same                                 |
| `SESSION_NOT_FOUND` / `SESSION_EXPIRED`                     | 403 `invalid_session` / `session_expired` | same                           |
| `STEP_UP_REQUIRED` / `SESSION_TERMINATED`                   | 403 `step_up_required` / `session_terminated` | same                       |
| `INVALID_API_KEY`                                           | 500 `certilayer_misconfigured`      | same                                 |
| `RATE_LIMITED` or other unexpected error                    | 503 `verification_unavailable`      | same                                 |
| Network error, timeout, or 5xx from CertiLayer              | 503 `verification_unavailable`      | request allowed (`degraded=True`)    |

`fail_open` only ever covers real outages. A bad key, an unknown session, or a
policy decision is never waved through.

---

## Error handling

All SDK errors raise `CertiLayerError` with a machine-readable `.code`
(and `.status_code` when the API responded):

```python
from certilayer import CertiLayerError

try:
    result = await client.verify_session(session_id)
except CertiLayerError as e:
    if e.code == "SESSION_NOT_FOUND":
        return JSONResponse({"error": "session_expired"}, status_code=400)
    raise
```

| Code                 | Meaning                                                       |
| -------------------- | ------------------------------------------------------------- |
| `INVALID_API_KEY`    | API key missing, empty, or rejected by the server             |
| `SESSION_NOT_FOUND`  | No session exists for the given `session_id`                  |
| `SESSION_EXPIRED`    | Session exists but has exceeded its TTL                       |
| `STEP_UP_REQUIRED`   | Policy engine requires additional verification (WebAuthn/OTP) |
| `SESSION_TERMINATED` | Policy engine has revoked this session as confidently synthetic |
| `RATE_LIMITED`       | Too many requests — back off and retry                        |
| `NETWORK_ERROR`      | Could not reach the CertiLayer API                            |
| `TIMEOUT`            | Request exceeded `timeout_s`                                  |
| `UNEXPECTED_ERROR`   | Unclassified server or SDK error                              |

---

## Upgrading from 1.0.x

1.1.0 changes the guards' defaults to be secure:

- **Fail closed.** 1.0.x let requests through on *any* CertiLayer error.
  Now only `fail_open=True` does, and only for outages. To keep the old
  availability-first behavior: `fail_open=True`.
- **Missing header is rejected.** The Django middleware used to pass requests
  with no session header straight through. Set `paths=(...)` to protect only
  your API routes, or `require_session=False` to restore the old behavior.
- **`passed` is stricter.** A `synthetic` verdict never passes, whatever the
  score.
- The 403 body no longer includes `score`.

---

## Requirements

- Python 3.9+
- `httpx` (installed automatically as a dependency)

---

## License

MIT

## Support

- Docs: [certilayer.net/docs](https://certilayer.net/docs)
- Issues: [GitHub Issues](https://github.com/certilayerhq/certilayer-python-sdk/issues) or [contact@certilayer.net](mailto:contact@certilayer.net)
