# Changelog

## 1.1.0 — 2026-10-23

### Security
- Guards now fail **closed** by default. `fail_open=True` is opt-in and only
  applies to outages (network error, timeout, 5xx). Invalid API key, unknown /
  expired / terminated sessions, step-up and rate limits always reject.
- Django middleware rejects requests with no session header (`require_session=True`).
- `quick_check().passed` is never true for a `synthetic` verdict.
- Session IDs are percent-encoded before being placed in the request path.
- Rejection responses no longer include the HCS score.

### Added
- `verify_session_sync()` / `quick_check_sync()` and `close()`.
- Django middleware is sync- and async-capable; new `paths` option.
- `QuickCheckResult.degraded`, `CertiLayerError.status_code`.
- `certilayer[fastapi]` and `certilayer[django]` extras now actually exist.
- `py.typed` marker.

### Fixed
- `str | None` annotations broke FastAPI on Python 3.9.
- `X-SDK-Version` header now follows the package version.

## 1.0.0
- Initial release.
