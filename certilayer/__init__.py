"""
CertiLayer Python SDK — L1 Backend SDK
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
Verify human sessions server-side in 3 lines:

    from certilayer import CertiLayerClient

    client = CertiLayerClient(api_key="cl_live_...")
    result = await client.verify_session(session_id)

    if result.verdict == "synthetic":
        raise HTTPException(status_code=403, detail="bot_detected")
"""

from .client import CertiLayerClient
from .types import (
    VerifyResult,
    QuickCheckResult,
    HCSVerdict,
    CertiLayerError,
    CertiLayerErrorCode,
)

__all__ = [
    "CertiLayerClient",
    "VerifyResult",
    "QuickCheckResult",
    "HCSVerdict",
    "CertiLayerError",
    "CertiLayerErrorCode",
]

__version__ = "1.0.0"
