import time
from typing import Any, Dict, Optional

import httpx
from jose import jwt
from jose.exceptions import JWTError

# Simple JWKS cache (in-memory)
_JWKS_CACHE: Dict[str, Any] = {}
_JWKS_CACHE_EXPIRES: float = 0


async def _get_jwks() -> Dict[str, Any]:
    """Fetch Microsoft identity platform signing keys (multi-tenant)."""
    global _JWKS_CACHE, _JWKS_CACHE_EXPIRES

    now = time.time()
    if _JWKS_CACHE and now < _JWKS_CACHE_EXPIRES:
        return _JWKS_CACHE

    # Common endpoint works for multi-tenant apps.
    jwks_url = "https://login.microsoftonline.com/common/discovery/v2.0/keys"
    async with httpx.AsyncClient(timeout=15) as client:
        r = await client.get(jwks_url)
        r.raise_for_status()
        data = r.json()

    _JWKS_CACHE = data
    _JWKS_CACHE_EXPIRES = now + 60 * 60  # 1 hour
    return data


async def verify_access_token(access_token: str, expected_audience: str) -> Dict[str, Any]:
    """Verify signature + audience. Returns decoded claims.

    Notes:
    - For MVP, we validate signature + aud.
    - In production, also validate issuer/tenant, roles, and other claims.
    """
    jwks = await _get_jwks()
    try:
        # jose will pick the right key via 'kid'
        claims = jwt.decode(
            access_token,
            jwks,
            algorithms=["RS256"],
            audience=expected_audience,
            options={"verify_iss": False},
        )
        return claims
    except JWTError as e:
        raise ValueError(f"Invalid token: {e}")


def extract_bearer_token(auth_header: Optional[str]) -> Optional[str]:
    if not auth_header:
        return None
    parts = auth_header.split()
    if len(parts) == 2 and parts[0].lower() == "bearer":
        return parts[1]
    return None
