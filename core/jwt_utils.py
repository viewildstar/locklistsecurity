import time
from typing import Any, Dict, Optional

import httpx
from jose import jwt
from jose.exceptions import JWTError

JWKS_URL = "https://login.microsoftonline.com/common/discovery/v2.0/keys"

# Accept either Graph audience form
ALLOWED_AUDIENCES = {
    "00000003-0000-0000-c000-000000000000",  # Microsoft Graph app id
    "https://graph.microsoft.com",
}

# Simple JWKS cache (in-memory)
_JWKS_CACHE: Dict[str, Any] = {}
_JWKS_CACHE_EXPIRES: float = 0


async def _get_jwks() -> Dict[str, Any]:
    global _JWKS_CACHE, _JWKS_CACHE_EXPIRES
    now = time.time()
    if _JWKS_CACHE and now < _JWKS_CACHE_EXPIRES:
        return _JWKS_CACHE

    async with httpx.AsyncClient(timeout=15) as client:
        r = await client.get(JWKS_URL)
        r.raise_for_status()
        data = r.json()

    _JWKS_CACHE = data
    _JWKS_CACHE_EXPIRES = now + 60 * 60  # 1 hour
    return data


def _find_jwk(jwks: Dict[str, Any], kid: str) -> Dict[str, Any]:
    for k in jwks.get("keys", []):
        if k.get("kid") == kid:
            return k
    raise ValueError("Signing key not found (kid mismatch) — try again (key rotation).")


async def verify_access_token(access_token: str) -> Dict[str, Any]:
    """
    Verify signature for a Microsoft identity platform JWT and ensure it's a Graph access token.
    """
    jwks = await _get_jwks()

    try:
        header = jwt.get_unverified_header(access_token)
        kid = header.get("kid")
        if not kid:
            raise ValueError("Token missing kid")

        jwk = _find_jwk(jwks, kid)

        # Verify signature + exp/nbf, but do audience manually (since Graph aud can vary)
        claims = jwt.decode(
            access_token,
            jwk,
            algorithms=["RS256"],
            options={
                "verify_aud": False,
                "verify_iss": False,
                "verify_exp": True,
                "verify_nbf": True,
            },
        )

        aud = claims.get("aud")
        if aud not in ALLOWED_AUDIENCES:
            raise ValueError(f"Invalid audience (aud): {aud}")

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
