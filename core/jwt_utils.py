import time
from typing import Any, Dict, Optional

import httpx
from jose import jwt
from jose.exceptions import JWTError

# Microsoft tenant-independent JWKS endpoint
JWKS_URL = "https://login.microsoftonline.com/common/discovery/v2.0/keys"

# Graph audience can appear as the App ID or the URL depending on token format
GRAPH_AUDIENCES = {
    "00000003-0000-0000-c000-000000000000",
    "https://graph.microsoft.com",
}

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
        jwks = r.json()

    # cache ~1 hour
    _JWKS_CACHE = jwks
    _JWKS_CACHE_EXPIRES = now + 3600
    return jwks


def _find_jwk(jwks: Dict[str, Any], kid: str) -> Dict[str, Any]:
    for k in jwks.get("keys", []):
        if k.get("kid") == kid:
            return k
    raise ValueError("Signing key not found (kid mismatch) — try again (key rotation).")


def extract_bearer_token(auth_header: Optional[str]) -> Optional[str]:
    if not auth_header:
        return None
    parts = auth_header.split()
    if len(parts) == 2 and parts[0].lower() == "bearer":
        return parts[1]
    return None


async def verify_graph_access_token(token: str) -> Dict[str, Any]:
    """
    Verify a delegated Microsoft Graph access token.
    Enforces:
      - signature (JWKS)
      - exp/nbf
      - aud is Graph
      - iss matches tid (v2 or v1 issuer format)
    """
    try:
        header = jwt.get_unverified_header(token)
        kid = header.get("kid")
        if not kid:
            raise ValueError("Token missing kid")

        # Get JWKS and signing key
        jwks = await _get_jwks()
        jwk = _find_jwk(jwks, kid)

        # Verify signature + standard claims (no issuer yet)
        claims = jwt.decode(
            token,
            jwk,
            algorithms=["RS256"],
            audience=list(GRAPH_AUDIENCES),
            options={
                "verify_aud": True,
                "verify_exp": True,
                "verify_nbf": True,
                "verify_iss": False,  # we'll do strict issuer check below
            },
        )

        tid = claims.get("tid")
        iss = claims.get("iss")
        if not tid or not iss:
            raise ValueError("Token missing tid/iss")

        valid_issuers = {
            f"https://login.microsoftonline.com/{tid}/v2.0",  # v2 tokens
            f"https://sts.windows.net/{tid}/",                # some access tokens show v1 issuer
        }
        if iss not in valid_issuers:
            raise ValueError(f"Invalid issuer: {iss}")

        return claims

    except (JWTError, httpx.HTTPError) as e:
        raise ValueError(f"Invalid token: {e}")

async def verify_access_token(token: str, expected_audience: Optional[str] = None) -> Dict[str, Any]:
    """
    Verify an Azure AD access token used by this service.

    Accepts Microsoft Graph access tokens by default. If `expected_audience` is provided,
    it will be accepted in addition to the standard Graph audiences.
    """
    audiences = set(GRAPH_AUDIENCES)
    if expected_audience:
        audiences.add(expected_audience)

    try:
        header = jwt.get_unverified_header(token)
        kid = header.get("kid")
        if not kid:
            raise ValueError("Token missing kid")

        jwks = await _get_jwks()
        jwk = _find_jwk(jwks, kid)

        claims = jwt.decode(
            token,
            jwk,
            algorithms=["RS256"],
            audience=list(audiences),
            options={
                "verify_aud": True,
                "verify_exp": True,
                "verify_nbf": True,
                "verify_iss": False,
            },
        )

        tid = claims.get("tid")
        iss = claims.get("iss")
        if not tid or not iss:
            raise ValueError("Token missing tid/iss")

        valid_issuers = {
            f"https://login.microsoftonline.com/{tid}/v2.0",
            f"https://sts.windows.net/{tid}/",
        }
        if iss not in valid_issuers:
            raise ValueError(f"Invalid issuer: {iss}")

        return claims

    except (JWTError, httpx.HTTPError) as e:
        raise ValueError(f"Invalid token: {e}")

