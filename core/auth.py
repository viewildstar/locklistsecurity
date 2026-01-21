# core/auth.py
import os
import time
import httpx
from jose import jwt

AZURE_AUTHORITY = os.getenv("AZURE_AUTHORITY", "https://login.microsoftonline.com/organizations")
GRAPH_AUD = "00000003-0000-0000-c000-000000000000"  # Microsoft Graph app id

# Simple in-memory cache so you do not fetch JWKS on every request
_cache = {"jwks": None, "exp": 0, "jwks_uri": None}

async def _get_jwks():
    now = time.time()
    if _cache["jwks"] and now < _cache["exp"]:
        return _cache["jwks"], _cache["jwks_uri"]

    discovery_url = f"{AZURE_AUTHORITY}/v2.0/.well-known/openid-configuration"
    async with httpx.AsyncClient(timeout=10) as client:
        discovery = (await client.get(discovery_url)).json()
        jwks_uri = discovery["jwks_uri"]
        jwks = (await client.get(jwks_uri)).json()

    _cache["jwks"] = jwks
    _cache["jwks_uri"] = jwks_uri
    _cache["exp"] = now + 6 * 60 * 60  # 6 hours
    return jwks, jwks_uri

async def validate_graph_access_token(token: str) -> dict:
    jwks, _ = await _get_jwks()

    header = jwt.get_unverified_header(token)
    kid = header.get("kid")
    if not kid:
        raise ValueError("Token header missing kid")

    key = next((k for k in jwks["keys"] if k.get("kid") == kid), None)
    if not key:
        raise ValueError("No matching JWKS key for kid")

    # Multi-tenant issuer varies by tenant, so do not hard-require a single iss.
    # Do validate signature, exp, nbf, and audience.
    claims = jwt.decode(
        token,
        key,
        algorithms=["RS256"],
        audience=GRAPH_AUD,
        options={"verify_iss": False},
    )
    return claims
