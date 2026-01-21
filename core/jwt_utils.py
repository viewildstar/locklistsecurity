# core/jwt_utils.py
from __future__ import annotations

from typing import Optional, Dict, Any
import os
import time
import httpx
from jose import jwt

# If your frontend sends a Microsoft Graph access token, aud will usually be one of these:
ALLOWED_AUDIENCES = {
    "00000003-0000-0000-c000-000000000000",  # Microsoft Graph app id
    "https://graph.microsoft.com",
}

# Cache JWKS per-tenant so you do not fetch keys on every request
_JWKS_CACHE: dict[str, tuple[float, dict]] = {}  # tid -> (expires_at, jwks)


def extract_bearer_token(auth_header: Optional[str]) -> Optional[str]:
    """
    Accepts either:
      - "Bearer <token>"
      - "<token>"
    Returns the raw JWT string or None.
    """
    if not auth_header:
        return None
    auth_header = auth_header.strip()
    if auth_header.lower().startswith("bearer "):
        return auth_header.split(" ", 1)[1].strip()
    return auth_header


def _authority_host() -> str:
    """
    AZURE_AUTHORITY examples:
      https://login.microsoftonline.com/organizations
      https://login.microsoftonline.us/organizations
    We want just scheme+host.
    """
    authority = os.getenv("AZURE_AUTHORITY", "https://login.microsoftonline.com/organizations").strip()
    # keep scheme://host
    parts = authority.split("/")
    return "/".join(parts[:3])


async def _get_jwks_for_tid(tid: str) -> dict:
    now = time.time()
    cached = _JWKS_CACHE.get(tid)
    if cached and now < cached[0]:
        return cached[1]

    host = _authority_host()

    # v2 keys endpoint for a specific tenant
    jwks_url = f"{host}/{tid}/discovery/v2.0/keys"

    async with httpx.AsyncClient(timeout=10) as client:
        r = await client.get(jwks_url)
        r.raise_for_status()
        jwks = r.json()

    _JWKS_CACHE[tid] = (now + 6 * 60 * 60, jwks)  # 6h cache
    return jwks


async def verify_access_token(access_token: str) -> Dict[str, Any]:
    """
    Verifies:
      - JWT signature using tenant-matched Microsoft JWKS (kid-matched)

    NOTE:
    This is a temporary stub to avoid syntax errors.
    Implement full verification logic later.
    """
    raise NotImplementedError("verify_access_token is not implemented yet")