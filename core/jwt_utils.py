# core/jwt_utils.py
from __future__ import annotations

from typing import Optional, Dict, Any

import jwt
from jwt import PyJWKClient


# Microsoft identity platform JWKS endpoint (works for Entra-issued tokens)
JWKS_URL = "https://login.microsoftonline.com/common/discovery/v2.0/keys"

# If your frontend sends a Microsoft Graph access token, aud will usually be one of these:
ALLOWED_AUDIENCES = {
    "00000003-0000-0000-c000-000000000000",  # Microsoft Graph app id
    "https://graph.microsoft.com",
}


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


def verify_access_token(access_token: str) -> Dict[str, Any]:
    """
    Verifies:
      - JWT signature using Microsoft JWKS (kid-matched)
      - exp/nbf (PyJWT verifies exp by default)
      - audience is Microsoft Graph (for your scan flow)

    Returns decoded claims dict on success, raises ValueError on failure.
    """
    token = extract_bearer_token(access_token)
    if not token:
        raise ValueError("Missing access token")

    try:
        jwk_client = PyJWKClient(JWKS_URL)
        signing_key = jwk_client.get_signing_key_from_jwt(token).key

        # Decode + verify signature + exp/nbf
        claims = jwt.decode(
            token,
            signing_key,
            algorithms=["RS256"],
            options={
                "verify_aud": False,  # we'll check aud manually
            },
        )

        aud = claims.get("aud")
        if aud not in ALLOWED_AUDIENCES:
            raise ValueError(f"Invalid token audience (aud): {aud}")

        # Optional: basic sanity checks
        if "tid" not in claims:
            raise ValueError("Token missing tid (tenant id)")
        if "iss" not in claims:
            raise ValueError("Token missing iss (issuer)")

        return claims

    except Exception as e:
        # Normalize errors into one message for your API
        raise ValueError(f"Invalid token: {e}")
