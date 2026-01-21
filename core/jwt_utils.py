from typing import Optional, Dict, Any
import jwt
from jwt import PyJWKClient

JWKS_URL = "https://login.microsoftonline.com/common/discovery/v2.0/keys"

ALLOWED_AUDIENCES = {
    "00000003-0000-0000-c000-000000000000",  # Graph app id
    "https://graph.microsoft.com",
}

def extract_bearer_token(auth_header: Optional[str]) -> Optional[str]:
    if not auth_header:
        return None
    parts = auth_header.split()
    if len(parts) == 2 and parts[0].lower() == "bearer":
        return parts[1]
    return auth_header  # allow raw token too

def verify_access_token(access_token: str) -> Dict[str, Any]:
    # Some frontends accidentally send "Bearer <token>"
    if access_token.startswith("Bearer "):
        access_token = access_token.split(" ", 1)[1].strip()

    jwk_client = PyJWKClient(JWKS_URL)
    signing_key = jwk_client.get_signing_key_from_jwt(access_token).key

    claims = jwt.decode(
        access_token,
        signing_key,
        algorithms=["RS256"],
        options={
            "verify_aud": False,  # we'll check aud manually
        },
    )

    aud = claims.get("aud")
    if aud not in ALLOWED_AUDIENCES:
        raise ValueError(f"Invalid audience (aud): {aud}")

    return claims
