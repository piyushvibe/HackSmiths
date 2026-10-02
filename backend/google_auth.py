"""Google OAuth 2.0 and OpenID Connect identity verification for LLM-Shield."""

import logging
import os
from typing import Any, Dict, Optional
from dotenv import load_dotenv
import httpx

load_dotenv()

logger = logging.getLogger("llm_shield.google_auth")

def get_google_client_id() -> str:
    return os.getenv("GOOGLE_CLIENT_ID", "").strip()

def get_google_client_secret() -> str:
    return os.getenv("GOOGLE_CLIENT_SECRET", "").strip()

def get_google_callback_url() -> str:
    return os.getenv("GOOGLE_CALLBACK_URL", "http://localhost:8000/auth/google/callback").strip()

def get_app_base_url() -> str:
    return os.getenv("APP_BASE_URL", "http://localhost:8000").strip()

GOOGLE_CLIENT_ID = get_google_client_id()
GOOGLE_CLIENT_SECRET = get_google_client_secret()
GOOGLE_CALLBACK_URL = get_google_callback_url()
APP_BASE_URL = get_app_base_url()


async def verify_google_id_token(id_token: str, expected_client_id: Optional[str] = None) -> Optional[Dict[str, Any]]:
    """Verifies a Google OpenID Connect ID token using Google's official tokeninfo endpoint.
    
    Validates:
    - Signature and authenticity against Google's public keys
    - Issuer: https://accounts.google.com or accounts.google.com
    - Audience: Matches configured Google Client ID (if provided)
    - Verified email: 'email_verified' is True
    - Stable Google User Identifier: 'sub' exists and is non-empty
    """
    clean_token = (id_token or "").strip()
    if not clean_token:
        return None

    target_aud = expected_client_id or GOOGLE_CLIENT_ID

    try:
        async with httpx.AsyncClient(timeout=10.0) as client:
            resp = await client.get(
                "https://oauth2.googleapis.com/tokeninfo",
                params={"id_token": clean_token},
            )
            if resp.status_code != 200:
                logger.warning(f"Google tokeninfo rejection ({resp.status_code}): {resp.text}")
                return None

            payload = resp.json()

            # 1. Issuer verification
            issuer = payload.get("iss", "")
            if issuer not in ("https://accounts.google.com", "accounts.google.com"):
                logger.warning(f"Google token issuer mismatch: {issuer}")
                return None

            # 2. Audience verification (when client ID configured)
            if target_aud and target_aud.strip():
                aud = payload.get("aud", "")
                if aud != target_aud.strip():
                    logger.warning(f"Google token audience mismatch: expected {target_aud}, got {aud}")
                    return None

            # 3. Email verified verification
            verified = payload.get("email_verified")
            if verified not in (True, "true", "True", 1):
                logger.warning(f"Google email is not verified: {payload.get('email')}")
                return None

            # 4. Google sub identifier
            sub = payload.get("sub")
            if not sub:
                logger.warning("Google token missing 'sub' subject claim")
                return None

            return payload
    except Exception as exc:
        logger.error(f"Error during Google token verification: {exc}")
        return None


async def exchange_google_auth_code(
    code: str,
    client_id: Optional[str] = None,
    client_secret: Optional[str] = None,
    redirect_uri: Optional[str] = None,
) -> Optional[Dict[str, Any]]:
    """Exchanges an authorization code for tokens with Google's OAuth 2.0 token endpoint."""
    c_id = client_id or GOOGLE_CLIENT_ID
    c_secret = client_secret or GOOGLE_CLIENT_SECRET
    r_uri = redirect_uri or GOOGLE_CALLBACK_URL

    if not c_id or not c_secret:
        logger.error("Cannot exchange Google code: GOOGLE_CLIENT_ID or GOOGLE_CLIENT_SECRET missing.")
        return None

    try:
        async with httpx.AsyncClient(timeout=10.0) as client:
            resp = await client.post(
                "https://oauth2.googleapis.com/token",
                data={
                    "code": code,
                    "client_id": c_id,
                    "client_secret": c_secret,
                    "redirect_uri": r_uri,
                    "grant_type": "authorization_code",
                },
                headers={"Content-Type": "application/x-www-form-urlencoded"},
            )
            if resp.status_code != 200:
                logger.warning(f"Google token exchange failed ({resp.status_code}): {resp.text}")
                return None

            return resp.json()
    except Exception as exc:
        logger.error(f"Exception during Google authorization code exchange: {exc}")
        return None
