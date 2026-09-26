"""Authentication and HMAC-SHA256 signature verification for LLM-Shield."""

import hashlib
import hmac
import json
import os
from typing import Any, Dict, Union
from dotenv import load_dotenv
from fastapi import HTTPException, status

from backend.schemas import ShieldRequest

load_dotenv()

DEFAULT_SECRET_KEY = "shield-super-secret-key-hacksmiths-2026"


def get_secret_key() -> str:
    """Retrieve the shared secret key from environment or fallback default."""
    return os.getenv("SHIELD_SECRET_KEY", DEFAULT_SECRET_KEY)


def serialize_canonical_payload(payload: Union[Dict[str, Any], ShieldRequest, str]) -> bytes:
    """Deterministically serialize payload to bytes for HMAC computation.
    
    Dictionaries are serialized with sorted keys and compact separators to ensure
    byte-for-byte consistency across platforms.
    """
    if isinstance(payload, ShieldRequest):
        canonical_data = payload.canonical_dict()
        return json.dumps(canonical_data, sort_keys=True, separators=(",", ":")).encode("utf-8")
    elif isinstance(payload, dict):
        return json.dumps(payload, sort_keys=True, separators=(",", ":")).encode("utf-8")
    elif isinstance(payload, str):
        return payload.encode("utf-8")
    elif isinstance(payload, (bytes, bytearray)):
        return bytes(payload)
    else:
        raise ValueError(f"Unsupported payload type for HMAC signing: {type(payload)}")


def generate_signature(
    payload: Union[Dict[str, Any], ShieldRequest, str],
    secret_key: Union[str, None] = None
) -> str:
    """Generate a hex-encoded HMAC-SHA256 signature for a payload.
    
    Args:
        payload: The structured payload (ShieldRequest, dictionary, or string).
        secret_key: The secret key to use. If None, loaded from environment.
        
    Returns:
        Hex-encoded SHA-256 HMAC string.
    """
    key = secret_key if secret_key is not None else get_secret_key()
    key_bytes = key.encode("utf-8")
    payload_bytes = serialize_canonical_payload(payload)
    
    return hmac.new(key_bytes, payload_bytes, hashlib.sha256).hexdigest()


def verify_signature(
    request: ShieldRequest,
    secret_key: Union[str, None] = None
) -> bool:
    """Verify an incoming ShieldRequest's HMAC-SHA256 signature against the secret key.
    
    Uses constant-time comparison to prevent timing side-channel attacks.
    
    Args:
        request: The parsed ShieldRequest.
        secret_key: Optional override for secret key.
        
    Returns:
        True if valid and untampered, False otherwise.
    """
    if not request.authenticate or not request.authenticate.sha256:
        return False
        
    expected_sig = generate_signature(request, secret_key=secret_key)
    received_sig = request.authenticate.sha256.strip().lower()
    
    return hmac.compare_digest(expected_sig.lower(), received_sig)


def verify_shield_auth(
    request: ShieldRequest,
    secret_key: Union[str, None] = None
) -> None:
    """FastAPI dependency / validation helper to enforce authentication.
    
    Raises:
        HTTPException (401): If signature is invalid or payload was tampered with.
    """
    if not verify_signature(request, secret_key=secret_key):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail={
                "error": "Unauthorized",
                "message": "Invalid HMAC-SHA256 signature or request payload has been tampered with."
            },
            headers={"WWW-Authenticate": "HMAC-SHA256"}
        )


def create_signed_payload(
    user_id: str,
    role: str,
    session_id: str,
    prompt_text: str,
    action: str = "chat",
    timestamp: Union[int, None] = None,
    secret_key: Union[str, None] = None
) -> Dict[str, Any]:
    """Helper utility for clients and test suites to construct a signed ShieldRequest dict."""
    import time
    ts = timestamp if timestamp is not None else int(time.time())
    
    canonical_dict = {
        "user": {
            "id": user_id,
            "role": role,
            "session_id": session_id,
        },
        "prompt": {
            "raw": prompt_text,
            "timestamp": ts,
        },
        "action": action,
    }
    
    sig = generate_signature(canonical_dict, secret_key=secret_key)
    
    return {
        "user": canonical_dict["user"],
        "prompt": canonical_dict["prompt"],
        "action": action,
        "authenticate": {
            "token_type": "HMAC-SHA256",
            "sha256": sig,
        }
    }

