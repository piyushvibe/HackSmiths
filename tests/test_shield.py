"""Unit and integration tests for LLM-Shield Step 1."""

import asyncio
import json
import pytest
from fastapi.testclient import TestClient

from backend.main import app
from backend.auth import generate_signature, create_signed_payload, verify_signature
from backend.schemas import ShieldRequest, UserContext, PromptContext, AuthContext


def test_signature_generation_and_verification():
    """Verify that generated signatures match and pass verification."""
    payload = create_signed_payload(
        user_id="usr-test-01",
        role="analyst",
        session_id="sess-xyz",
        prompt_text="Explain buffer overflow protection.",
        action="chat",
        timestamp=1700000000,
    )
    
    req = ShieldRequest(**payload)
    assert verify_signature(req) is True


def test_tampered_payload_rejected():
    """Verify that tampering with prompt content invalidates the signature."""
    payload = create_signed_payload(
        user_id="usr-test-01",
        role="analyst",
        session_id="sess-xyz",
        prompt_text="Legitimate security query.",
        action="chat",
        timestamp=1700000000,
    )
    
    # Tamper with the raw prompt
    payload["prompt"]["raw"] = "DROP TABLE users; --"
    req = ShieldRequest(**payload)
    assert verify_signature(req) is False


def test_tampered_user_rejected():
    """Verify that tampering with user ID or role invalidates the signature."""
    payload = create_signed_payload(
        user_id="usr-test-01",
        role="analyst",
        session_id="sess-xyz",
        prompt_text="Legitimate security query.",
        action="chat",
        timestamp=1700000000,
    )
    
    # Tamper with the role to escalate privileges
    payload["user"]["role"] = "superadmin"
    req = ShieldRequest(**payload)
    assert verify_signature(req) is False


def test_health_endpoint():
    """Verify GET /api/health returns 200 and schema."""
    client = TestClient(app)
    response = client.get("/api/health")
    assert response.status_code == 200
    data = response.json()
    assert data["status"] == "healthy"
    assert "upstream_url" in data
    assert "upstream_model" in data
    assert "ollama_online" in data


def test_chat_unauthenticated_returns_401():
    """Verify POST /api/chat rejects requests with invalid or tampered signatures."""
    client = TestClient(app)
    payload = {
        "user": {"id": "attacker", "role": "hacker", "session_id": "bad-sess"},
        "prompt": {"raw": "Malicious payload", "timestamp": 1700000000},
        "action": "chat",
        "authenticate": {"token_type": "HMAC-SHA256", "sha256": "badbeef000000000000000000000000000000000000000000000000000000000"}
    }
    response = client.post("/api/chat", json=payload)
    assert response.status_code == 401
    assert "Invalid HMAC-SHA256 signature" in response.text


def test_chat_authenticated_streams_response():
    """Verify POST /api/chat accepts legitimate signature and returns SSE stream."""
    client = TestClient(app)
    payload = create_signed_payload(
        user_id="valid-user-1",
        role="analyst",
        session_id="session-123",
        prompt_text="Hello, LLM-Shield!",
        action="chat",
    )
    response = client.post("/api/chat", json=payload)
    assert response.status_code == 200
    assert "text/event-stream" in response.headers["content-type"]
    content = response.text
    assert "data:" in content
    assert "[DONE]" in content


def test_websocket_soc_connection():
    """Verify WebSocket /ws/soc accepts connection and handles ping/pong."""
    client = TestClient(app)
    with client.websocket_connect("/ws/soc") as websocket:
        initial = websocket.receive_json()
        assert initial["event"] == "soc_connected"
        assert initial["status"] == "active"
        
        websocket.send_text("ping")
        reply = websocket.receive_text()
        assert reply == "pong"


if __name__ == "__main__":
    pytest.main(["-v", __file__])

