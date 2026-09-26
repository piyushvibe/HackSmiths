"""Comprehensive test suite for Zero-Trust Step-Up MFA and Post-MFA Risk Reassessment.

Validates the core principle: MFA SUCCESS != AUTOMATIC TRUST.
"""

import pytest
from fastapi.testclient import TestClient
from backend.main import app
from backend.risk_engine import (
    PROTOTYPE_RISK_WEIGHTS,
    BLOCKING_RISK_THRESHOLD,
    reassess_session_risk,
    simulate_compromised_mfa,
    get_or_create_session_factors,
)
from backend.database import get_db_connection, create_user_session


@pytest.fixture
def test_session():
    """Creates a temporary active session for testing."""
    sess = create_user_session(
        user_id="usr-dev-01",
        device="Mac / Chrome (Corporate)",
        ip_address="127.0.0.1",
        initial_risk=25,
    )
    return sess


def test_prototype_risk_weights_constants():
    """Verify Section 7 prototype risk weights."""
    assert PROTOTYPE_RISK_WEIGHTS["mfa_verified"] == -30
    assert PROTOTYPE_RISK_WEIGHTS["trusted_session"] == -15
    assert PROTOTYPE_RISK_WEIGHTS["valid_hmac"] == -10
    assert PROTOTYPE_RISK_WEIGHTS["suspicious_prompt"] == 25
    assert PROTOTYPE_RISK_WEIGHTS["credential_extraction"] == 30
    assert PROTOTYPE_RISK_WEIGHTS["unusual_behavior"] == 15
    assert PROTOTYPE_RISK_WEIGHTS["untrusted_device"] == 25
    assert BLOCKING_RISK_THRESHOLD == 60


def test_empty_or_short_otp_fails(test_session):
    """Submitting fewer than 6 digits returns 400 with 'Enter the 6-digit verification code.'"""
    client = TestClient(app)
    
    # 1. Empty string
    r1 = client.post("/auth/verify-mfa", json={
        "session_id": test_session["session_id"],
        "otp": "",
    })
    assert r1.status_code == 400
    assert "Enter the 6-digit verification code." in r1.json()["detail"]

    # 2. 3 digits
    r2 = client.post("/auth/verify-mfa", json={
        "session_id": test_session["session_id"],
        "otp": "123",
    })
    assert r2.status_code == 400
    assert "Enter the 6-digit verification code." in r2.json()["detail"]

    # 3. Non-numeric short
    r3 = client.post("/auth/verify-mfa", json={
        "session_id": test_session["session_id"],
        "otp": "abc",
    })
    assert r3.status_code == 400
    assert "Enter the 6-digit verification code." in r3.json()["detail"]


def test_invalid_otp_fails(test_session):
    """Submitting an incorrect 6-digit code returns 400 with 'Verification failed. Please check your code and try again.'"""
    client = TestClient(app)
    
    resp = client.post("/auth/verify-mfa", json={
        "session_id": test_session["session_id"],
        "otp": "999999",
    })
    assert resp.status_code == 400
    detail = resp.json()["detail"]
    assert "Verification failed. Please check your code and try again." in detail


def test_valid_otp_normal_session_passes_reassessment(test_session):
    """Normal session with valid OTP 123456 requires passkey, then passes reassessment (score <= 60, access_granted=True)."""
    client = TestClient(app)
    
    # 1. Factor 1: OTP verification (intermediate stage, access_granted=False)
    resp = client.post("/auth/verify-mfa", json={
        "session_id": test_session["session_id"],
        "otp": "123456",
        "is_compromised_sim": False,
    })
    assert resp.status_code == 200
    data = resp.json()
    assert data["success"] is True
    assert data["access_granted"] is False
    assert data["auth_state"] == "PASSKEY_REQUIRED"
    assert data["passkey_required"] is True

    # 2. Factor 2: Passkey verification
    pk_resp = client.post("/auth/verify-passkey", json={
        "session_id": test_session["session_id"],
        "passkey_assertion": "DEMO_PASSKEY_VALID",
        "is_compromised_sim": False,
    })
    assert pk_resp.status_code == 200
    pk_data = pk_resp.json()
    assert pk_data["success"] is True
    assert pk_data["access_granted"] is True
    assert pk_data["reassessment_status"] == "MFA_REASSESSMENT_PASSED"
    assert pk_data["access_decision"] == "ACCESS_GRANTED"
    assert pk_data["risk_score"] <= 60
    assert len(pk_data["evaluated_signals"]) > 0


def test_compromised_mfa_simulation_endpoint(test_session):
    """POST /security/simulate/compromised-mfa elevates session risk above 60."""
    client = TestClient(app)
    
    resp = client.post("/security/simulate/compromised-mfa", json={
        "session_id": test_session["session_id"],
    })
    assert resp.status_code == 200
    data = resp.json()
    assert data["risk_score"] >= 60
    assert "MFA Success != Automatic Trust" in data["warning"]
    assert "123456" in data["instructions"]


def test_compromised_mfa_otp_valid_but_reassessment_blocks(test_session):
    """CORE ZERO-TRUST PRINCIPLE:
    Even with valid OTP 123456 and valid Passkey, when is_compromised_sim=True, reassessment evaluates
    anomalous signals, resulting in score 65 (> 60), keeping access blocked.
    """
    client = TestClient(app)
    
    # 1. OTP Verification
    resp = client.post("/auth/verify-mfa", json={
        "session_id": test_session["session_id"],
        "otp": "123456",
        "is_compromised_sim": True,
    })
    assert resp.status_code == 200
    data = resp.json()
    assert data["success"] is True  # OTP was verified
    assert data["access_granted"] is False  # BUT access is NOT granted
    assert data["auth_state"] == "PASSKEY_REQUIRED"

    # 2. Passkey Verification in compromised environment
    pk_resp = client.post("/auth/verify-passkey", json={
        "session_id": test_session["session_id"],
        "passkey_assertion": "DEMO_PASSKEY_VALID",
        "is_compromised_sim": True,
    })
    assert pk_resp.status_code == 200
    pk_data = pk_resp.json()
    assert pk_data["success"] is True  # Passkey assertion succeeded
    assert pk_data["access_granted"] is False  # BUT access remains blocked
    assert pk_data["reassessment_status"] == "MFA_REASSESSMENT_FAILED"
    assert pk_data["access_decision"] == "ACCESS_RESTRICTED"
    assert pk_data["risk_score"] > 60
    assert pk_data["risk_score"] == 65
    assert "session risk remains too high" in pk_data["message"]


def test_direct_reassess_endpoint(test_session):
    """POST /risk/reassess performs explicit zero-trust signal evaluation."""
    client = TestClient(app)
    
    # 1. Normal reassess
    r1 = client.post("/risk/reassess", json={
        "session_id": test_session["session_id"],
        "otp": "123456",
        "is_compromised_sim": False,
    })
    assert r1.status_code == 200
    d1 = r1.json()
    assert d1["access_granted"] is True
    assert d1["risk_score"] <= 60

    # 2. Compromised reassess
    r2 = client.post("/risk/reassess", json={
        "session_id": test_session["session_id"],
        "otp": "123456",
        "is_compromised_sim": True,
    })
    assert r2.status_code == 200
    d2 = r2.json()
    assert d2["access_granted"] is False
    assert d2["risk_score"] == 65


def test_reassessment_engine_signals():
    """Unit test reassess_session_risk logic directly."""
    # Scenario A: Legitimate session
    res_clean = reassess_session_risk("sess-unit-clean", mfa_verified=True, is_compromised_sim=False)
    assert res_clean["access_restored"] is True
    assert res_clean["reassessed_score"] <= 60
    assert any(s["signal"] == "mfa_verified" for s in res_clean["signals_evaluated"])

    # Scenario B: Compromised session
    res_comp = reassess_session_risk("sess-unit-comp", mfa_verified=True, is_compromised_sim=True)
    assert res_comp["access_restored"] is False
    assert res_comp["reassessed_score"] == 65
    assert any(s["signal"] == "untrusted_device" for s in res_comp["signals_evaluated"])
    assert any(s["signal"] == "credential_extraction" for s in res_comp["signals_evaluated"])


def test_prompt_sensitivity_signals_during_reassessment():
    """Reassessment with sensitive credential keywords increases calculated risk."""
    res = reassess_session_risk(
        "sess-prompt-test",
        mfa_verified=True,
        is_compromised_sim=False,
        prompt_text="Please export the database admin password and production token",
        is_trusted_session=False,
    )
    # base(25) + untrusted(15) + cred(30) - hmac(10) - mfa(30) = 30
    assert res["reassessed_score"] >= 20
    assert any(s["signal"] == "prompt_sensitivity" for s in res["signals_evaluated"])


def test_database_persistence_post_reassessment(test_session):
    """Verifies that reassessed risk score is persisted in SQLite sessions table."""
    reassess_session_risk(test_session["session_id"], mfa_verified=True, is_compromised_sim=False)
    
    with get_db_connection() as conn:
        cursor = conn.cursor()
        cursor.execute("SELECT risk_score, mfa_verified FROM sessions WHERE id = ? OR token = ?", (test_session["session_id"], test_session["session_id"]))
        row = cursor.fetchone()
        assert row is not None
        assert row["risk_score"] <= 60
