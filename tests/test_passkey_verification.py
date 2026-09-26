"""
Zero-Trust Passkey Verification Test Suite
==========================================
Validates the two-stage step-up authentication contract:
OTP Verification -> Passkey Verification -> Identity Risk Reassessment -> Access Resolution.
"""
import pytest
from fastapi.testclient import TestClient
from backend.main import app
from backend.database import get_db_connection, create_user_session, init_db


@pytest.fixture(autouse=True)
def setup_db():
    init_db()


@pytest.fixture
def active_session():
    """Generates an active test session for user piyush."""
    sess = create_user_session(
        user_id="usr-dev-01",
        device="MacBook Pro M2",
        ip_address="192.168.1.50",
    )
    return sess


def test_1_otp_alone_does_not_grant_access(active_session):
    """TEST 1: OTP SUCCESS DOES NOT RELEASE PROTECTED INFORMATION.
    OTP verification is an intermediate stage; access_granted must remain False,
    passkey_required must be True, and mfa_verified must remain 0 in the database.
    """
    client = TestClient(app)

    resp = client.post("/auth/verify-mfa", json={
        "session_id": active_session["session_id"],
        "otp": "123456",
        "is_compromised_sim": False,
    })
    assert resp.status_code == 200
    data = resp.json()
    assert data["success"] is True
    assert data["access_granted"] is False  # ZERO-TRUST: OTP alone != access
    assert data["passkey_required"] is True
    assert data["auth_state"] == "PASSKEY_REQUIRED"
    assert data["otp_verified"] is True

    # Database invariant check
    conn = get_db_connection()
    try:
        row = conn.execute("SELECT otp_verified, passkey_verified, mfa_verified FROM sessions WHERE id = ?", (active_session["session_id"],)).fetchone()
        assert row["otp_verified"] == 1
        assert row["passkey_verified"] == 0
        assert row["mfa_verified"] == 0
    finally:
        conn.close()


def test_2_passkey_verification_endpoint_success(active_session):
    """TEST 2: Passkey verification succeeds with valid assertion and completes reassessment."""
    client = TestClient(app)

    # First complete OTP
    client.post("/auth/verify-mfa", json={
        "session_id": active_session["session_id"],
        "otp": "123456",
    })

    # Then complete Passkey
    resp = client.post("/auth/verify-passkey", json={
        "session_id": active_session["session_id"],
        "passkey_assertion": "DEMO_PASSKEY_VALID",
        "is_compromised_sim": False,
    })
    assert resp.status_code == 200
    data = resp.json()
    assert data["success"] is True
    assert data["access_granted"] is True
    assert data["reassessment_status"] == "MFA_REASSESSMENT_PASSED"
    assert data["access_decision"] == "ACCESS_GRANTED"
    assert data["risk_score"] <= 60

    # Database check
    conn = get_db_connection()
    try:
        row = conn.execute("SELECT otp_verified, passkey_verified, mfa_verified FROM sessions WHERE id = ?", (active_session["session_id"],)).fetchone()
        assert row["otp_verified"] == 1
        assert row["passkey_verified"] == 1
        assert row["mfa_verified"] == 1
    finally:
        conn.close()


def test_3_valid_otp_plus_valid_passkey_normal_risk_restores_access(active_session):
    """TEST 3: Full sequence (OTP -> Passkey -> Risk Reassessment <= 60) restores workstation access."""
    client = TestClient(app)

    # 1. OTP
    r1 = client.post("/auth/verify-mfa", json={
        "session_id": active_session["session_id"],
        "otp": "123456",
    })
    assert r1.status_code == 200
    assert r1.json()["access_granted"] is False

    # 2. Passkey
    r2 = client.post("/auth/verify-passkey", json={
        "session_id": active_session["session_id"],
        "passkey_assertion": "DEMO_PASSKEY_VALID",
    })
    assert r2.status_code == 200
    d2 = r2.json()
    assert d2["access_granted"] is True
    assert d2["auth_state"] == "ACCESS_GRANTED"
    assert d2["risk_level"] in ("LOW", "MEDIUM")


def test_4_valid_otp_plus_valid_passkey_with_high_risk_blocks_access(active_session):
    """TEST 4: Compromised MFA Scenario (OTP valid + Passkey valid + Anomaly Risk > 60).
    Zero-Trust principle holds: even when all credentials pass, access remains blocked!
    """
    client = TestClient(app)

    # 1. Valid OTP in compromised environment
    r1 = client.post("/auth/verify-mfa", json={
        "session_id": active_session["session_id"],
        "otp": "123456",
        "is_compromised_sim": True,
    })
    assert r1.status_code == 200
    assert r1.json()["access_granted"] is False

    # 2. Valid Passkey in compromised environment
    r2 = client.post("/auth/verify-passkey", json={
        "session_id": active_session["session_id"],
        "passkey_assertion": "DEMO_PASSKEY_VALID",
        "is_compromised_sim": True,
    })
    assert r2.status_code == 200
    d2 = r2.json()
    assert d2["success"] is True
    assert d2["access_granted"] is False  # Zero-Trust block
    assert d2["reassessment_status"] == "MFA_REASSESSMENT_FAILED"
    assert d2["access_decision"] == "ACCESS_RESTRICTED"
    assert d2["risk_score"] == 65

    # Database invariant check: mfa_verified must NOT be granted
    conn = get_db_connection()
    try:
        row = conn.execute("SELECT mfa_verified FROM sessions WHERE id = ?", (active_session["session_id"],)).fetchone()
        assert row["mfa_verified"] == 0
    finally:
        conn.close()


def test_5_failed_passkey_assertion_rejects(active_session):
    """TEST 5: Failed or malicious passkey assertion fails verification and keeps access restricted."""
    client = TestClient(app)

    # Complete OTP
    client.post("/auth/verify-mfa", json={
        "session_id": active_session["session_id"],
        "otp": "123456",
    })

    # Failed Passkey assertion
    r_fail = client.post("/auth/verify-passkey", json={
        "session_id": active_session["session_id"],
        "passkey_assertion": "FAIL",
    })
    assert r_fail.status_code == 400
    assert "Passkey verification failed" in r_fail.json()["detail"]

    # Database invariant: passkey_verified and mfa_verified remain 0
    conn = get_db_connection()
    try:
        row = conn.execute("SELECT passkey_verified, mfa_verified FROM sessions WHERE id = ?", (active_session["session_id"],)).fetchone()
        assert row["passkey_verified"] == 0
        assert row["mfa_verified"] == 0
    finally:
        conn.close()


def test_6_passkey_api_aliases_work(active_session):
    """TEST 6: API endpoints /api/mfa/verify-stepup and /api/mfa/verify-passkey work equivalently."""
    client = TestClient(app)

    r_otp = client.post("/api/mfa/verify-stepup", json={
        "session_id": active_session["session_id"],
        "otp": "123456",
    })
    assert r_otp.status_code == 200
    assert r_otp.json()["passkey_required"] is True

    r_pk = client.post("/api/mfa/verify-passkey", json={
        "session_id": active_session["session_id"],
        "passkey_assertion": "DEMO_PASSKEY_VALID",
    })
    assert r_pk.status_code == 200
    assert r_pk.json()["access_granted"] is True


def test_7_zero_trust_invariant_no_single_factor_grants_access(active_session):
    """TEST 7: Zero-Trust Invariant: Neither factor alone nor unverified risk releases access."""
    client = TestClient(app)

    # Scenario A: OTP alone
    r_otp = client.post("/auth/verify-mfa", json={
        "session_id": active_session["session_id"],
        "otp": "123456",
    })
    assert r_otp.json()["access_granted"] is False

    # Scenario B: Invalid OTP
    r_inv_otp = client.post("/auth/verify-mfa", json={
        "session_id": active_session["session_id"],
        "otp": "000000",
    })
    assert r_inv_otp.status_code == 400

    # Scenario C: Invalid Passkey
    r_inv_pk = client.post("/auth/verify-passkey", json={
        "session_id": active_session["session_id"],
        "passkey_assertion": "INVALID_ASSERTION",
    })
    assert r_inv_pk.status_code == 400
