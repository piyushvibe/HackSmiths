"""Tests for User Registration, PBKDF2 Real Authentication, and Google SSO Integration."""

import pytest
from fastapi.testclient import TestClient
from backend.main import app
from backend.database import get_db_connection


client = TestClient(app)


def test_demo_credentials_authentication():
    """Verify pre-seeded demo credentials authenticate successfully."""
    # Test Developer login
    resp = client.post(
        "/auth/login",
        json={"username": "piyush", "password": "Demo@123", "device": "Mac / Chrome (Test)"},
    )
    assert resp.status_code == 200
    data = resp.json()
    assert data["username"] == "piyush"
    assert data["role"] == "Developer"
    assert "token" in data
    assert data["token"].startswith("shield-tok-")
    assert "session_id" in data

    # Test Security Admin login
    resp_adm = client.post(
        "/auth/login",
        json={"username": "admin", "password": "Admin@123", "device": "Mac / Chrome (Test)"},
    )
    assert resp_adm.status_code == 200
    data_adm = resp_adm.json()
    assert data_adm["username"] == "admin"
    assert data_adm["role"] == "Security Admin"


def test_invalid_credentials_rejected():
    """Verify that wrong passwords or non-existent usernames return 401 Unauthorized."""
    # Wrong password for existing user
    resp = client.post(
        "/auth/login",
        json={"username": "piyush", "password": "WrongPassword!999"},
    )
    assert resp.status_code == 401
    assert "Invalid username or password" in resp.json()["detail"]

    # Non-existent user
    resp_fake = client.post(
        "/auth/login",
        json={"username": "non_existent_user_xyz", "password": "AnyPassword123!"},
    )
    assert resp_fake.status_code == 401
    assert "Invalid username or password" in resp_fake.json()["detail"]


def test_user_registration_and_real_auth():
    """Verify new user registration creates a real record and authenticates strictly."""
    import secrets
    unique_user = f"reguser_{secrets.token_hex(4)}"
    password = "StrongPassword789!"
    
    # 1. Register new user
    reg_resp = client.post(
        "/auth/register",
        json={
            "username": unique_user,
            "password": password,
            "full_name": "Test Engineer",
            "role": "Developer",
        },
    )
    assert reg_resp.status_code == 200
    reg_data = reg_resp.json()
    assert reg_data["username"] == unique_user
    assert reg_data["role"] == "Developer"
    assert "token" in reg_data
    assert "session_id" in reg_data

    # 2. Verify login succeeds with the correct password
    login_resp = client.post(
        "/auth/login",
        json={"username": unique_user, "password": password},
    )
    assert login_resp.status_code == 200
    assert login_resp.json()["username"] == unique_user

    # 3. Verify login fails with incorrect password
    bad_login = client.post(
        "/auth/login",
        json={"username": unique_user, "password": "IncorrectPassword!"},
    )
    assert bad_login.status_code == 401


def test_registration_validation_and_duplicate_prevention():
    """Verify input validation and duplicate prevention on registration."""
    import secrets
    existing_user = f"dupuser_{secrets.token_hex(4)}"
    
    # First registration
    client.post(
        "/auth/register",
        json={
            "username": existing_user,
            "password": "Password123!",
            "full_name": "Duplicate Tester",
        },
    )

    # Attempt to register duplicate
    dup_resp = client.post(
        "/auth/register",
        json={
            "username": existing_user,
            "password": "AnotherPassword456!",
            "full_name": "Duplicate Tester 2",
        },
    )
    assert dup_resp.status_code == 400
    assert "already registered" in dup_resp.json()["detail"].lower()

    # Short password
    short_pw_resp = client.post(
        "/auth/register",
        json={
            "username": f"short_{secrets.token_hex(4)}",
            "password": "123",
            "full_name": "Short Pw User",
        },
    )
    assert short_pw_resp.status_code == 400


def test_google_config_endpoint():
    """Verify GET /auth/google/config returns OAuth configuration."""
    resp = client.get("/auth/google/config")
    assert resp.status_code == 200
    data = resp.json()
    assert "client_id" in data
    assert "configured" in data
    assert isinstance(data["configured"], bool)


def test_google_signin_vs_signup_flow():
    """Verify strict separation between Google Sign In and Sign Up:
    - Sign In rejects unknown Google accounts with 404.
    - Sign Up registers new accounts with Developer role (least privilege).
    - Role escalation via signup payload is prevented.
    - Subsequent Sign In succeeds.
    """
    import secrets
    google_id = f"goog_{secrets.token_hex(8)}"
    google_email = f"user_{secrets.token_hex(4)}@google.com"

    # 1. Attempt Sign In before registration -> Must fail with 404
    signin_resp = client.post(
        "/auth/google",
        json={
            "google_id": google_id,
            "email": google_email,
            "full_name": "Google User",
            "mode": "signin",
        },
    )
    assert signin_resp.status_code == 404
    assert "ACCOUNT_NOT_FOUND" in signin_resp.json()["detail"] or "switch to Sign Up" in signin_resp.json()["detail"]

    # 2. Attempt Sign Up with role escalation attempt -> Must enforce Developer role
    signup_resp = client.post(
        "/auth/google",
        json={
            "google_id": google_id,
            "email": google_email,
            "full_name": "Google User",
            "role": "Security Admin",  # Attacker tries to escalate
            "mode": "signup",
        },
    )
    assert signup_resp.status_code == 200
    signup_data = signup_resp.json()
    assert signup_data["role"] == "Developer"  # Must be strictly Developer
    assert "token" in signup_data
    assert "session_id" in signup_data

    # 3. Subsequent Sign In with existing account -> Must succeed
    signin_success = client.post(
        "/auth/google",
        json={
            "google_id": google_id,
            "email": google_email,
            "full_name": "Google User",
            "mode": "signin",
        },
    )
    assert signin_success.status_code == 200
    signin_data = signin_success.json()
    assert signin_data["role"] == "Developer"
    assert "token" in signin_data

    # 4. Invalid email format rejected
    bad_email_resp = client.post(
        "/auth/google",
        json={"email": "not-an-email", "mode": "signup"},
    )
    assert bad_email_resp.status_code == 400


def test_frontend_registration_and_google_elements():
    """Verify index.html and app.js contain Google SSO UI components and no demo credentials."""
    html_resp = client.get("/")
    assert html_resp.status_code == 200
    html = html_resp.text
    assert "btnGoogleAuth" in html
    assert "tabSignIn" in html
    assert "tabSignUp" in html
    assert "authSwitchPrompt" in html
    assert "googleModal" not in html
    assert "googleJudgeAccount" not in html
    assert "fillDemoDevBtn" not in html

    js_resp = client.get("/app.js")
    assert js_resp.status_code == 200
    assert "triggerGoogleAuth" in js_resp.text
    assert "initGoogleAuth" in js_resp.text
    assert "setAuthMode" in js_resp.text

