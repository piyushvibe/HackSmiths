"""Tests for Step 4: Frontend Web UI and static asset mounting."""

from fastapi.testclient import TestClient
from backend.main import app


def test_frontend_index_serves_html():
    """Verify GET / returns index.html with 3-panel UI elements."""
    client = TestClient(app)
    response = client.get("/")
    assert response.status_code == 200
    assert "text/html" in response.headers["content-type"]
    html = response.text
    assert "LLM-SHIELD" in html
    assert "panelUser" in html
    assert "panelHacker" in html
    assert "panelSoc" in html
    assert "ONE-CLICK ATTACK TRIGGERS FOR JUDGE DEMO" in html
    assert "SOC SECURITY RADAR" in html


def test_frontend_static_assets_serve_css_and_js():
    """Verify GET /styles.css and /app.js return 200 with proper media types."""
    client = TestClient(app)
    css_resp = client.get("/styles.css")
    assert css_resp.status_code == 200
    assert "text/css" in css_resp.headers["content-type"]
    assert "--bg-main:" in css_resp.text

    js_resp = client.get("/app.js")
    assert js_resp.status_code == 200
    assert "javascript" in js_resp.headers["content-type"]
    assert "computeHMAC" in js_resp.text
    assert "ATTACK_SCENARIOS" in js_resp.text


def test_api_routes_take_priority_over_static():
    """Verify /api/health and /api/chat are not masked by static files."""
    client = TestClient(app)
    health_resp = client.get("/api/health")
    assert health_resp.status_code == 200
    assert health_resp.json()["status"] == "healthy"


def test_auth_frontend_elements():
    """Verify login page includes styled Google button, OR divider, email/password inputs, and no demo credentials."""
    client = TestClient(app)
    html_resp = client.get("/")
    assert html_resp.status_code == 200
    html = html_resp.text

    # Google Auth elements and tabs are present
    assert "btnGoogleAuth" in html
    assert "btnGoogleAuthSignUp" in html
    assert "tabSignIn" in html
    assert "tabSignUp" in html
    assert "Continue with Google" in html
    assert "auth-divider" in html

    # Email & password inputs and toggles are present
    assert 'id="loginEmail"' in html
    assert 'id="loginPassword"' in html
    assert 'id="toggleLoginPassword"' in html
    assert 'id="regFullName"' in html
    assert 'id="regEmail"' in html
    assert 'id="regPassword"' in html
    assert 'id="regPasswordConfirm"' in html

    # Demo credentials and judge pre-seeded elements are NOT present
    assert "fillDemoDevBtn" not in html
    assert "fillDemoAdminBtn" not in html
    assert "Demo@123" not in html
    assert "Admin@123" not in html
    assert "DEMO JUDGE PRE-SEEDED CREDENTIALS" not in html

    js_resp = client.get("/app.js")
    assert js_resp.status_code == 200
    assert "initGoogleAuth" in js_resp.text
    assert "triggerGoogleAuth" in js_resp.text
    assert "handleSignInSubmit" in js_resp.text
    assert "handleSignUpSubmit" in js_resp.text
    assert "setupPasswordToggle" in js_resp.text

