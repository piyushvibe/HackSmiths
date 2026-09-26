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


def test_login_demo_credentials_elements():
    """Verify login page includes pre-seeded demo credential buttons and JS handlers."""
    client = TestClient(app)
    html_resp = client.get("/")
    assert html_resp.status_code == 200
    html = html_resp.text
    assert "fillDemoDevBtn" in html
    assert "fillDemoAdminBtn" in html
    assert "fillDemoCredentials" in html

    js_resp = client.get("/app.js")
    assert js_resp.status_code == 200
    assert "fillDemoCredentials" in js_resp.text
    assert "Demo@123" in js_resp.text
    assert "Admin@123" in js_resp.text

