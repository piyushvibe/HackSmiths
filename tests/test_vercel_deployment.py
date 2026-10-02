"""Tests for Vercel Serverless Function deployment and entrypoint."""

import os
from fastapi.testclient import TestClient
from backend.main import app
from backend.database import get_db_path, SOURCE_DB_PATH
import tomllib
import json


def test_vercel_entrypoint_loads():
    """Verify backend.main:app loads and serves routes correctly."""
    client = TestClient(app)

    # 1. Health check
    resp_health = client.get("/api/health")
    assert resp_health.status_code == 200
    assert resp_health.json()["status"] == "healthy"

    # 2. Frontend HTML
    resp_root = client.get("/")
    assert resp_root.status_code == 200
    assert "LLM-SHIELD" in resp_root.text

    # 3. Static CSS & JS
    resp_css = client.get("/styles.css")
    assert resp_css.status_code == 200
    assert "text/css" in resp_css.headers["content-type"]

    resp_js = client.get("/app.js")
    assert resp_js.status_code == 200
    assert "javascript" in resp_js.headers["content-type"]


def test_vercel_tmp_database_path(monkeypatch):
    """Verify that in Vercel environment (VERCEL=1), get_db_path copies DB to /tmp and returns it."""
    monkeypatch.setenv("VERCEL", "1")
    path = get_db_path()
    assert path == "/tmp/llm_shield.db"
    assert os.path.exists("/tmp/llm_shield.db")


def test_vercel_config_entrypoint_matches():
    """Verify vercel.json and pyproject.toml both explicitly target backend.main:app."""
    # 1. Verify pyproject.toml
    with open("pyproject.toml", "rb") as f:
        pyproj = tomllib.load(f)
    assert pyproj.get("tool", {}).get("vercel", {}).get("entrypoint") == "backend.main:app"
    assert pyproj.get("tool", {}).get("fastapi", {}).get("entrypoint") == "backend.main:app"

    # 2. Verify vercel.json
    with open("vercel.json", "r") as f:
        vcfg = json.load(f)
    assert vcfg["builds"][0]["src"] == "backend/main.py"
    assert vcfg["routes"][0]["dest"] == "backend/main.py"
