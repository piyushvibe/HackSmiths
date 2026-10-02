"""Vercel Serverless Function entrypoint for LLM-Shield."""

import os
import sys

# Ensure repository root is in sys.path so 'backend' package imports work cleanly
PROJECT_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if PROJECT_ROOT not in sys.path:
    sys.path.insert(0, PROJECT_ROOT)

from backend.main import app

# Vercel's Python builder automatically wraps the ASGI 'app'
