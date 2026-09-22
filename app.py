"""Vercel's FastAPI entrypoint; the Docker entrypoint remains pii_proxy.serve."""

from src.pii_proxy.app import app as app
