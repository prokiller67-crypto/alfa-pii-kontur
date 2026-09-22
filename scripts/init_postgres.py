"""Idempotent schema setup for this application's isolated database."""

import os
from pathlib import Path
from urllib.parse import urlsplit

import certifi
import psycopg


def main():
    url = os.environ.get("DATABASE_URL_UNPOOLED", "")
    if not url or "-pooler" in (urlsplit(url).hostname or ""):
        raise ValueError("direct_DATABASE_URL_UNPOOLED_required")
    source = Path(__file__).resolve().parents[1] / "migrations" / "001_pii_state.sql"
    with psycopg.connect(url, connect_timeout=10, sslmode="verify-full", sslrootcert=certifi.where()) as conn:
        conn.execute("SELECT pg_advisory_xact_lock(719204551)")
        conn.execute(source.read_text())
    print("Encrypted state schema ready")


if __name__ == "__main__":
    main()
