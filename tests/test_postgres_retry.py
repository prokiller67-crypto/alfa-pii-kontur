"""A stale pooled connection should not fail the first request after idling."""

import psycopg
import pytest

from pii_proxy.postgres import PostgresStore


async def test_operational_error_retries_once(monkeypatch):
    store = PostgresStore("postgresql://unused")
    store._opened = True
    calls = 0

    async def run_query(_query, _params):
        nonlocal calls
        calls += 1
        if calls == 1:
            raise psycopg.OperationalError("stale connection")
        return (True,)

    monkeypatch.setattr(store, "_run_query", run_query)
    assert await store._query("SELECT TRUE") == (True,)
    assert calls == 2


async def test_persistent_operational_error_fails_closed(monkeypatch):
    store = PostgresStore("postgresql://unused")
    store._opened = True
    calls = 0

    async def run_query(_query, _params):
        nonlocal calls
        calls += 1
        raise psycopg.OperationalError("database unavailable")

    monkeypatch.setattr(store, "_run_query", run_query)
    with pytest.raises(psycopg.OperationalError):
        await store._query("SELECT TRUE")
    assert calls == 2
