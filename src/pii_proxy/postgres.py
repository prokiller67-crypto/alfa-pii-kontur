"""Encrypted shared state for serverless deployments backed by PostgreSQL."""

from __future__ import annotations

import asyncio
import time

import certifi
import psycopg
from psycopg_pool import AsyncConnectionPool, PoolTimeout, TooManyRequests

from .vault import CapacityError


class PostgresStore:
    def __init__(self, url: str):
        self.pool = AsyncConnectionPool(
            url, open=False, min_size=1, max_size=4, max_waiting=64, timeout=14,
            max_idle=60, reconnect_timeout=5,
            kwargs={"autocommit": True, "prepare_threshold": None, "connect_timeout": 5,
                    "sslmode": "verify-full", "sslrootcert": certifi.where()},
        )
        self._opened = False
        self._lock = asyncio.Lock()
        self._next_cleanup = 0.0

    async def _query(self, query: str, params: tuple = ()):
        if not self._opened:
            async with self._lock:
                if not self._opened:
                    await self.pool.open()
                    self._opened = True
        for attempt in range(2):
            try:
                return await self._run_query(query, params)
            except (PoolTimeout, TooManyRequests):
                raise CapacityError from None
            except psycopg.OperationalError:
                # Neon may suspend while a Vercel instance still holds a pooled
                # connection. The pool discards it; the next checkout reconnects.
                if attempt:
                    raise
            except psycopg.Error as exc:
                if exc.sqlstate and exc.sqlstate.startswith("53"):
                    raise CapacityError from None
                raise

    async def _run_query(self, query: str, params: tuple):
        try:
            async with self.pool.connection() as conn:
                if time.monotonic() >= self._next_cleanup:
                    self._next_cleanup = time.monotonic() + 15
                    await conn.execute("""
                        DELETE FROM pii_state WHERE key IN (
                            SELECT key FROM pii_state WHERE expires_at <= clock_timestamp()
                            ORDER BY expires_at LIMIT 2000
                        )
                    """)
                cursor = await conn.execute(query, params)
                return await cursor.fetchone()
        except psycopg.OperationalError:
            self._next_cleanup = 0.0
            raise

    async def get(self, key: str) -> bytes | None:
        row = await self._query(
            "SELECT ciphertext FROM pii_state WHERE key = %s AND expires_at > clock_timestamp()", (key,)
        )
        return bytes(row[0]) if row else None

    async def put_if_absent(self, key: str, value: bytes, ttl: int) -> bool:
        row = await self._query("""
            INSERT INTO pii_state (key, ciphertext, expires_at)
            VALUES (%s, %s, clock_timestamp() + %s * interval '1 second')
            ON CONFLICT (key) DO UPDATE
                SET ciphertext = EXCLUDED.ciphertext, expires_at = EXCLUDED.expires_at
                WHERE pii_state.expires_at <= clock_timestamp()
            RETURNING key
        """, (key, value, ttl))
        return row is not None

    async def ping(self) -> bool:
        row = await self._query("SELECT to_regclass('public.pii_state') IS NOT NULL")
        return bool(row and row[0])

    async def close(self) -> None:
        await self.pool.close(timeout=0.4)
