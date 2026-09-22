"""Bounded encrypted state; atomic first-writer wins across workers."""

from __future__ import annotations

import asyncio
import base64
import hashlib
import heapq
import hmac
import json
import os
import time
from typing import Protocol

from cryptography.hazmat.primitives.ciphers.aead import AESGCM


class CapacityError(Exception):
    pass


class Store(Protocol):
    async def get(self, key: str) -> bytes | None: ...
    async def put_if_absent(self, key: str, value: bytes, ttl: int) -> bool: ...
    async def ping(self) -> bool: ...
    async def close(self) -> None: ...


class MemoryStore:
    """Single-process development adapter. Never evict a live restoration mapping."""

    def __init__(self, max_entries: int = 100_000, max_bytes: int = 256 * 1024 * 1024):
        self.entries: dict[str, bytes] = {}
        self.expiry: list[tuple[float, str]] = []
        self.size_bytes = 0
        self.max_entries = max_entries
        self.max_bytes = max_bytes
        self.lock = asyncio.Lock()

    def _prune(self) -> None:
        now = time.monotonic()
        while self.expiry and self.expiry[0][0] <= now:
            _, key = heapq.heappop(self.expiry)
            value = self.entries.pop(key, None)
            if value is not None:
                self.size_bytes -= len(value) + len(key)

    async def get(self, key: str) -> bytes | None:
        async with self.lock:
            self._prune()
            return self.entries.get(key)

    async def put_if_absent(self, key: str, value: bytes, ttl: int) -> bool:
        async with self.lock:
            self._prune()
            if key in self.entries:
                return False
            size = len(value) + len(key)
            if len(self.entries) >= self.max_entries or self.size_bytes + size > self.max_bytes:
                raise CapacityError
            self.entries[key] = value
            self.size_bytes += size
            heapq.heappush(self.expiry, (time.monotonic() + ttl, key))
            return True

    async def ping(self) -> bool:
        return True

    async def close(self) -> None:
        self.entries.clear()
        self.expiry.clear()
        self.size_bytes = 0


class RedisStore:
    def __init__(self, url: str):
        from redis.asyncio import Redis
        self.client = Redis.from_url(url, socket_connect_timeout=0.5, socket_timeout=0.5,
                                     max_connections=128, decode_responses=False)

    async def get(self, key: str) -> bytes | None:
        return await self.client.get(key)

    async def put_if_absent(self, key: str, value: bytes, ttl: int) -> bool:
        from redis.exceptions import OutOfMemoryError
        try:
            return bool(await self.client.set(key, value, nx=True, ex=ttl))
        except OutOfMemoryError:
            raise CapacityError from None

    async def ping(self) -> bool:
        return bool(await self.client.ping())

    async def close(self) -> None:
        await self.client.aclose()


class Vault:
    def __init__(self, store: Store, master_key: bytes, ttl: int = 1800):
        if len(master_key) != 32:
            raise ValueError("master_key_must_be_32_bytes")
        self.store = store
        self.ttl = ttl
        self._hash_key = hmac.digest(master_key, b"pii-proxy:hash:v1", hashlib.sha256)
        self._cipher = AESGCM(hmac.digest(master_key, b"pii-proxy:encryption:v1", hashlib.sha256))

    def digest(self, value: str) -> str:
        return hmac.new(self._hash_key, value.encode(), hashlib.sha256).hexdigest()

    def key(self, tenant: str, payload_id: str) -> str:
        return "pii:v1:" + self.digest(json.dumps([tenant, payload_id], ensure_ascii=False))

    async def get(self, tenant: str, payload_id: str) -> dict | None:
        key = self.key(tenant, payload_id)
        ciphertext = await self.store.get(key)
        if ciphertext is None:
            return None
        plaintext = self._cipher.decrypt(ciphertext[:12], ciphertext[12:], key.encode())
        return json.loads(plaintext)

    async def put(self, tenant: str, payload_id: str, record: dict) -> bool:
        key = self.key(tenant, payload_id)
        nonce = os.urandom(12)
        plaintext = json.dumps(record, ensure_ascii=False, separators=(",", ":")).encode()
        ciphertext = nonce + self._cipher.encrypt(nonce, plaintext, key.encode())
        return await self.store.put_if_absent(key, ciphertext, self.ttl)


def load_key(*, required: bool = False) -> bytes:
    value = os.environ.get("PII_MASTER_KEY")
    if not value:
        if required:
            raise ValueError("PII_MASTER_KEY_required_for_shared_or_public_service")
        return os.urandom(32)
    try:
        key = base64.urlsafe_b64decode(value)
    except Exception:
        raise ValueError("invalid_PII_MASTER_KEY") from None
    if len(key) != 32:
        raise ValueError("invalid_PII_MASTER_KEY_length")
    return key
