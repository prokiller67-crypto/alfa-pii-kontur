"""A stalled store must permit safe retries, including an uncertain commit."""

import asyncio

import httpx
import pytest

from pii_proxy.app import create_app
from pii_proxy.detector import Detector
from pii_proxy.service import Processor
from pii_proxy.vault import MemoryStore, Vault


class StallingStore(MemoryStore):
    def __init__(self, stage):
        super().__init__()
        self.stage = stage
        self.entered = asyncio.Event()

    async def stall(self):
        self.entered.set()
        await asyncio.Event().wait()

    async def get(self, key):
        if self.stage == "read":
            await self.stall()
        return await super().get(key)

    async def put_if_absent(self, key, value, ttl):
        result = await super().put_if_absent(key, value, ttl)
        if self.stage == "after_commit":
            await self.stall()
        return result


@pytest.mark.parametrize("stage", ["read", "after_commit"])
async def test_deadline_fails_closed_and_retry_restores_exactly(stage, caplog):
    store = StallingStore(stage)
    processor = Processor(Detector(use_ner=False), Vault(store, b"t" * 32))
    app = create_app(processor, request_timeout=0.1)
    transport = httpx.ASGITransport(app=app, client=("127.0.0.1", 123))
    body = {"payload": "Почта: secret@example.org", "payload_id": "deadline-private-id"}
    async with httpx.AsyncClient(transport=transport, base_url="http://test") as client:
        with caplog.at_level("INFO", logger="pii_proxy.audit"):
            async with asyncio.timeout(2):
                busy = await client.post("/process", json=body)
        assert store.entered.is_set()
        assert busy.status_code == 429
        assert busy.headers["retry-after"] == "1"
        assert busy.json() == {"error": "processing_deadline_retry"}
        assert "secret@" not in busy.text + caplog.text
        assert body["payload_id"] not in caplog.text
        assert app.state.inflight == 0

        # The database may have committed even though its acknowledgement stalled.
        store.stage = None
        masked = await client.post("/process", json=body)
        assert masked.status_code == 200
        assert "secret@" not in masked.json()["result"]
        assert len(store.entries) == 1
        restored = await client.post("/process", json={**body, "payload": masked.json()["result"]})
        assert restored.status_code == 200
        assert restored.json() == {"result": body["payload"]}
        assert app.state.inflight == 0


async def test_client_cancellation_releases_capacity():
    store = StallingStore("read")
    processor = Processor(Detector(use_ner=False), Vault(store, b"t" * 32))
    app = create_app(processor)
    transport = httpx.ASGITransport(app=app, client=("127.0.0.1", 123))
    async with httpx.AsyncClient(transport=transport, base_url="http://test") as client:
        request = asyncio.create_task(client.post("/process", json={"payload": "text", "payload_id": "cancel"}))
        async with asyncio.timeout(2):
            await store.entered.wait()
        assert app.state.inflight == 1
        request.cancel()
        with pytest.raises(asyncio.CancelledError):
            await request
        assert app.state.inflight == 0
