import asyncio
import json

import httpx
import pytest
from fastapi.testclient import TestClient

from pii_proxy.app import create_app
from pii_proxy.detector import Detector
from pii_proxy.service import Policy, Processor
from pii_proxy.vault import CapacityError, UpstashStore, Vault


async def test_https_store_restores_across_instances_and_preserves_first_writer():
    data, commands = {}, []

    async def redis_api(request):
        assert request.headers["authorization"] == "Bearer test-token"
        command = json.loads(request.content)
        commands.append(command)
        if command[0] == "GET":
            result = data.get(command[1])
        elif command[0] == "SET":
            assert command[3:] == ["NX", "EX", 1800]
            result = None if command[1] in data else "OK"
            if result:
                data[command[1]] = command[2]
        else:
            assert command == ["PING"]
            result = "PONG"
        return httpx.Response(200, json={"result": result})

    stores = [UpstashStore("https://redis.example", "test-token", transport=httpx.MockTransport(redis_api))
              for _ in range(2)]
    try:
        assert await stores[0].ping()
        processors = [Processor(Detector(use_ner=False), Vault(store, b"t" * 32)) for store in stores]
        policy = Policy("tenant", mode="token")
        original = "Почта: synthetic@example.org\n"
        masks = await asyncio.gather(*(processors[i % 2].process(original, "same-id", policy) for i in range(8)))
        assert len({m["result"] for m in masks}) == 1
        restored = await processors[1].process(masks[0]["result"], "same-id", policy)
        assert restored["result"] == original
        assert "synthetic" not in json.dumps(commands)
        assert len(data) == 1
    finally:
        for store in stores:
            await store.close()


@pytest.mark.parametrize("status,body", [(429, {}), (200, {"error": "ERR max requests limit exceeded"}),
                                       (200, {"error": "OOM command not allowed"})])
async def test_provider_quota_becomes_retryable_capacity(status, body):
    store = UpstashStore("https://redis.example", "test-token",
                         transport=httpx.MockTransport(lambda _: httpx.Response(status, json=body)))
    try:
        with pytest.raises(CapacityError):
            await store.get("key")
    finally:
        await store.close()


def test_vercel_cannot_start_with_process_local_state(monkeypatch):
    monkeypatch.setenv("VERCEL", "1")
    monkeypatch.delenv("PII_REDIS_URL", raising=False)
    monkeypatch.delenv("UPSTASH_REDIS_REST_URL", raising=False)
    with pytest.raises(ValueError, match="shared_store_required_on_vercel"), TestClient(create_app()):
        pass
