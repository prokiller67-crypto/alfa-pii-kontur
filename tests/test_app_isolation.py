"""Global route functions must still use the state of their own application."""

import httpx

from pii_proxy.app import create_app
from pii_proxy.detector import Detector
from pii_proxy.service import Policy, Processor
from pii_proxy.vault import MemoryStore, Vault


async def test_app_instances_keep_auth_mappings_and_metrics_separate():
    apps = [create_app(
        Processor(Detector(use_ner=False), Vault(MemoryStore(), b"t" * 32)),
        policies={"tenant": (Policy("tenant"), key)}, local_demo=False,
    ) for key in ("key-a", "key-b")]
    headers_a = {"x-system-id": "tenant", "x-api-key": "key-a"}
    headers_b = {"x-system-id": "tenant", "x-api-key": "key-b"}
    async with (
        httpx.AsyncClient(transport=httpx.ASGITransport(app=apps[0]), base_url="http://a") as a,
        httpx.AsyncClient(transport=httpx.ASGITransport(app=apps[1]), base_url="http://b") as b,
    ):
        body_a = {"payload": "first@example.org", "payload_id": "same-id"}
        body_b = {"payload": "second@example.org", "payload_id": "same-id"}
        masked_a = await a.post("/process", json=body_a, headers=headers_a)
        assert masked_a.status_code == 200
        assert (await b.post("/process", json=body_a, headers=headers_a)).status_code == 401
        masked_b = await b.post("/process", json=body_b, headers=headers_b)
        assert masked_b.status_code == 200
        restored = await a.post("/process", json={**body_a, "payload": masked_a.json()["result"]}, headers=headers_a)
        assert restored.json() == {"result": body_a["payload"]}
        metrics_a = await a.get("/metrics", headers=headers_a)
        metrics_b = await b.get("/metrics", headers=headers_b)
        assert 'operation="restore",status="200"' in metrics_a.text
        assert 'operation="restore",status="200"' not in metrics_b.text
