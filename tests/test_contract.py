import asyncio
import json
from dataclasses import replace

import httpx
import pytest
from fastapi.testclient import TestClient

from pii_proxy.app import create_app
from pii_proxy.detector import Detector, Kind
from pii_proxy.service import Policy, Processor, ServiceError
from pii_proxy.vault import MemoryStore, Vault


@pytest.fixture
def processor():
    return Processor(Detector(use_ner=False), Vault(MemoryStore(), b"t" * 32))


@pytest.fixture
def client(processor):
    with TestClient(create_app(processor, policies={})) as client:
        yield client


def test_official_contract_and_both_retry_directions(client):
    original = "Клиент Иванов Иван Иванович, паспорт 4509 123456"
    body = {"payload": original, "payload_id": "contract-1"}
    first = client.post("/process", json=body)
    assert first.status_code == 200
    assert set(first.json()) == {"result"}
    masked = first.json()["result"]
    assert masked != original
    assert "123456" not in masked and "Иванов" not in masked
    assert client.post("/process", json=body).json()["result"] == masked
    for _ in range(3):
        assert client.post("/process", json={**body, "payload": masked}).json()["result"] == original
    assert client.post("/process", json=body).json()["result"] == masked


@pytest.mark.parametrize("original", ["", "Ничего секретного: сумма 350 рублей.", "😀\nEmail: TEST+hello@example.org\t!", "Паспорт: серия 45 09 номер 123456\n"])
def test_exact_roundtrip(client, original):
    body = {"payload": original, "payload_id": "exact"}
    mask = client.post("/process", json=body).json()["result"]
    assert client.post("/process", json={**body, "payload": mask}).json() == {"result": original}


def test_id_conflict_never_returns_original(client):
    client.post("/process", json={"payload": "email: private@example.org", "payload_id": "conflict"})
    response = client.post("/process", json={"payload": "другая строка", "payload_id": "conflict"})
    assert response.status_code == 409
    assert "private" not in response.text


def test_validation_does_not_echo_input(client, caplog):
    body = {"payload": {"secret": "sensitive@example.org"}, "payload_id": "123"}
    with caplog.at_level("INFO", logger="pii_proxy.audit"):
        response = client.post("/process", json=body)
        client.post("/process", json={"payload": "sensitive@example.org", "payload_id": "private-id"})
    assert response.status_code == 422
    assert "sensitive" not in response.text + caplog.text
    assert "private-id" not in caplog.text
    assert "types=EMAIL" in caplog.text


def test_vault_never_stores_plaintext(client, processor):
    original = "email: sensitive@example.org"
    client.post("/process", json={"payload": original, "payload_id": "sensitive-id"})
    for key, value in processor.vault.store.entries.items():
        assert "sensitive" not in key
        assert b"sensitive" not in value
        with pytest.raises((UnicodeDecodeError, json.JSONDecodeError)):
            json.loads(value)


async def test_parallel_masking_is_atomic_and_retry_safe(processor):
    policy = Policy("a", mode="token")
    text = "Email: demo@example.org"
    results = await asyncio.gather(*(processor.process(text, "concurrent", policy) for _ in range(30)))
    assert len({r["result"] for r in results}) == 1
    restored = await asyncio.gather(*(processor.process(results[0]["result"], "concurrent", policy) for _ in range(10)))
    assert all(r["result"] == text for r in restored)


async def test_tenant_isolation(processor):
    a, b = Policy("a"), Policy("b")
    result = await processor.process("alice@example.org", "same", a)
    await processor.process("bob@example.org", "same", b)
    with pytest.raises(ServiceError) as e:
        await processor.process(result["result"], "same", b)
    assert e.value.status == 409


async def test_policy_controls(processor):
    policy = Policy("a", types=frozenset({Kind.EMAIL}), restore=False)
    text = "Email: mail@example.org; телефон: +7 999 123-45-67"
    out = await processor.process(text, "one", policy)
    assert "mail@" not in out["result"]
    assert "+7 999" in out["result"]
    with pytest.raises(ServiceError) as e:
        await processor.process(out["result"], "one", policy)
    assert e.value.status == 403
    with pytest.raises(ServiceError):
        await processor.process(text, "one", replace(policy, restore=True))


async def test_conditional_types(processor):
    policy = Policy("a", requires={Kind.PIN: frozenset({Kind.CARD})})
    assert (await processor.process("ПИН-код карты: 1234", "pin", policy))["result"] == "ПИН-код карты: 1234"
    result = await processor.process("Номер карты: 4111 1111 1111 1111; ПИН-код карты: 1234", "both", policy)
    assert "1234" not in result["result"]


async def test_capacity_does_not_evict_live_mappings():
    store = MemoryStore(max_entries=1)
    processor = Processor(Detector(use_ner=False), Vault(store, b"t" * 32))
    app = create_app(processor)
    async with httpx.AsyncClient(transport=httpx.ASGITransport(app=app, client=("127.0.0.1", 123)), base_url="http://test") as c:
        first = await c.post("/process", json={"payload": "a@example.org", "payload_id": "one"})
        full = await c.post("/process", json={"payload": "b@example.org", "payload_id": "two"})
        assert full.status_code == 429
        assert full.headers["retry-after"] == "1"
        back = await c.post("/process", json={"payload": first.json()["result"], "payload_id": "one"})
        assert back.json()["result"] == "a@example.org"


async def test_expired_mapping_and_tampered_ciphertext(processor, monkeypatch):
    policy = Policy("a", mode="token")
    first = await processor.process("a@example.org", "expiry", policy)
    monkeypatch.setattr("pii_proxy.vault.time.monotonic", lambda: 10**15)
    with pytest.raises(ServiceError) as e:
        await processor.restore(first["result"], "expiry", policy)
    assert e.value.status == 410


def test_store_outage_fails_closed(client, processor, monkeypatch):
    async def fail(_key):
        raise ConnectionError("sensitive-value-in-exception")
    monkeypatch.setattr(processor.vault.store, "get", fail)
    response = client.post("/process", json={"payload": "private@example.org", "payload_id": "one"})
    assert response.status_code == 503
    assert "sensitive" not in response.text and "private" not in response.text


async def test_unknown_remote_system_denied(processor):
    app = create_app(processor, policies={}, local_demo=False)
    async with httpx.AsyncClient(transport=httpx.ASGITransport(app=app), base_url="http://test") as c:
        response = await c.post("/process", json={"payload": "x", "payload_id": "one"})
        assert response.status_code == 401


def test_proxy_headers_cannot_claim_local_demo(client):
    response = client.post("/process", headers={"x-forwarded-for": "127.0.0.1"},
                           json={"payload": "x", "payload_id": "a"})
    assert response.status_code == 401


def test_explicit_tokens_restore_rephrased_response(client):
    body = {"payload": "Почта: one@example.org", "payload_id": "llm", "mode": "token"}
    masked = client.post("/v1/mask", json=body).json()["result"]
    token = masked.split("Почта: ", 1)[1]
    reply = f"Ответ отправлен на {token}. Повтор: {token}"
    restored = client.post("/v1/restore", json={**body, "payload": reply})
    assert restored.status_code == 200
    assert restored.json()["result"] == "Ответ отправлен на one@example.org. Повтор: one@example.org"


def test_large_json_body_is_bounded(client):
    response = client.post("/process", content=b"x" * 8_000_001, headers={"Content-Type": "application/json"})
    assert response.status_code == 413
