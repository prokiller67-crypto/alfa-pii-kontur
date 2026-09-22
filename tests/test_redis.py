import pytest

from pii_proxy.detector import Detector
from pii_proxy.service import Policy, Processor
from pii_proxy.vault import RedisStore, Vault


async def test_shared_redis_protocol_between_distinct_processors():
    # Protocol simulation, complemented by the real Docker/Redis HTTP benchmark.
    import fakeredis.aioredis
    server = fakeredis.FakeServer()
    stores = [RedisStore("redis://unused") for _ in range(2)]
    for store in stores:
        await store.client.aclose()
        store.client = fakeredis.aioredis.FakeRedis(server=server)
    first, second = [Processor(Detector(use_ner=False), Vault(store, b"k" * 32)) for store in stores]
    policy = Policy("tenant", mode="token")
    masked = await first.process("somebody@example.org", "pair", policy)
    assert (await second.process(masked["result"], "pair", policy))["result"] == "somebody@example.org"
    assert (await second.process("somebody@example.org", "pair", policy))["result"] == masked["result"]
    for store in stores:
        await store.close()


async def test_ciphertext_bound_to_tenant_and_id():
    from pii_proxy.vault import MemoryStore
    vault = Vault(MemoryStore(), b"k" * 32)
    await vault.put("a", "1", {"secret": "example"})
    ciphertext = vault.store.entries[vault.key("a", "1")]
    await vault.store.put_if_absent(vault.key("b", "1"), ciphertext, 1800)
    from cryptography.exceptions import InvalidTag
    with pytest.raises(InvalidTag):
        await vault.get("b", "1")
