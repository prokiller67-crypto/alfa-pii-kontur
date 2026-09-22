"""Opt-in live contract test; deletes only the unique synthetic records it creates."""

import asyncio
import os
import uuid

import pytest

from pii_proxy.detector import Detector
from pii_proxy.postgres import PostgresStore
from pii_proxy.service import Policy, Processor
from pii_proxy.vault import Vault


@pytest.mark.skipif(not os.environ.get("PII_TEST_POSTGRES_URL"), reason="requires isolated PostgreSQL test database")
async def test_postgres_atomicity_encryption_expiry_and_cross_instance_restore():
    stores = [PostgresStore(os.environ["PII_TEST_POSTGRES_URL"]) for _ in range(2)]
    vaults = [Vault(s, b"t" * 32) for s in stores]
    payload_id = "sql-contract-" + str(uuid.uuid4())
    expiry_id = payload_id + "-ttl"
    policy = Policy("integration-test", mode="token")
    try:
        for store in stores:
            assert await store.ping()
        processors = [Processor(Detector(use_ner=False), v) for v in vaults]
        original = "Email: synthetic-sql-test@example.org\n"
        results = await asyncio.gather(*(processors[i % 2].process(original, payload_id, policy) for i in range(12)))
        assert len({r["result"] for r in results}) == 1
        assert (await processors[1].process(results[0]["result"], payload_id, policy))["result"] == original
        assert (await processors[1].process(original, payload_id, policy))["result"] == results[0]["result"]
        ciphertext = await stores[0].get(vaults[0].key(policy.tenant, payload_id))
        assert ciphertext and original.encode() not in ciphertext

        expiring = Vault(stores[0], b"t" * 32, ttl=1)
        assert await expiring.put(policy.tenant, expiry_id, {"value": "first"})
        assert not await expiring.put(policy.tenant, expiry_id, {"value": "overwrite"})
        await asyncio.sleep(1.1)
        assert await expiring.get(policy.tenant, expiry_id) is None
        assert await expiring.put(policy.tenant, expiry_id, {"value": "after-expiry"})
        assert await expiring.get(policy.tenant, expiry_id) == {"value": "after-expiry"}
    finally:
        if stores[0]._opened:
            async with stores[0].pool.connection() as conn:
                await conn.execute("DELETE FROM pii_state WHERE key = ANY(%s)",
                                   ([vaults[0].key(policy.tenant, p) for p in (payload_id, expiry_id)],))
        for store in stores:
            await store.close()
