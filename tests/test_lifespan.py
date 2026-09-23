"""Application-owned stores are released even when lifespan exits abnormally."""

import asyncio
from types import SimpleNamespace

import pytest

import pii_proxy.app as app_module
from pii_proxy.vault import MemoryStore


@pytest.mark.parametrize("supplied", [False, True])
@pytest.mark.parametrize("exit_error", [None, RuntimeError, asyncio.CancelledError])
async def test_lifespan_respects_store_ownership_on_every_exit(monkeypatch, supplied, exit_error):
    store = MemoryStore()
    await store.put_if_absent("pending", b"encrypted-state", 60)
    processor = SimpleNamespace(vault=SimpleNamespace(store=store))
    monkeypatch.setattr(app_module, "_create_processor", lambda _checker: processor)
    app = app_module.create_app(processor if supplied else None, policies={}, local_demo=False)

    async def run_lifespan():
        async with app.router.lifespan_context(app):
            assert await store.get("pending") == b"encrypted-state"
            if exit_error:
                raise exit_error("interrupted lifespan")

    if exit_error:
        with pytest.raises(exit_error, match="interrupted lifespan"):
            await run_lifespan()
    else:
        await run_lifespan()

    expected = b"encrypted-state" if supplied else None
    assert await store.get("pending") == expected
