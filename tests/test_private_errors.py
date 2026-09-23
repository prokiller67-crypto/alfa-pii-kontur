"""Third-party exceptions can contain PII and must not enter HTTP or audit output."""

import httpx
import pytest

import pii_proxy.app as app_module
from pii_proxy.detector import Detector
from pii_proxy.service import Processor
from pii_proxy.vault import MemoryStore, Vault


class FailingStore(MemoryStore):
    async def get(self, key):
        raise RuntimeError("database failure for secret@example.org private-payload-id")

    async def ping(self):
        raise RuntimeError("database failure for secret@example.org private-payload-id")


@pytest.mark.parametrize("path", ["/process", "/readyz"])
async def test_dependency_error_keeps_pii_and_traceback_out_of_response_and_log(path, caplog, monkeypatch):
    processor = Processor(Detector(use_ner=False), Vault(FailingStore(), b"t" * 32))
    app = app_module.create_app(processor, policies={}, local_demo=True)
    monkeypatch.setattr(app_module.logger, "propagate", True)
    transport = httpx.ASGITransport(app=app, client=("127.0.0.1", 123))
    async with httpx.AsyncClient(transport=transport, base_url="http://test") as client:
        with caplog.at_level("INFO", logger="pii_proxy.audit"):
            if path == "/process":
                response = await client.post(path, json={"payload": "secret@example.org", "payload_id": "private-payload-id"})
            else:
                response = await client.get(path)
    assert response.status_code == 503
    assert "secret@example.org" not in response.text + caplog.text
    assert "private-payload-id" not in response.text + caplog.text
    assert "exception_type=RuntimeError" in caplog.text
    audit_records = [r for r in caplog.records if r.name == "pii_proxy.audit"]
    assert audit_records
    assert not any(r.exc_info or r.exc_text for r in audit_records)
