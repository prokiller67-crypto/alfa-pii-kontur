from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass, field

from starlette.concurrency import run_in_threadpool

from .detector import Detector, Kind
from .masking import mask, remask_exact, restore_exact, restore_tokens
from .vault import Vault


class ServiceError(Exception):
    def __init__(self, status: int, code: str):
        self.status, self.code = status, code


@dataclass(frozen=True)
class Policy:
    tenant: str
    enabled: bool = True
    types: frozenset[Kind] = frozenset(Kind)
    restore: bool = True
    mode: str = "shape"
    min_types: int = 1
    requires: dict[Kind, frozenset[Kind]] = field(default_factory=dict)

    @property
    def fingerprint(self) -> str:
        value = {"types": sorted(self.types), "restore": self.restore, "mode": self.mode,
                 "min_types": self.min_types,
                 "requires": {k: sorted(v) for k, v in sorted(self.requires.items())}}
        return hashlib.sha256(json.dumps(value, sort_keys=True).encode()).hexdigest()


class Processor:
    def __init__(self, detector: Detector, vault: Vault):
        self.detector, self.vault = detector, vault

    def _existing(self, text: str, record: dict, policy: Policy, *, mask_only: bool = False) -> dict:
        if record["policy"] != policy.fingerprint:
            raise ServiceError(409, "policy_changed_use_new_payload_id")
        digest = self.vault.digest(text)
        if digest == record["original_hash"]:
            return {"result": remask_exact(text, record["replacements"]), "operation": "mask_retry",
                    "types": record["types"], "spans": record["spans"], "mode": record["mode"]}
        if digest == record["masked_hash"] and not mask_only:
            if not policy.restore:
                raise ServiceError(403, "restoration_disabled")
            return {"result": restore_exact(text, record["replacements"]), "operation": "restore",
                    "types": record["types"], "spans": [], "mode": record["mode"]}
        raise ServiceError(409, "payload_id_conflict")

    async def process(self, text: str, payload_id: str, policy: Policy, *, mask_only: bool = False) -> dict:
        if not policy.enabled:
            raise ServiceError(403, "system_disabled")
        record = await self.vault.get(policy.tenant, payload_id)
        if record is not None:
            return self._existing(text, record, policy, mask_only=mask_only)
        if "⟦" in text:
            raise ServiceError(410, "mapping_missing_or_expired")
        detected = await run_in_threadpool(self.detector.detect, text)
        enabled = tuple(s for s in detected if s.kind in policy.types)
        present = {s.kind for s in enabled}
        selected = tuple(s for s in enabled if policy.requires.get(s.kind, frozenset()) <= present)
        if len({s.kind for s in selected}) < policy.min_types:
            selected = ()
        result, replacements = mask(text, selected, policy.mode)
        types = sorted({s.kind.value for s in selected})
        spans = [{"start": s.start, "end": s.end, "type": s.kind.value, "source": s.source} for s in selected]
        record = {"original_hash": self.vault.digest(text), "masked_hash": self.vault.digest(result),
                  "replacements": replacements, "types": types, "spans": spans,
                  "mode": policy.mode, "policy": policy.fingerprint}
        if not await self.vault.put(policy.tenant, payload_id, record):
            # Another worker completed the same id while detection was running.
            winner = await self.vault.get(policy.tenant, payload_id)
            if winner is None:
                raise ServiceError(503, "mapping_unavailable_retry")
            return self._existing(text, winner, policy, mask_only=mask_only)
        return {"result": result, "operation": "mask", "types": types, "spans": spans, "mode": policy.mode}

    async def restore(self, text: str, payload_id: str, policy: Policy) -> dict:
        if not policy.enabled or not policy.restore:
            raise ServiceError(403, "restoration_disabled")
        record = await self.vault.get(policy.tenant, payload_id)
        if record is None:
            raise ServiceError(410, "mapping_missing_or_expired")
        if record["policy"] != policy.fingerprint:
            raise ServiceError(409, "policy_changed_use_new_payload_id")
        if record["mode"] == "token":
            result = restore_tokens(text, record["replacements"])
        elif self.vault.digest(text) == record["masked_hash"]:
            result = restore_exact(text, record["replacements"])
        else:
            raise ServiceError(409, "exact_mask_required")
        return {"result": result, "operation": "restore", "types": record["types"], "spans": [], "mode": record["mode"]}
