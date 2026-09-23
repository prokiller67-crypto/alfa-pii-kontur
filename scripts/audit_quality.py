"""Evaluate a frozen synthetic split and optionally the real public API.

Span F1 is a local diagnostic, not the unspecified organizer Levenshtein metric.
Public checks compare the exact expected partial mask and exact restoration.
"""

import argparse
import asyncio
import hashlib
import json
import ssl
import sys
import uuid
from collections import Counter
from pathlib import Path

import aiohttp
import certifi

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from benchmarks.fresh_cases import DEVELOPMENT, HOLDOUT  # noqa: E402
from pii_proxy.detector import Detector, Kind, Span  # noqa: E402
from pii_proxy.masking import mask, restore_exact  # noqa: E402
from scripts.evaluate import parse  # noqa: E402


def score(counts):
    tp, fp, fn = (counts[k] for k in ("tp", "fp", "fn"))
    return {"tp": tp, "fp": fp, "fn": fn,
            "precision": tp / max(tp + fp, 1), "recall": tp / max(tp + fn, 1),
            "f1": 2 * tp / max(2 * tp + fp + fn, 1)}


async def audit(args):
    cases = DEVELOPMENT if args.split == "development" else HOLDOUT
    dataset_hash = hashlib.sha256(json.dumps(cases, ensure_ascii=False).encode()).hexdigest()
    detector = Detector(cache_size=0)
    counts, per_type, errors, public = Counter(), {}, [], Counter()
    run_id = uuid.uuid4().hex
    async with aiohttp.ClientSession(timeout=aiohttp.ClientTimeout(total=10),
                                    connector=aiohttp.TCPConnector(ssl=ssl.create_default_context(cafile=certifi.where()))) as client:
        for name, marked in cases:
            text, expected = parse(marked)
            actual_spans = detector.detect(text)
            actual = {(s.start, s.end, s.kind.value) for s in actual_spans}
            counts.update(tp=len(actual & expected), fp=len(actual - expected), fn=len(expected - actual))
            counts["exact_documents"] += actual == expected
            for kind in {s[2] for s in expected | actual}:
                e, a = {s for s in expected if s[2] == kind}, {s for s in actual if s[2] == kind}
                per_type.setdefault(kind, Counter()).update(tp=len(a & e), fp=len(a - e), fn=len(e - a))
            masked, mappings = mask(text, actual_spans, "partial")
            counts["roundtrip_ok"] += restore_exact(masked, mappings) == text
            gold_spans = tuple(Span(start, end, Kind(kind)) for start, end, kind in sorted(expected))
            gold_mask, _ = mask(text, gold_spans, "partial")
            if actual != expected:
                errors.append({"case": name, "missing": sorted(expected - actual), "extra": sorted(actual - expected)})
            if args.url:
                payload_id = f"audit-{run_id}-{name}"
                try:
                    async with client.post(args.url.rstrip("/") + "/process", json={"payload": text, "payload_id": payload_id}) as response:
                        public[f"http_{response.status}"] += 1
                        body = await response.json()
                        result = body.get("result")
                    public["expected_mask"] += result == gold_mask
                    if not isinstance(result, str):
                        public["invalid_mask_response"] += 1
                        continue
                    async with client.post(args.url.rstrip("/") + "/process", json={"payload": result, "payload_id": payload_id}) as response:
                        public[f"http_{response.status}"] += 1
                        restored = (await response.json()).get("result")
                    public["exact_restore"] += restored == text
                    if result != gold_mask or restored != text:
                        public["failed_cases"] += 1
                except (aiohttp.ClientError, TimeoutError, ValueError) as exc:
                    public["transport_error"] += 1
                    errors.append({"case": name, "public_transport_error": type(exc).__name__})
    report = {"dataset": "assistant-labelled synthetic audit; not human-independent or organizer accuracy",
              "split": args.split, "dataset_sha256": dataset_hash, "cases": len(cases),
              "exact_span": score(counts), "exact_documents": counts["exact_documents"],
              "roundtrip_ok": counts["roundtrip_ok"], "per_type": {k: score(v) for k, v in sorted(per_type.items())},
              "errors": errors, "public_url": args.url, "public": dict(public)}
    Path(args.output).write_text(json.dumps(report, ensure_ascii=False, indent=2) + "\n")
    print(json.dumps(report, ensure_ascii=False, indent=2))


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--split", choices=["development", "holdout"], required=True)
    parser.add_argument("--url")
    parser.add_argument("--output", required=True)
    asyncio.run(audit(parser.parse_args()))
