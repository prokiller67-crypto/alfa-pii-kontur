"""Real HTTP paired requests. Runs only against an explicitly provided URL.

Local generator and service compete for the same computer. Closed-loop throughput
is not an independent 5-minute organizer test. Report unique and reused text separately.
"""

import argparse
import asyncio
import json
import platform
import time
import uuid
from collections import Counter
from pathlib import Path

import aiohttp


async def run(args):
    latencies, statuses = [], Counter()
    roundtrip_ok = 0
    run_id = uuid.uuid4().hex
    queue = asyncio.Queue()
    for i in range(args.pairs):
        queue.put_nowait(i)
    connector = aiohttp.TCPConnector(limit=args.concurrency)
    async with aiohttp.ClientSession(base_url=args.url, connector=connector,
                                     timeout=aiohttp.ClientTimeout(total=10),
                                     json_serialize=lambda value: json.dumps(value, ensure_ascii=False)) as client:
        async def post(payload, payload_id):
            start = time.perf_counter()
            try:
                async with client.post("/process", json={"payload": payload, "payload_id": payload_id}) as response:
                    statuses[str(response.status)] += 1
                    return (await response.json()).get("result") if response.status == 200 else None
            except (aiohttp.ClientError, TimeoutError, ValueError):
                statuses["transport_error"] += 1
                return None
            finally:
                latencies.append((time.perf_counter() - start) * 1000)
        async def worker():
            nonlocal roundtrip_ok
            while not queue.empty():
                i = queue.get_nowait()
                prefix = f"Обращение {i}. " if args.unique else ""
                text = prefix + "Клиент Иванов Иван Иванович, паспорт 4509 123456; email: demo@example.org; телефон: +7 999 123-45-67"
                payload_id = f"{run_id}-{i}"
                masked = await post(text, payload_id)
                if masked is not None:
                    restored = await post(masked, payload_id)
                    roundtrip_ok += restored == text and "demo@example.org" not in masked
                queue.task_done()
        start = time.perf_counter()
        await asyncio.gather(*(worker() for _ in range(args.concurrency)))
        elapsed = time.perf_counter() - start
    ordered = sorted(latencies)
    def percentile(p):
        return round(ordered[min(int((len(ordered) - 1) * p), len(ordered) - 1)], 2)
    result = {"kind": "local real HTTP; closed-loop; generator and server share hardware",
              "generator": "aiohttp + uvloop (when available)",
              "machine": platform.machine(), "unique_inputs": args.unique, "concurrency": args.concurrency,
              "pairs_requested": args.pairs, "requests_completed": len(latencies), "seconds": round(elapsed, 3),
              "rps": round(len(latencies) / elapsed, 1), "statuses": dict(statuses),
              "latency_ms": {"p50": percentile(.5), "p95": percentile(.95), "p99": percentile(.99), "max": round(max(ordered), 2)},
              "exact_and_masked_roundtrip_pairs": roundtrip_ok}
    path = Path(args.output)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(result, ensure_ascii=False, indent=2) + "\n")
    print(json.dumps(result, ensure_ascii=False, indent=2))


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--url", default="http://127.0.0.1:8090")
    parser.add_argument("--pairs", type=int, default=2000)
    parser.add_argument("--concurrency", type=int, default=32)
    parser.add_argument("--unique", action="store_true")
    parser.add_argument("--output", default="artifacts/http-benchmark.json")
    args = parser.parse_args()
    if args.pairs < 1 or args.concurrency < 1:
        parser.error("pairs and concurrency must be positive")
    try:
        import uvloop
    except ImportError:
        asyncio.run(run(args))
    else:
        uvloop.run(run(args))
