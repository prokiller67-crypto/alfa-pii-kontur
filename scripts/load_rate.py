"""External open-loop paired HTTP load; no retries hide overload.

New pairs are scheduled at rate/2, independent of previous responses. Restoration
follows a successful mask. Report actual attempts/rates and skipped arrivals;
an overloaded/aborted run can never pass. Inputs are synthetic and varied but
template-derived; this is not the organizer corpus or its official client.
"""

import argparse
import asyncio
import json
import math
import ssl
import time
import uuid
from collections import Counter
from pathlib import Path

import aiohttp
import certifi

TEMPLATES = (
    "Клиент Андрей Морозов, паспорт 5416 839201; почта: load-{i}@example.org",
    "Передайте документы Ольге Захаровой. Телефон: +7 (913) 765-43-21.",
    "Дата рождения: 19.04.1988; место рождения: Омск; гражданство: Россия.",
    "Номер карты: 5105 1051 0510 5100; CVV: 456; PIN: 8291; держатель карты: ANDREY MOROZOV",
    "Адрес регистрации: г. Тюмень, ул. Республики, д. 15, кв. 24; email: load-{i}@example.net",
    "Обращение принято, доставка завтра. Номер заказа {i}; сумма 2400 рублей.",
)


def percentiles(values):
    ordered = sorted(values)
    if not ordered:
        return {}
    return {name: round(ordered[min(math.ceil(len(ordered) * p) - 1, len(ordered) - 1)], 3)
            for name, p in (("p50", .5), ("p95", .95), ("p99", .99), ("max", 1))}


async def run(args):
    counters, statuses = Counter(), Counter()
    latencies, scheduler_lags = [], []
    buckets = {}
    run_id = uuid.uuid4().hex
    pending = set()
    abort_reason = None
    consecutive_errors = 0
    warmup = None
    start = time.perf_counter()
    deadline = start + args.seconds
    connector = aiohttp.TCPConnector(limit=args.max_inflight * 2,
                                    ssl=ssl.create_default_context(cafile=certifi.where()))
    async with aiohttp.ClientSession(connector=connector, timeout=aiohttp.ClientTimeout(total=10)) as client:
        async def post(payload, payload_id):
            nonlocal abort_reason, consecutive_errors
            sent = time.perf_counter()
            counters["requests_attempted"] += 1
            bucket = buckets.setdefault(int(sent - start), Counter())
            bucket["sent"] += 1
            try:
                async with client.post(args.url.rstrip("/") + "/process", json={"payload": payload, "payload_id": payload_id}) as response:
                    statuses[str(response.status)] += 1
                    body = await response.json() if response.status == 200 else {}
                    result = body.get("result") if isinstance(body, dict) else None
                    valid = response.status == 200 and isinstance(result, str)
                    if valid:
                        counters["http_success"] += 1
                        bucket["success"] += 1
                        consecutive_errors = 0
                        return result
                    counters["request_errors"] += 1
                    bucket["errors"] += 1
                    consecutive_errors += 1
            except (aiohttp.ClientError, TimeoutError, ValueError) as exc:
                statuses[type(exc).__name__] += 1
                counters["request_errors"] += 1
                bucket["errors"] += 1
                consecutive_errors += 1
            finally:
                latencies.append((time.perf_counter() - sent) * 1000)
            if consecutive_errors >= 5:
                abort_reason = abort_reason or "five_consecutive_invalid_responses"
            if counters["request_errors"] >= 50:
                abort_reason = abort_reason or "fifty_invalid_responses"
            return None

        async def pair(index, scheduled):
            scheduler_lags.append(max(0, time.perf_counter() - scheduled) * 1000)
            template = TEMPLATES[index % len(TEMPLATES)]
            text_index = index if args.text_mode == "unique" else index % len(TEMPLATES)
            text = f"Тест {text_index}. " + template.format(i=text_index)
            payload_id = f"load-{run_id}-{index}"
            masked = await post(text, payload_id)
            if masked is None:
                return
            # Template 6 intentionally contains no PII; the others must change.
            counters["expected_mask_presence"] += (masked != text) == (index % len(TEMPLATES) != 5)
            restored = await post(masked, payload_id)
            if restored == text:
                counters["exact_pairs"] += 1
            elif restored is not None:
                counters["wrong_restore"] += 1

        if args.warmup_pairs:
            await asyncio.gather(*(pair(i, time.perf_counter()) for i in range(args.warmup_pairs)))
            warmup = {"pairs": args.warmup_pairs, "counters": dict(counters),
                      "statuses": dict(statuses), "seconds": time.perf_counter() - start}
            if counters["exact_pairs"] != args.warmup_pairs:
                abort_reason = "warmup_failed"
            counters.clear()
            statuses.clear()
            latencies.clear()
            scheduler_lags.clear()
            buckets.clear()
            start = time.perf_counter()
            deadline = start + args.seconds
        scheduled_pairs = math.floor(args.rate * args.seconds / 2)
        for index in range(scheduled_pairs):
            scheduled = start + index * 2 / args.rate
            await asyncio.sleep(max(0, scheduled - time.perf_counter()))
            if abort_reason:
                break
            if time.perf_counter() >= deadline:
                break
            counters["arrivals"] += 1
            if len(pending) >= args.max_inflight:
                counters["dropped_arrivals"] += 1
                if counters["dropped_arrivals"] >= 50:
                    abort_reason = "client_inflight_limit_reached"
                    break
                continue
            counters["pairs_started"] += 1
            task = asyncio.create_task(pair(index, scheduled))
            pending.add(task)
            task.add_done_callback(pending.discard)
        injection_seconds = time.perf_counter() - start
        if pending:
            await asyncio.gather(*pending)
        elapsed = time.perf_counter() - start
    report = {"method": "open-loop pair arrivals at rate/2; restore follows mask; no retries",
              "data": "six rotating synthetic templates; NOT organizer corpus",
              "text_mode": args.text_mode, "unique_payload_ids": True,
              "warmup": warmup,
              "server_url": args.url, "target_http_rps": args.rate, "target_seconds": args.seconds,
              "max_inflight_pairs": args.max_inflight, "abort_reason": abort_reason,
              "injection_seconds": round(injection_seconds, 3), "total_seconds_with_drain": round(elapsed, 3),
              "counters": dict(counters), "statuses": dict(statuses),
              "successful_rps_with_drain": round(counters["http_success"] / elapsed, 2),
              "request_latency_ms": percentiles(latencies), "scheduler_lag_ms": percentiles(scheduler_lags),
              "per_second_sent": {k: dict(v) for k, v in sorted(buckets.items())}}
    report["clean_target_run"] = (not abort_reason and counters["pairs_started"] == scheduled_pairs
                                  and counters["exact_pairs"] == scheduled_pairs
                                  and counters["expected_mask_presence"] == scheduled_pairs
                                  and not counters["request_errors"] and not counters["dropped_arrivals"])
    Path(args.output).write_text(json.dumps(report, ensure_ascii=False, indent=2) + "\n")
    print(json.dumps({k: v for k, v in report.items() if k != "per_second_sent"}, ensure_ascii=False, indent=2), flush=True)


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--url", required=True)
    parser.add_argument("--rate", type=float, required=True)
    parser.add_argument("--seconds", type=float, default=20)
    parser.add_argument("--max-inflight", type=int, default=256)
    parser.add_argument("--text-mode", choices=["unique", "repeated"], default="unique")
    parser.add_argument("--warmup-pairs", type=int, default=0)
    parser.add_argument("--output", required=True)
    args = parser.parse_args()
    if args.rate <= 0 or args.seconds <= 0 or args.max_inflight < 1:
        parser.error("rate, seconds and max-inflight must be positive")
    if not 0 <= args.warmup_pairs <= 128:
        parser.error("warmup-pairs must be between 0 and 128")
    try:
        import uvloop
    except ImportError:
        asyncio.run(run(args))
    else:
        uvloop.run(run(args))
