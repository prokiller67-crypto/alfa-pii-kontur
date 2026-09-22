"""Large synthetic text smoke: reports characters honestly, not assumed LLM tokens."""
import argparse
import json
import time
import uuid
from pathlib import Path

import httpx

parser = argparse.ArgumentParser()
parser.add_argument("--url", default="http://127.0.0.1:8090")
parser.add_argument("--lines", type=int, default=6000)
args = parser.parse_args()
text = "\n".join(f"Обращение {i}. Клиент Иванов Иван Иванович; email: user{i}@example.org." for i in range(args.lines))
payload_id = "large-" + uuid.uuid4().hex
with httpx.Client(base_url=args.url, timeout=30) as client:
    start = time.perf_counter()
    response = client.post("/process", json={"payload": text, "payload_id": payload_id})
    mask_seconds = time.perf_counter() - start
    result = {"characters": len(text), "lines": args.lines, "tokens": "not measured; tokenizer unspecified",
              "mask_seconds": round(mask_seconds, 3), "mask_status": response.status_code}
    if response.status_code == 200:
        masked = response.json()["result"]
        start = time.perf_counter()
        back = client.post("/process", json={"payload": masked, "payload_id": payload_id})
        result.update(restore_seconds=round(time.perf_counter() - start, 3), restore_status=back.status_code,
                      exact_roundtrip=back.status_code == 200 and back.json()["result"] == text,
                      email_domain_leaked="example.org" in masked, name_leaked="Иванов" in masked)
Path("artifacts/large-text.json").write_text(json.dumps(result, ensure_ascii=False, indent=2) + "\n")
print(json.dumps(result, ensure_ascii=False, indent=2))
