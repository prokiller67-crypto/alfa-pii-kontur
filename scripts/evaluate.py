"""Transparent dev evaluation: exact typed spans, sensitive-character coverage, exact roundtrip."""

import argparse
import json
import re
import sys
import time
from collections import Counter
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from benchmarks.cases import CASES  # noqa: E402
from pii_proxy.detector import Detector  # noqa: E402
from pii_proxy.masking import mask, restore_exact  # noqa: E402


def parse(marked):
    text, spans, cursor = "", [], 0
    for m in re.finditer(r"\[\[(\w+)\|(.+?)\]\]", marked):
        text += marked[cursor:m.start()]
        start = len(text)
        text += m[2]
        spans.append((start, len(text), m[1]))
        cursor = m.end()
    return text + marked[cursor:], set(spans)


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--challenge", action="store_true")
    args = parser.parse_args()
    cases = CASES
    if args.challenge:
        from benchmarks.challenge_cases import CASES as challenge
        cases = challenge
    detector = Detector(cache_size=0)
    counts, categories, errors, timings = Counter(), {}, [], []
    for name, marked in cases:
        text, expected = parse(marked)
        t = time.perf_counter()
        spans = detector.detect(text)
        timings.append((time.perf_counter() - t) * 1000)
        actual = {(s.start, s.end, s.kind.value) for s in spans}
        counts.update(tp=len(actual & expected), fp=len(actual - expected), fn=len(expected - actual))
        exp_chars = {i for a, b, _ in expected for i in range(a, b) if text[i].isalnum()}
        act_chars = {i for a, b, _ in actual for i in range(a, b) if text[i].isalnum()}
        counts.update(covered=len(exp_chars & act_chars), sensitive=len(exp_chars), extra=len(act_chars - exp_chars))
        for kind in {s[2] for s in expected | actual}:
            cat = categories.setdefault(kind, Counter())
            e, a = {s for s in expected if s[2] == kind}, {s for s in actual if s[2] == kind}
            cat.update(tp=len(a & e), fp=len(a - e), fn=len(e - a))
        for mode in ("shape", "partial", "token"):
            masked, replacements = mask(text, spans, mode)
            counts["roundtrips"] += 1
            counts["roundtrip_ok"] += restore_exact(masked, replacements) == text
        if actual != expected:
            errors.append({"case": name, "missing": sorted(expected - actual), "extra": sorted(actual - expected)})
    def scores(c):
        precision = c["tp"] / max(c["tp"] + c["fp"], 1)
        recall = c["tp"] / max(c["tp"] + c["fn"], 1)
        return {**c, "precision": round(precision, 4), "recall": round(recall, 4),
                "f1": round(2 * precision * recall / max(precision + recall, 1e-9), 4)}
    report = {"dataset": "hand-labelled synthetic development set; NOT organizer score or blind validation",
              "cases": len(cases), "exact_span": scores({k: counts[k] for k in ("tp", "fp", "fn")}),
              "sensitive_character_recall": round(counts["covered"] / counts["sensitive"], 4),
              "extra_masked_alphanumeric_characters": counts["extra"],
              "exact_roundtrip": f"{counts['roundtrip_ok']}/{counts['roundtrips']}",
              "detector_cold_ms": {"median": round(sorted(timings)[len(timings)//2], 2), "max": round(max(timings), 2)},
              "per_type": {k: scores(c) for k, c in sorted(categories.items())}, "errors": errors}
    out = Path("artifacts/challenge-evaluation.json" if args.challenge else "artifacts/evaluation.json")
    out.parent.mkdir(exist_ok=True)
    out.write_text(json.dumps(report, ensure_ascii=False, indent=2) + "\n")
    print(json.dumps(report, ensure_ascii=False, indent=2))


if __name__ == "__main__":
    main()
