"""Only the development split is a regression test; holdout stays separate."""

import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from benchmarks.fresh_cases import DEVELOPMENT  # noqa: E402
from pii_proxy.detector import Detector  # noqa: E402
from pii_proxy.masking import mask, restore_exact  # noqa: E402
from scripts.evaluate import parse  # noqa: E402


@pytest.fixture(scope="module")
def detector():
    return Detector(cache_size=0)


@pytest.mark.parametrize("case", DEVELOPMENT, ids=[case[0] for case in DEVELOPMENT])
def test_fresh_development(detector, case):
    text, expected = parse(case[1])
    spans = detector.detect(text)
    assert {(s.start, s.end, s.kind.value) for s in spans} == expected
    result, replacements = mask(text, spans, "partial")
    assert restore_exact(result, replacements) == text


@pytest.mark.parametrize("text", [
    "Клиент Любовь Миронова обратилась за помощью.",
    "Клиент Вера Крылова позвонила.",
    "Клиент Неизвестнов Арсений прислал документы.",
])
def test_ambiguous_and_unknown_names_are_preserved_as_candidates(detector, text):
    spans = detector.detect(text)
    result, replacements = mask(text, spans, "partial")
    assert replacements and result != text
    assert restore_exact(result, replacements) == text
