import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from benchmarks.cases import CASES  # noqa: E402
from pii_proxy.detector import Detector  # noqa: E402
from scripts.evaluate import parse  # noqa: E402


@pytest.fixture(scope="module")
def detector():
    return Detector(cache_size=0)


@pytest.mark.parametrize("case", CASES, ids=[c[0] for c in CASES])
def test_development_regression(detector, case):
    _, marked = case
    text, expected = parse(marked)
    result = {(s.start, s.end, s.kind.value) for s in detector.detect(text)}
    assert result == expected


def test_dense_large_document_does_not_timeout(detector):
    from pii_proxy.masking import mask, restore_exact
    text = "\n".join(f"Обращение {i}. Клиент Иванов Иван Иванович; email: user{i}@example.org." for i in range(2000))
    spans = detector.detect(text)
    masked, replacements = mask(text, spans)
    assert "example.org" not in masked
    assert "Иванов" not in masked
    assert restore_exact(masked, replacements) == text
