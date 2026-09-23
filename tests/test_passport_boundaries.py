import pytest

from pii_proxy.detector import Detector, Kind
from pii_proxy.masking import mask, restore_exact


@pytest.fixture(scope="module")
def detector():
    return Detector(cache_size=0)


@pytest.mark.parametrize("text", [
    "4510 987654",
    "Документ клиента: 4510 987654.",
    "При проверке предъявили 4510 987654.",
    "Реквизиты:\t4510 987654; готовы к проверке.",
    "Документ: (4510 987654).",
    "Документ: 4510\t987654.",
])
def test_unlabelled_passport_in_prose_is_fully_protected(detector, text):
    spans = detector.detect(text)
    assert len(spans) == 1
    span = spans[0]
    assert span.kind == Kind.PASSPORT
    assert text[span.start:span.end].split() == ["4510", "987654"]
    masked, replacements = mask(text, spans)
    assert "4510" not in masked and "987654" not in masked
    assert restore_exact(masked, replacements) == text


@pytest.mark.parametrize("text", [
    "Код изделия: abc4510 987654def",
    "Код изделия: abc4510 987654",
    "Код изделия: 4510 987654def",
    "Значения датчика: 12 4510 987654 90",
    "Значения датчика: 12   4510 987654",
    "Значения датчика: 4510 987654   90",
])
def test_numeric_fragment_of_larger_identifier_is_not_a_passport(detector, text):
    assert not any(span.kind == Kind.PASSPORT for span in detector.detect(text))
