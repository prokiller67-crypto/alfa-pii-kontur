import pytest

from pii_proxy.detector import Kind, Span
from pii_proxy.masking import mask, remask_exact, restore_exact, restore_tokens


@pytest.mark.parametrize("mode", ["shape", "partial", "token"])
def test_multiple_length_changes_unicode_and_punctuation(mode):
    text = "😀 Петров Пётр,\n a@example.org."
    a = text.index("Петров")
    b = text.index("a@example")
    spans = (Span(a, a + len("Петров Пётр"), Kind.PERSON), Span(b, b + len("a@example.org"), Kind.EMAIL))
    masked, mapping = mask(text, spans, mode)
    assert restore_exact(masked, mapping) == text
    assert remask_exact(text, mapping) == masked


def test_token_restore_is_not_recursive():
    replacements = [{"masked": "⟦A⟧", "original": "⟦B⟧"}, {"masked": "⟦B⟧", "original": "secret"}]
    assert restore_tokens("⟦A⟧ / ⟦B⟧", replacements) == "⟦B⟧ / secret"


def test_modified_shape_is_rejected():
    with pytest.raises(ValueError):
        restore_exact("abcd", [{"start": 0, "end": 4, "masked": "****", "original": "secret"}])


def test_license_letter_series_is_masked():
    original = "77 АА номер 123456"
    masked, mapping = mask(original, (Span(0, len(original), Kind.DRIVER_LICENSE),))
    assert masked == "** ** номер ******"
    assert restore_exact(masked, mapping) == original


def test_same_entity_gets_same_token():
    text = "one@example.org и one@example.org"
    b = text.rindex("one")
    _, replacements = mask(text, (Span(0, 15, Kind.EMAIL), Span(b, b + 15, Kind.EMAIL)), "token")
    assert replacements[0]["masked"] == replacements[1]["masked"]
