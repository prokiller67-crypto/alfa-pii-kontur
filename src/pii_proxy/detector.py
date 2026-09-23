"""Local span detection. Rules identify fields; NER supplies person/location candidates.

Offsets always refer to the untouched input. No prompt or entity value is logged or cached.
The small cache contains only keyed digests and span coordinates/types.
"""

from __future__ import annotations

import hashlib
import hmac
import secrets
import threading
import time
from bisect import bisect_left, bisect_right
from collections import OrderedDict
from dataclasses import dataclass
from enum import StrEnum

import regex


class Kind(StrEnum):
    PERSON = "PERSON"
    BIRTH_DATE = "BIRTH_DATE"
    BIRTH_PLACE = "BIRTH_PLACE"
    PASSPORT = "PASSPORT"
    CITIZENSHIP = "CITIZENSHIP"
    PASSPORT_ISSUER = "PASSPORT_ISSUER"
    DEPARTMENT_CODE = "DEPARTMENT_CODE"
    ISSUE_DATE = "ISSUE_DATE"
    DRIVER_LICENSE = "DRIVER_LICENSE"
    ADDRESS = "ADDRESS"
    EMAIL = "EMAIL"
    PHONE = "PHONE"
    INN = "INN"
    CARD = "CARD"
    CVV = "CVV"
    PIN = "PIN"
    CARDHOLDER = "CARDHOLDER"


@dataclass(frozen=True, slots=True)
class Span:
    start: int
    end: int
    kind: Kind
    priority: int = 70
    source: str = "rule"


FLAGS = regex.IGNORECASE | regex.VERSION1
MONTH = r"(?:январ[ья]|феврал[ья]|март[а]?|апрел[ья]|ма[йя]|июн[ья]|июл[ья]|август[а]?|сентябр[ья]|октябр[ья]|ноябр[ья]|декабр[ья])"
DATE = rf"(?:\d{{1,4}}[./-]\d{{1,2}}[./-]\d{{1,4}}|\d{{1,2}}\s+{MONTH}\s+\d{{4}}(?:\s*г(?:ода|\.)?)?)"
ORDINAL = r"(?:первого|второго|третьего|четв[её]ртого|пятого|шестого|седьмого|восьмого|девятого|десятого|одиннадцатого|двенадцатого|тринадцатого|четырнадцатого|пятнадцатого|шестнадцатого|семнадцатого|восемнадцатого|девятнадцатого|двадцатого|тридцатого|(?:двадцать|тридцать)\s+(?:первого|второго|третьего|четв[её]ртого|пятого|шестого|седьмого|восьмого|девятого))"
WORD_DATE = rf"{ORDINAL}\s+{MONTH}\s+(?:\d{{4}}(?:\s*г(?:ода|\.)?)?|(?:[а-яё-]+\s+){{1,8}}года)"
NAME_WORD = r"[а-яёa-z]+(?:-[а-яёa-z]+)?"
NAME = rf"{NAME_WORD}(?:[ \t]+{NAME_WORD}){{1,2}}"
NEXT_FIELD = regex.compile(
    r"[,;\n]\s*(?=(?:паспорт|телефон|email|e-mail|инн|фио|дата|гражданство|код подразделения|"
    r"место рождения|адрес|номер карты|cvv|cvc|пин|pin|водительское|выдан|держатель)\b)", FLAGS
)


def rx(pattern: str) -> regex.Pattern:
    return regex.compile(pattern, FLAGS)


# Most free-text fields stop at a semicolon/newline or the next recognized field.
RULES: tuple[tuple[Kind, regex.Pattern, int], ...] = (
    (Kind.EMAIL, rx(r"(?<![\w.+-])(?P<v>[\w.!#$%&'*+/=?^`{|}~-]+@[\w-]+(?:\.[\w-]+)+)(?![\w-])"), 100),
    (Kind.PASSPORT, rx(r"\bпаспорт(?:а|ом)?(?:\s+(?:рф|гражданина\s+рф))?\s*[:№=-]?\s*(?:серия\s*)?(?P<v>\d{2}\s?\d{2}\s*(?:(?:номер|№)\s*)?\d{6})(?!\d)"), 100),
    (Kind.PASSPORT, rx(r"\bсерия\s+(?P<v>\d{2}\s?\d{2}\s+номер\s+\d{6})(?!\d)"), 95),
    (Kind.PASSPORT, rx(r"\bсерия\s+(?P<v>\d{2}\s?\d{2}\s*,\s*номер\s+\d{6})(?!\d)"), 95),
    (Kind.PASSPORT, rx(r"(?<![\d ])(?P<v>\d{4}[ \t]+\d{6})(?!\d)"), 70),
    (Kind.DRIVER_LICENSE, rx(r"\b(?:водительск[а-яё]*\s+удостоверени[а-яё]*|в\s*/\s*у)\s*[:№=-]?\s*(?:серия\s*)?(?P<v>(?:\d{2}\s?\d{2}|\d{2}\s?[а-яёa-z]{2})\s*(?:(?:номер|№)\s*)?\d{6})(?!\d)"), 100),
    (Kind.DEPARTMENT_CODE, rx(r"\bкод\s+подразделени[а-яё]*\s*[:=-]?\s*(?P<v>\d{3}[ -]?\d{3})(?!\d)"), 100),
    (Kind.BIRTH_DATE, rx(rf"\b(?:дата\s+рождения|д\s*\.\s*р\s*\.|родил(?:ся|ась)|рожд[её]н(?:а)?|день\s+рождения)\s*[:=-]?\s*(?P<v>{DATE})"), 100),
    (Kind.BIRTH_DATE, rx(rf"(?P<v>{DATE})\s*(?:года\s+рождения|г\s*\.\s*р\s*\.)"), 100),
    (Kind.BIRTH_DATE, rx(rf"\b(?:дата\s+рождения|родил(?:ся|ась))\s*[:=-]?\s*(?P<v>{WORD_DATE})"), 100),
    (Kind.ISSUE_DATE, rx(rf"\b(?:дата\s+выдачи|выдан(?:а|о)?(?:\s+паспорт)?)\s*[:=-]?\s*(?P<v>{DATE})"), 100),
    (Kind.BIRTH_PLACE, rx(r"\b(?:место\s+рождения|родил(?:ся|ась)\s+в|урожен(?:ец|ка))\s*[:=-]?\s*(?P<v>[^;\n]+)"), 90),
    (Kind.CITIZENSHIP, rx(r"\bгражданств[оа]\s*[:=-]?\s*(?P<v>Российск(?:ая|ой)\s+Федераци[яи]|Республики\s+[а-яё-]+|[а-яё-]+(?:\s+[а-яё-]+)?)(?=[,;\n.]|$)"), 100),
    (Kind.CITIZENSHIP, rx(r"\bграждан(?:ин|ка)\s+(?P<v>Российской\s+Федерации|Республики\s+[а-яё-]+|[а-яё-]+)(?=[,;\n.]|$)"), 100),
    (Kind.PASSPORT_ISSUER, rx(r"\b(?:орган,?\s+выдавший\s+паспорт|кем\s+выдан|паспорт\s+выдан)\s*[:=-]?\s*(?P<v>(?!\d)[^;\n]+)"), 90),
    (Kind.PASSPORT_ISSUER, rx(r"\bвыдан\s+(?P<v>(?:овд|увд|умвд|уфмс|гу\s+мвд|мвд|отдел[а-яё]*\s+мвд)[^;\n]+)"), 90),
    (Kind.ADDRESS, rx(r"\b(?:адрес(?:\s+(?:проживания|регистрации|доставки))?|прожива(?:ю|ет)|живу|зарегистрирован(?:а)?)\s*(?:по\s+адресу|в)?\s*[:=-]?\s*(?P<v>[^;\n]+)"), 85),
    (Kind.ADDRESS, rx(r"\b(?:мой|моя|мо[её])\s+(?:город|страна|улица|дом|квартира|индекс)\s*[:=-]?\s*(?P<v>[^;\n,.]+)"), 85),
    (Kind.CARDHOLDER, rx(rf"\b(?:имя\s+держателя(?:\s+карты)?|держатель\s+карты|card\s*holder(?:\s+name)?)\s*[:=-]?\s*(?P<v>{NAME})"), 100),
    (Kind.PERSON, rx(rf"\b(?:фио|ф\s*\.\s*и\s*\.\s*о\s*\.|меня\s+зовут|клиент(?:ка)?|за[её]мщик|получатель)\s*[:=-]?\s*(?P<v>{NAME})"), 80),
    (Kind.PERSON, rx(rf"\b(?:фио|клиент(?:ка)?|получатель)\s*[:=-]?\s*(?P<v>{NAME_WORD}\s+[а-яёa-z]\.\s*[а-яёa-z]\.)"), 95),
    (Kind.INN, rx(r"\bинн\s*[:№=-]?\s*(?P<v>\d{12}|\d{10})(?!\d)"), 100),
    (Kind.CVV, rx(r"\b(?:cvv2?|cvc2?|цвв)(?:[- ]код)?\s*[:=-]?\s*(?P<v>\d{3,4})(?!\d)"), 100),
    (Kind.PIN, rx(r"\b(?:пин|pin)(?:[- ]код)?(?:\s+карты)?\s*[:=-]?\s*(?P<v>\d{4,6})(?!\d)"), 100),
    (Kind.PHONE, rx(r"\b(?:телефон|тел\.?|мобильный|номер\s+телефона)\s*[:=-]?\s*(?P<v>\+?\d[\d ()-]{7,22}\d)(?!\d)"), 85),
)
PHONE = rx(r"(?<!\d)(?P<v>(?:\+7|8)[ \t-]*\(?\d{3}\)?[ \t-]*\d{3}[ \t-]*\d{2}[ \t-]*\d{2})(?!\d)")
CARD = rx(r"(?<!\d)(?P<v>\d(?:[ -]?\d){12,18})(?!\d)")
INN = rx(r"(?<!\d)(?P<v>\d{12}|\d{10})(?!\d)")
PUBLIC = rx(r"\b(?:поэт[а-яё]*|писател[а-яё]*|роман|стихотворени[а-яё]*|историческ[а-яё]*)\b")
PUBLIC_PERSON = rx(r"\bалександр[а-яё]*\s+(?:сергеевич[а-яё]*\s+)?пушкин[а-яё]*\b")
PRIVATE = rx(r"\b(?:клиент[а-яё]*|за[её]мщик[а-яё]*|паспорт[а-яё]*|мои|мой|меня|фио|живу|прожива[а-яё]*|гражданств[а-яё]*)\b")
BANK_ADDRESS = rx(r"\b(?:отделени[а-яё]*|офис[а-яё]*|филиал[а-яё]*|банкомат[а-яё]*)\s+(?:банка|альфа[- ]?банка)\b")
PUBLIC_ADDRESS = rx(r"\b(?:магазин[а-яё]*|ресторан[а-яё]*|музе[а-яё]*|отделени[а-яё]*\s+банка)\b")
NAME_STOP = {"пришел", "пришёл", "обратился", "позвонил", "просит", "хочет", "указал", "не", "в", "на", "из", "и", "это", "без", "номер", "паспорт", "телефон"}
COMPONENT = rx(r"\b(?:страна|город|улица|дом|квартира|индекс)\s*:\s*(?P<v>[^,;\n.]+)")
ABBREVIATIONS = {"г", "ул", "д", "кв", "пр", "пер", "обл", "корп", "стр", "пос", "им", "р"}


def sentence_end(value: str) -> int:
    for stop in regex.finditer(r"\.(?=\s|$)", value):
        word = regex.search(r"(\w+)$", value[max(0, stop.start() - 32):stop.start()])
        if word and word[1].lower() not in ABBREVIATIONS:
            return stop.start()
    return len(value)


class ClauseIndex:
    """Build sentence boundaries once per window, not once per entity."""

    def __init__(self, text: str):
        self.text = text
        boundaries = {0, len(text)}
        for match in regex.finditer(r"[;\n]|\.(?=\s+[А-ЯЁA-Z])", text):
            if match[0] == ".":
                word = regex.search(r"(\w+)$", text[max(0, match.start() - 32):match.start()])
                if word and word[1].lower() in ABBREVIATIONS:
                    continue
            boundaries.add(match.end())
        self.boundaries = sorted(boundaries)

    def at(self, start: int, end: int) -> str:
        left = self.boundaries[max(0, bisect_right(self.boundaries, start) - 1)]
        right = self.boundaries[bisect_left(self.boundaries, end)]
        return self.text[left:right]


def is_public_context(clause: str) -> bool:
    # Calling a person a poet is not evidence that their personal data is public.
    # Keep the exception narrow and auditable; personal/customer context takes precedence.
    return bool(PUBLIC.search(clause) and PUBLIC_PERSON.search(clause) and not PRIVATE.search(clause))


def luhn(digits: str) -> bool:
    total = 0
    for i, char in enumerate(reversed(digits)):
        digit = int(char)
        if i % 2:
            digit = digit * 2
            digit = digit - 9 if digit > 9 else digit
        total += digit
    return len(set(digits)) > 1 and total % 10 == 0


def inn_valid(value: str) -> bool:
    digits = list(map(int, value))
    if len(set(digits)) < 2:
        return False
    def check(weights: list[int], expected: int) -> bool:
        return sum(a * b for a, b in zip(weights, digits, strict=False)) % 11 % 10 == expected
    if len(digits) == 10:
        return check([2, 4, 10, 3, 5, 9, 4, 6, 8], digits[-1])
    return len(digits) == 12 and check([7, 2, 4, 10, 3, 5, 9, 4, 6, 8], digits[-2]) and check([3, 7, 2, 4, 10, 3, 5, 9, 4, 6, 8], digits[-1])


def resolve(spans: list[Span]) -> tuple[Span, ...]:
    """Keep high-confidence structured fields ahead of broad NER spans."""
    accepted: list[Span] = []
    starts: list[int] = []
    for span in sorted(spans, key=lambda s: (-s.priority, -(s.end - s.start), s.start)):
        pos = bisect_left(starts, span.start)
        if span.end <= span.start:
            continue
        if pos and accepted[pos - 1].end > span.start:
            continue
        if pos < len(accepted) and accepted[pos].start < span.end:
            continue
        starts.insert(pos, span.start)
        accepted.insert(pos, span)
    return tuple(accepted)


class Detector:
    def __init__(self, *, use_ner: bool = True, cache_size: int = 1024):
        self.use_ner = use_ner
        self.cache_size = cache_size
        self._cache: OrderedDict[bytes, tuple[float, tuple[Span, ...]]] = OrderedDict()
        self._key = secrets.token_bytes(32)
        self._lock = threading.RLock()
        from pymorphy3 import MorphAnalyzer
        self._morph = MorphAnalyzer()
        self._word_cache: OrderedDict[bytes, frozenset[str]] = OrderedDict()
        if use_ner:
            from natasha import Doc, NewsEmbedding, NewsNERTagger, Segmenter
            self._doc = Doc
            self._segmenter = Segmenter()
            self._ner = NewsNERTagger(NewsEmbedding())

    def _name_tags(self, word: str) -> frozenset[str]:
        if word.lower() in NAME_STOP | {"по", "к", "от", "для", "у", "о", "об", "со", "с", "при"}:
            return frozenset()
        key = hmac.digest(self._key, word.lower().encode(), hashlib.sha256)
        with self._lock:
            cached = self._word_cache.get(key)
            if cached is not None:
                self._word_cache.move_to_end(key)
                return cached
        tags = frozenset(t for p in self._morph.parse(word) if p.is_known for t in ("Name", "Surn", "Patr") if t in p.tag)
        with self._lock:
            self._word_cache[key] = tags
            if len(self._word_cache) > 8192:
                self._word_cache.popitem(last=False)
        return tags

    def detect(self, text: str) -> tuple[Span, ...]:
        key = hmac.digest(self._key, text.encode(), hashlib.sha256)
        with self._lock:
            cached = self._cache.get(key)
            if cached and time.monotonic() - cached[0] < 60:
                self._cache.move_to_end(key)
                return cached[1]
        spans: list[Span] = []
        # Overlap handles entities crossing processing windows. Never modify source offsets.
        for start in range(0, max(len(text), 1), 1600):
            chunk = text[start:start + 1900]
            spans.extend(Span(s.start + start, s.end + start, s.kind, s.priority, s.source)
                         for s in self._detect_chunk(chunk))
        result = resolve(spans)
        if self.cache_size:
            with self._lock:
                self._cache[key] = (time.monotonic(), result)
                while len(self._cache) > self.cache_size:
                    self._cache.popitem(last=False)
        return result

    def _detect_chunk(self, text: str) -> list[Span]:
        spans: list[Span] = []
        clauses = ClauseIndex(text)
        for kind, pattern, priority in RULES:
            # Materialize bounded matches: regex timeout must not include Python postprocessing.
            for match in list(pattern.finditer(text, timeout=0.1)):
                start, end = match.span("v")
                clause = clauses.at(match.start(), end)
                if kind in {Kind.PERSON, Kind.BIRTH_PLACE, Kind.BIRTH_DATE} and is_public_context(clause):
                    continue
                if kind in {Kind.ADDRESS, Kind.BIRTH_PLACE, Kind.PASSPORT_ISSUER}:
                    value = text[start:end]
                    boundary = NEXT_FIELD.search(value)
                    if boundary:
                        end = start + boundary.start()
                    end = start + sentence_end(text[start:end])
                    while end > start and text[end - 1] in " .,\t":
                        end -= 1
                if kind == Kind.PASSPORT_ISSUER:
                    # An unlabeled date after the authority is still the passport
                    # issue date; keeping it inside the issuer loses a required type.
                    inline_date = regex.search(rf"(?:\bот\s+)?(?P<date>{DATE})\s*$", text[start:end], FLAGS, timeout=0.1)
                    if inline_date and inline_date.start() > 0:
                        date_start = start + inline_date.start("date")
                        spans.append(Span(date_start, start + inline_date.end("date"), Kind.ISSUE_DATE, 100))
                        end = start + len(text[start:start + inline_date.start()].rstrip(" ,\t"))
                if kind == Kind.PERSON and any(w.lower() in NAME_STOP for w in text[start:end].split()):
                    continue
                if kind == Kind.PERSON and priority == 80:
                    words = list(regex.finditer(NAME_WORD, text[start:end], FLAGS))
                    if len(words) == 3 and not self._name_tags(words[-1][0]):
                        end = start + words[-2].end()
                if kind == Kind.ADDRESS:
                    clause = text[max(0, match.start() - 60):end]
                    if (BANK_ADDRESS.search(clause) or PUBLIC_ADDRESS.search(clause)) and not PRIVATE.search(clause):
                        continue
                    if not regex.search(r"\d|москв|петербург|город|улиц|ул\.|проспект|росси|г\.", text[start:end], FLAGS):
                        continue
                    tail = regex.search(r"\b(?:дом|д\.|квартира|кв\.)\s*\d+[а-яё]?(?:[/ -]\d+)?\s*,(?!\s*(?:кв|квартира|корп|корпус|стр|строение|д|дом|подъезд|этаж)\b)\s*", text[start:end], FLAGS)
                    if tail:
                        end = start + text[start:end].index(",", tail.start())
                spans.append(Span(start, end, kind, priority))
        for match in COMPONENT.finditer(text, timeout=0.1):
            clause = clauses.at(match.start(), match.end())
            if not BANK_ADDRESS.search(clause):
                start, end = match.span("v")
                end = start + len(text[start:end].rstrip())
                spans.append(Span(start, end, Kind.ADDRESS, 90, "component"))
        words = list(regex.finditer(NAME_WORD, text, FLAGS))
        for i in range(len(words) - 1):
            first, second = words[i:i + 2]
            if not text[first.end():second.start()].isspace():
                continue
            tags_a, tags_b = self._name_tags(first[0]), self._name_tags(second[0])
            if not (("Name" in tags_a and tags_b & {"Surn", "Patr"}) or ("Surn" in tags_a and "Name" in tags_b)):
                continue
            end = second.end()
            if i + 2 < len(words) and text[end:words[i + 2].start()].isspace():
                third = words[i + 2]
                if self._name_tags(third[0]) & {"Patr", "Surn"}:
                    end = third.end()
            clause = clauses.at(first.start(), end)
            if not is_public_context(clause):
                spans.append(Span(first.start(), end, Kind.PERSON, 75, "morphology"))
        for match in PHONE.finditer(text, timeout=0.1):
            spans.append(Span(*match.span("v"), Kind.PHONE, 75))
        for match in CARD.finditer(text, timeout=0.1):
            digits = regex.sub(r"\D", "", match.group("v"))
            before = text[max(0, match.start() - 40):match.start()]
            if luhn(digits) or regex.search(r"(?:номер\s+карты|карта|pan|card)\s*[:№=-]?\s*$", before, FLAGS):
                spans.append(Span(*match.span("v"), Kind.CARD, 95))
        for match in INN.finditer(text, timeout=0.1):
            if inn_valid(match.group("v")):
                spans.append(Span(*match.span("v"), Kind.INN, 65))
        if self.use_ner and regex.search(r"[а-яё]{2}", text, FLAGS):
            with self._lock:
                doc = self._doc(text)
                doc.segment(self._segmenter)
                doc.tag_ner(self._ner)
            for entity in doc.spans:
                # Clause context avoids allowing a public name to exempt a customer's name elsewhere.
                clause = clauses.at(entity.start, entity.stop)
                if entity.type == "PER":
                    if is_public_context(clause):
                        continue
                    spans.append(Span(entity.start, entity.stop, Kind.PERSON, 60, "ner"))
                elif entity.type == "LOC" and PRIVATE.search(clause) and not BANK_ADDRESS.search(clause):
                    if regex.search(r"\b(?:живу|прожива[а-яё]*|адрес)\b", clause, FLAGS):
                        spans.append(Span(entity.start, entity.stop, Kind.ADDRESS, 50, "ner"))
        return spans
