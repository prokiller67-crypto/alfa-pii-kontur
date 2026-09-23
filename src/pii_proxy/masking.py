"""Reversible replacements. Only detected sensitive fragments enter the encrypted vault."""

from __future__ import annotations

import re
import secrets
from dataclasses import asdict, dataclass

from .detector import Kind, Span


@dataclass(frozen=True)
class Replacement:
    start: int
    end: int
    original: str
    masked: str


def _shape_mask(original: str, kind: Kind) -> str:
    """Keep punctuation and the field words inside document spans."""
    is_sensitive = str.isdigit if kind == Kind.PASSPORT else str.isalnum
    chars = ["*" if is_sensitive(char) else char for char in original]
    if kind == Kind.DRIVER_LICENSE:
        for label in re.finditer(r"\bномер\b", original, flags=re.IGNORECASE):
            chars[label.start():label.end()] = original[label.start():label.end()]
    return "".join(chars)


def _mask_fragment(original: str, kind: Kind, mode: str) -> str:
    if mode == "partial" and kind in {Kind.PERSON, Kind.CARDHOLDER}:
        return " ".join(part[0] + "." for part in original.split())
    masked = _shape_mask(original, kind)
    if mode == "partial" and kind in {Kind.PASSPORT, Kind.CARD, Kind.PHONE}:
        indices = [index for index, char in enumerate(original) if char.isdigit()]
        chars = list(masked)
        for index in indices[:2] + indices[-2:]:
            chars[index] = original[index]
        return "".join(chars)
    return masked


def mask(text: str, spans: tuple[Span, ...], mode: str = "shape") -> tuple[str, list[dict]]:
    pieces: list[str] = []
    replacements: list[dict] = []
    cursor = 0
    masked_position = 0
    namespace = secrets.token_hex(8)
    tokens: dict[tuple[Kind, str], str] = {}
    for i, span in enumerate(spans):
        prefix = text[cursor:span.start]
        pieces.append(prefix)
        masked_position += len(prefix)
        original = text[span.start:span.end]
        if mode == "token":
            masked = tokens.setdefault((span.kind, original), f"⟦{span.kind}:{namespace}:{i + 1}⟧")
        else:
            masked = _mask_fragment(original, span.kind, mode)
        pieces.append(masked)
        replacements.append(asdict(Replacement(masked_position, masked_position + len(masked), original, masked)))
        masked_position += len(masked)
        cursor = span.end
    pieces.append(text[cursor:])
    return "".join(pieces), replacements


def restore_exact(text: str, replacements: list[dict]) -> str:
    pieces: list[str] = []
    cursor = 0
    for item in replacements:
        if text[item["start"]:item["end"]] != item["masked"]:
            raise ValueError("mask_mismatch")
        pieces.extend((text[cursor:item["start"]], item["original"]))
        cursor = item["end"]
    return "".join(pieces) + text[cursor:]


def remask_exact(text: str, replacements: list[dict]) -> str:
    pieces: list[str] = []
    cursor = 0
    delta = 0
    for item in replacements:
        start = item["start"] + delta
        end = start + len(item["original"])
        if text[start:end] != item["original"]:
            raise ValueError("source_mismatch")
        pieces.extend((text[cursor:start], item["masked"]))
        cursor = end
        delta += len(item["original"]) - len(item["masked"])
    return "".join(pieces) + text[cursor:]


def restore_tokens(text: str, replacements: list[dict]) -> str:
    """Restore only tokens belonging to this session, in a single non-recursive pass."""
    mapping = {r["masked"]: r["original"] for r in replacements}
    if not mapping:
        return text
    pattern = re.compile("|".join(re.escape(s) for s in sorted(mapping, key=len, reverse=True)))
    return pattern.sub(lambda m: mapping[m.group()], text)
