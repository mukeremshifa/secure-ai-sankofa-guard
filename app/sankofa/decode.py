"""Decode-and-reveal: expose obfuscated / encoded content so it can be re-checked.

Pure functions, no network. Fixes W1 (encoding bypass) and W6 (defanged links).
"""
import base64
import codecs
import re
import unicodedata
from dataclasses import dataclass, field
from urllib.parse import unquote

_ZERO_WIDTH = dict.fromkeys(map(ord, "​‌‍⁠﻿­"), None)
_HOMOGLYPHS = str.maketrans({
    # Cyrillic lookalikes
    "а": "a", "е": "e", "о": "o", "р": "p", "с": "c", "х": "x", "у": "y",
    "і": "i", "ѕ": "s", "ј": "j", "ԁ": "d", "һ": "h",
    "А": "A", "В": "B", "Е": "E", "К": "K", "М": "M", "Н": "H", "О": "O",
    "Р": "P", "С": "C", "Т": "T", "Х": "X",
    # Greek lookalikes
    "α": "a", "ο": "o", "ν": "v", "ρ": "p", "ι": "i",
    "Α": "A", "Β": "B", "Ε": "E", "Ι": "I", "Κ": "K", "Ν": "N", "Ο": "O", "Τ": "T",
})
_B64_RE = re.compile(r"(?<![A-Za-z0-9+/_-])[A-Za-z0-9+/_-]{16,}={0,2}(?![A-Za-z0-9+/=_-])")
_HEX_RE = re.compile(r"\b(?:0x)?(?:[0-9a-fA-F]{2}[ :]?){8,}\b")
_PCT_RE = re.compile(r"(?:%[0-9a-fA-F]{2}){3,}")
_COMMON = set(
    "the a an and or to of in is it you your me my this that for with all please "
    "ignore previous instructions instruction system prompt reveal show print tell "
    "secret secrets password code codes staff confidential what are give list output "
    "everything above before now do not follow rules internal override pin config".split()
)


@dataclass
class Layer:
    kind: str
    encoded: str
    decoded: str


@dataclass
class DecodeResult:
    original: str
    normalized: str      # zero-width stripped, homoglyphs folded, links re-fanged
    expanded: str        # normalized + every encoded segment replaced by its decoded text
    layers: list = field(default_factory=list)

    @property
    def changed(self) -> bool:
        return self.expanded != self.original

    @property
    def encoded_layers(self):
        return [l for l in self.layers if l.kind in ("base64", "hex", "percent", "rot13")]


def _printable_text(b: bytes):
    try:
        s = b.decode("utf-8")
    except UnicodeDecodeError:
        return None
    if len(s.strip()) < 6:
        return None
    printable = sum(ch.isprintable() or ch in "\n\t" for ch in s)
    alpha = sum(ch.isalpha() or ch.isspace() for ch in s)
    if printable / len(s) < 0.97 or alpha / len(s) < 0.6:
        return None
    return s


def _try_b64(token: str):
    t = token.replace("-", "+").replace("_", "/")
    t += "=" * (-len(t) % 4)
    try:
        return _printable_text(base64.b64decode(t, validate=True))
    except Exception:
        return None


def _try_hex(token: str):
    h = re.sub(r"[^0-9a-fA-F]", "", token[2:] if token.lower().startswith("0x") else token)
    if len(h) % 2:
        return None
    try:
        return _printable_text(bytes.fromhex(h))
    except ValueError:
        return None


def _word_hits(s: str) -> int:
    return sum(w in _COMMON for w in re.findall(r"[a-z]+", s.lower()))


def normalize(text: str):
    """Return (normalized_text, layers) for the cheap character-level tricks."""
    layers = []
    out = text
    stripped = out.translate(_ZERO_WIDTH)
    if stripped != out:
        layers.append(Layer("zero-width", "invisible characters", "removed"))
        out = stripped
    nfkc = unicodedata.normalize("NFKC", out)
    folded = nfkc.translate(_HOMOGLYPHS)
    if folded != out:
        layers.append(Layer("homoglyph", "look-alike unicode letters", "folded to ASCII"))
        out = folded
    refanged = re.sub(r"(?i)\bhxxp(s?)", r"http\1", out)
    refanged = re.sub(r"\s?[\[\(\{]\s?(?:\.|dot)\s?[\]\)\}]\s?", ".", refanged, flags=re.I)
    refanged = re.sub(r"[\[\(\{]:[\]\)\}]", ":", refanged)
    if refanged != out:
        layers.append(Layer("defanged-link", "hxxp / [.] notation", "re-fanged"))
        out = refanged
    return out, layers


def _expand_once(text: str):
    found = []

    def sub_b64(m):
        dec = _try_b64(m.group(0))
        if dec is None:
            return m.group(0)
        found.append(Layer("base64", m.group(0)[:40], dec))
        return dec

    def sub_hex(m):
        dec = _try_hex(m.group(0))
        if dec is None:
            return m.group(0)
        found.append(Layer("hex", m.group(0)[:40], dec))
        return dec

    out = _B64_RE.sub(sub_b64, text)
    out = _HEX_RE.sub(sub_hex, out)
    if _PCT_RE.search(out):
        dec = unquote(out)
        if dec != out:
            found.append(Layer("percent", "%XX sequences", dec[:80]))
            out = dec
    if not found:
        rot = codecs.decode(out, "rot_13")
        if _word_hits(rot) >= 3 and _word_hits(rot) > _word_hits(out):
            found.append(Layer("rot13", out[:40], rot))
            out = rot
    return out, found


def analyze(text: str, max_depth: int = 3) -> DecodeResult:
    norm, layers = normalize(text)
    expanded = norm
    for _ in range(max_depth):
        expanded, found = _expand_once(expanded)
        if not found:
            break
        layers.extend(found)
    return DecodeResult(original=text, normalized=norm, expanded=expanded, layers=layers)
