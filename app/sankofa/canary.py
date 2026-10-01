"""Output-side secret / canary scanner (fixes W2: the Guard is blind to *our* secrets).

Looks for each protected secret in the model's reply in many disguises: exact,
spaced-out, reversed, encoded (base64/hex/ROT13) and as an acrostic.
"""
import re
from dataclasses import dataclass

from . import decode

_PIN_CONTEXT = re.compile(r"pin|override|supervisor|frozen|code|passcode", re.I)


def _alnum(s: str) -> str:
    return re.sub(r"[^a-z0-9]", "", s.casefold())


@dataclass
class Hit:
    secret: str  # label
    form: str    # how it was hidden

    def __str__(self):
        return f"{self.secret} ({self.form})"


def _acrostics(text: str):
    lines = [l.strip() for l in text.splitlines() if l.strip()]
    line_initials = "".join(re.sub(r"^[^A-Za-z0-9]+", "", l)[:1] for l in lines)
    sentences = [s.strip() for s in re.split(r"(?<=[.!?])\s+|\n+", text) if s.strip()]
    sent_initials = "".join(re.sub(r"^[^A-Za-z0-9]+", "", s)[:1] for s in sentences)
    return [line_initials.casefold(), sent_initials.casefold()]


def _scan_plain(text: str, secrets: dict, via: str = ""):
    hits = []
    low = text.casefold()
    squashed = _alnum(text)
    sfx = f" via {via}" if via else ""
    for label, secret in secrets.items():
        sq = _alnum(secret)
        if len(sq) < 6:  # short numeric PIN: needs context to avoid noise
            for m in re.finditer(rf"(?<![\d.,]){re.escape(secret)}(?!\d)", text):
                window = text[max(0, m.start() - 80): m.end() + 80]
                if _PIN_CONTEXT.search(window):
                    hits.append(Hit(label, "exact" + sfx))
                    break
            continue
        if secret.casefold() in low:
            hits.append(Hit(label, "exact" + sfx))
        elif sq in squashed:
            hits.append(Hit(label, "spaced/reformatted" + sfx))
        elif sq[::-1] in squashed:
            hits.append(Hit(label, "reversed" + sfx))
    return hits


def scan(text: str, secrets: dict):
    """Return a de-duplicated list of Hit for every secret found in `text`."""
    hits = _scan_plain(text, secrets)
    found = {h.secret for h in hits}

    dec = decode.analyze(text)
    if dec.encoded_layers:
        hits += [h for h in _scan_plain(dec.expanded, secrets, "encoding") if h.secret not in found]
        found = {h.secret for h in hits}

    acros = _acrostics(text)
    for label, secret in secrets.items():
        if label in found:
            continue
        tokens = [t for t in re.findall(r"[a-z]{5,}", secret.casefold())]
        full = _alnum(secret)
        for a in acros:
            if (len(full) >= 6 and full in a) or any(t in a for t in tokens):
                hits.append(Hit(label, "acrostic"))
                break
    return hits


def overlap(reply: str, reference: str, n: int = 4, threshold: int = 3):
    """Word n-gram overlap between the reply and the confidential block."""
    def grams(s):
        w = re.findall(r"\w+", s.lower())
        return {tuple(w[i:i + n]) for i in range(len(w) - n + 1)}
    shared = grams(reply) & grams(reference)
    return len(shared), len(shared) >= threshold
