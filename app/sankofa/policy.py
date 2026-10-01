"""Local policy: a small lexicon used when the Guard cannot give a full verdict,
and on re-assembled multi-turn windows. Also the allow/redact/block decision."""
import re
from dataclasses import dataclass, field

LEXICON = [
    ("instruction-override", r"\b(ignore|disregard|forget|override)\b.{0,30}\b(previous|prior|above|earlier|all|your)\b.{0,20}\b(instructions?|rules|prompt)"),
    ("system-prompt-probe", r"\b(system|hidden|internal|initial|original)\s+(prompt|instructions?|configuration|config)\b"),
    ("config-export", r"\b(export|dump|print|output|show|reveal|repeat|list)\b.{0,40}\b(config(uration)?|instructions?|prompt|settings)\b.{0,20}\b(json|yaml|verbatim|exactly|in full)?"),
    ("staff-secret-probe", r"\b(staff|supervisor|internal|confidential)\b.{0,25}\b(codes?|pins?|notes|passwords?|secrets?|waiver)\b"),
    ("waiver-code-probe", r"\bfee[-\s]?waiver\s+code\b|\boverride\s+pin\b|\bcanary\b"),
    ("text-above-probe", r"\b(text|lines?|everything|content|message)s?\b.{0,30}\b(above|before)\b.{0,20}\b(my|this|the)\b.{0,20}\b(first )?(message|prompt|conversation)"),
]
_LEX = [(n, re.compile(p, re.I | re.S)) for n, p in LEXICON]


def lexicon_hits(text: str):
    return [n for n, rx in _LEX if rx.search(text)]


# Local link policy (W6): the Guard let a re-fanged phishing URL through.
_URL = re.compile(r"https?://[^\s<>\"')]+", re.I)
_BAD_TLD = {"xyz", "top", "click", "icu", "tk", "gq", "ml", "cf", "ga", "work", "zip", "monster", "buzz"}
_BAIT = re.compile(r"login|verify|wallet|claim|reward|bonus|free|airdrop|giveaway|momo|secure-?update", re.I)


def suspicious_links(text: str):
    out = []
    for u in _URL.findall(text):
        host = re.sub(r"^https?://", "", u, flags=re.I).split("/")[0].split(":")[0]
        if host.rsplit(".", 1)[-1].lower() in _BAD_TLD and _BAIT.search(u):
            out.append(u)
    return out


@dataclass
class Decision:
    action: str = "allow"           # allow | redact | block
    layer: str = ""                 # which layer decided
    reasons: list = field(default_factory=list)

    def block(self, layer, reason):
        self.action, self.layer = "block", layer
        self.reasons.append(reason)
        return self

    @property
    def blocked(self):
        return self.action == "block"
