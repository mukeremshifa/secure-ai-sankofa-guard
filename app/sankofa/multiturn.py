"""Multi-turn accumulator (fixes W4: the Guard is stateless).

Keeps a rolling window of the user's recent turns. When a new message looks like
it is *assembling* an earlier payload ("save P1 = ...", "now join P1 and P2"),
the joined window is returned so it can be re-checked as one piece of text.
"""
import re
from collections import deque
from dataclasses import dataclass

_LABEL = r"(?:p|part|var|variable|piece|segment|fragment|chunk|string|x|y)\s*[-_#]?\s*\d"
_DEFINE = re.compile(rf"\b{_LABEL}\s*(?:=|:|is\b)", re.I)
_SAVE = re.compile(rf"\b(?:save|store|remember|memori[sz]e|keep|note)\b.{{0,80}}\b(?:as|in|into|called|named)\b\s+{_LABEL}", re.I | re.S)
_JOIN = re.compile(rf"\b(?:join|combine|concatenate|merge|assemble|stitch|put together|append)\b.{{0,80}}{_LABEL}", re.I | re.S)
_REFS = re.compile(_LABEL, re.I)


@dataclass
class Assessment:
    triggered: bool
    reason: str
    joined: str


class Accumulator:
    def __init__(self, window: int = 8):
        self.turns = deque(maxlen=window)

    def assess(self, message: str) -> Assessment:
        reason = ""
        if _JOIN.search(message):
            reason = "join/combine of earlier fragments"
        elif _DEFINE.search(message) or _SAVE.search(message):
            reason = "fragment definition (P1/P2-style variables)"
        elif len(set(m.lower() for m in _REFS.findall(message))) >= 2:
            reason = "references several saved fragments"
        joined = "\n".join([*self.turns, message]) if reason else message
        return Assessment(bool(reason), reason, joined)

    def add(self, message: str):
        self.turns.append(message)
