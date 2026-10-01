"""Ghana-specific PII detector/redactor (fixes W3: the Guard's PII check is US-centric)."""
import re
from dataclasses import dataclass

_MOBILE = r"(?:20|23|24|25|26|27|28|29|50|53|54|55|56|57|59)"
PATTERNS = [
    ("GHANA_CARD", re.compile(r"(?<![A-Za-z0-9])GHA[-\s]?\d{9}[-\s]?\d(?!\d)", re.I)),
    ("SSNIT_ID", re.compile(r"(?<![A-Za-z0-9])[A-Z]\d{12}(?!\d)")),
    ("MOMO_NUMBER", re.compile(
        rf"(?<![\w+])(?:\+?233|0)[\s-]?{_MOBILE}[\s-]?\d{{3}}[\s-]?\d{{4}}(?!\d)")),
]


@dataclass
class Finding:
    kind: str
    value: str


def find(text: str):
    out = []
    for kind, rx in PATTERNS:
        out += [Finding(kind, m.group(0)) for m in rx.finditer(text)]
    return out


def redact(text: str):
    """Return (redacted_text, findings)."""
    findings = []
    for kind, rx in PATTERNS:
        def _sub(m, kind=kind):
            findings.append(Finding(kind, m.group(0)))
            return f"[{kind}]"
        text = rx.sub(_sub, text)
    return text, findings
