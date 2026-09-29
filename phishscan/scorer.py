from dataclasses import dataclass

from .models import Finding
from .weights import MALICIOUS_AT, SUSPICIOUS_AT


@dataclass
class Verdict:
    score: int
    label: str
    findings: list


def score(findings) -> Verdict:
    unique: dict[str, Finding] = {}
    for f in findings:
        unique.setdefault(f.rule, f)
    kept = sorted(unique.values(), key=lambda f: -f.points)
    total = min(100, sum(f.points for f in kept))
    label = "Malicious" if total >= MALICIOUS_AT else "Suspicious" if total >= SUSPICIOUS_AT else "Safe"
    return Verdict(total, label, kept)
