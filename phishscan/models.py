from dataclasses import dataclass


@dataclass(frozen=True)
class Finding:
    rule: str
    points: int
    reason: str
    mitre: str | None = None
