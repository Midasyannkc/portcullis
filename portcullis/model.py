"""One finding shape shared by every detector in Portcullis."""
from __future__ import annotations

import hashlib
from dataclasses import dataclass, field, asdict

SEVERITIES = ["info", "low", "medium", "high", "critical"]


@dataclass
class Finding:
    source: str            # which detector produced it
    rule: str
    severity: str
    title: str
    location: str
    category: str
    detail: str = ""
    extra: dict = field(default_factory=dict)

    @property
    def fingerprint(self) -> str:
        return hashlib.sha256(f"{self.category}|{self.location}|{self.detail}".encode()).hexdigest()[:16]

    def to_dict(self):
        return {**asdict(self), "fingerprint": self.fingerprint}


def worst(findings) -> str:
    return max((f.severity for f in findings), key=SEVERITIES.index, default="info")
