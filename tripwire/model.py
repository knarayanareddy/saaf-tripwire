"""Shared contract. Every rule module in tripwire/rules/ exposes RULE and check(); do not change these shapes."""
from __future__ import annotations
from dataclasses import dataclass, field, asdict
from pathlib import Path

SEVERITIES = ("critical", "high", "medium", "low", "info")
CLASSES = ("ai-and-llm", "web-protocol-and-auth", "client-side", "data-isolation", "resource-exhaustion", "supply-chain-and-release")

@dataclass
class Finding:
    rule: str            # e.g. "TW-NET1"
    severity: str        # one of SEVERITIES
    file: str            # repo-relative path ("" for repo-level)
    line: int            # 1-based, 0 if not applicable
    message: str         # what is wrong, one sentence
    fix: str             # how to fix, one sentence
    evidence: str = ""   # short snippet; NEVER a secret value (mask it)
    def to_dict(self): return asdict(self)

@dataclass
class Context:
    root: Path                       # repo root being scanned
    history: bool = True             # scan full git history where relevant
    files: list[Path] = field(default_factory=list)  # tracked files (filled by the engine)

# A rule module must define:
#   RULE = {"id": "TW-XXX1", "title": "...", "severity": "high", "class": "<one of CLASSES>",
#           "why": "one line: the attack it stops", "seen_in": ["repo names from the SAAF audit"]}
#   def check(ctx: Context) -> list[Finding]
