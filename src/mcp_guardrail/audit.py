"""A tamper-evident, append-only audit log.

Every gateway decision is recorded as an entry whose hash chains to the previous
entry. If any past record is altered or removed, `verify()` fails, which is the
property an auditor actually cares about.
"""

from __future__ import annotations

import hashlib
import json
import time
from dataclasses import asdict, dataclass, field
from pathlib import Path

GENESIS = "0" * 64


@dataclass
class AuditEntry:
    role: str
    tool: str
    action: str  # "allow" | "deny"
    reasons: list[str]
    findings: dict[str, int]
    ts: float = field(default_factory=time.time)
    prev_hash: str = GENESIS
    entry_hash: str = ""

    def digest(self) -> str:
        payload = {
            "role": self.role,
            "tool": self.tool,
            "action": self.action,
            "reasons": self.reasons,
            "findings": self.findings,
            "ts": round(self.ts, 6),
            "prev_hash": self.prev_hash,
        }
        blob = json.dumps(payload, sort_keys=True, separators=(",", ":"))
        return hashlib.sha256(blob.encode()).hexdigest()


class AuditLog:
    def __init__(self, path: str | Path | None = None) -> None:
        self.entries: list[AuditEntry] = []
        self.path = Path(path) if path else None

    def append(self, role: str, tool: str, action: str, reasons: list[str], findings: dict[str, int]) -> AuditEntry:
        prev = self.entries[-1].entry_hash if self.entries else GENESIS
        entry = AuditEntry(role=role, tool=tool, action=action, reasons=reasons, findings=findings, prev_hash=prev)
        entry.entry_hash = entry.digest()
        self.entries.append(entry)
        if self.path:
            with self.path.open("a") as fh:
                fh.write(json.dumps(asdict(entry)) + "\n")
        return entry

    def verify(self) -> bool:
        """Return True only if the whole chain is internally consistent."""
        prev = GENESIS
        for entry in self.entries:
            if entry.prev_hash != prev:
                return False
            if entry.entry_hash != entry.digest():
                return False
            prev = entry.entry_hash
        return True

    def __len__(self) -> int:
        return len(self.entries)
