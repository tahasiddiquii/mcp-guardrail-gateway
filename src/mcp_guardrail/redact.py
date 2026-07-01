"""Redaction and injection neutralization.

Redaction masks secret and PII spans so they never reach the model or the user.
Neutralization defangs an injection span in a tool result so it reads as inert
quoted text rather than a live instruction the agent might follow.
"""

from __future__ import annotations

from dataclasses import dataclass

from mcp_guardrail.detectors import Finding


@dataclass
class Sanitized:
    text: str
    redacted: int
    neutralized: int


def _merge_spans(findings: list[Finding]) -> list[Finding]:
    """Drop findings whose span is fully covered by an earlier, longer finding."""
    ordered = sorted(findings, key=lambda f: (f.start, -(f.end - f.start)))
    kept: list[Finding] = []
    covered_until = -1
    for f in ordered:
        if f.start >= covered_until:
            kept.append(f)
            covered_until = f.end
    return kept


def apply(text: str, findings: list[Finding], *, redact_pii: bool, redact_secrets: bool, neutralize_injection: bool) -> Sanitized:
    """Rewrite `text`, replacing risky spans according to the flags.

    Spans are rewritten from right to left so earlier offsets stay valid.
    """
    selected = [
        f
        for f in findings
        if (f.kind == "pii" and redact_pii)
        or (f.kind == "secret" and redact_secrets)
        or (f.kind == "injection" and neutralize_injection)
    ]
    selected = _merge_spans(selected)
    redacted = 0
    neutralized = 0
    out = text
    for f in sorted(selected, key=lambda f: f.start, reverse=True):
        if f.kind == "injection":
            replacement = f"[neutralized-{f.label}]"
            neutralized += 1
        else:
            replacement = f"[redacted-{f.label}]"
            redacted += 1
        out = out[: f.start] + replacement + out[f.end :]
    return Sanitized(text=out, redacted=redacted, neutralized=neutralized)
