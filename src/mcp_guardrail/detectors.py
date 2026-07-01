"""Content detectors for prompt injection, secrets, and PII.

These are deterministic, offline, rule-based detectors. They run on both tool
arguments (to stop secrets leaving the boundary) and tool results (because a
result is untrusted data that may carry an indirect prompt injection). Setting
`GUARDRAIL_SCANNER=llm` is the documented hook for a model-graded second pass;
the rule set below is the always-on floor.
"""

from __future__ import annotations

import re
from dataclasses import dataclass


@dataclass(frozen=True)
class Finding:
    """A single detected span of risky content."""

    kind: str  # "injection" | "secret" | "pii"
    label: str
    start: int
    end: int
    severity: str  # "low" | "medium" | "high"

    @property
    def span(self) -> tuple[int, int]:
        return (self.start, self.end)


# --- Prompt injection ---------------------------------------------------------
# Phrases that try to override instructions, hijack tools, or exfiltrate data when
# they appear inside otherwise-trusted content (files, web pages, DB rows).
_INJECTION_PATTERNS: list[tuple[str, str, str]] = [
    ("instruction_override", r"ignore (?:all |any |the )?(?:previous|prior|above) (?:instructions|prompts?)", "high"),
    ("instruction_override", r"disregard (?:all |any |the )?(?:previous|prior|above) (?:instructions|context)", "high"),
    ("persona_override", r"you are now (?:a|an|the|in)\b", "medium"),
    ("system_prompt_probe", r"(?:reveal|print|show|repeat|leak)\b[^.\n]{0,40}\b(?:system prompt|instructions|secret)", "high"),
    ("tool_hijack", r"(?:call|use|invoke)\b[^.\n]{0,40}\b(?:send_email|fetch_url|delete|transfer)\b", "high"),
    ("exfiltration", r"(?:send|email|post|upload|exfiltrate)\b[^.\n]{0,60}\b(?:to |@)[\w.@-]+", "high"),
    ("override_marker", r"(?:^|\n)\s*(?:###|<\|)?\s*(?:system|assistant|developer)\s*(?:message|prompt|role)\b", "medium"),
    ("do_not_tell", r"do not (?:tell|inform|mention (?:this )?to) (?:the )?(?:user|human|operator)", "high"),
]

# --- Secrets ------------------------------------------------------------------
_SECRET_PATTERNS: list[tuple[str, str, str]] = [
    ("openai_key", r"sk-[A-Za-z0-9]{16,}", "high"),
    ("aws_access_key", r"AKIA[0-9A-Z]{16}", "high"),
    ("github_token", r"gh[pousr]_[A-Za-z0-9]{20,}", "high"),
    ("slack_token", r"xox[baprs]-[A-Za-z0-9-]{10,}", "high"),
    ("private_key", r"-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----", "high"),
    ("jwt", r"eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}", "medium"),
    ("generic_secret", r"(?:password|passwd|secret|api[_-]?key)\s*[:=]\s*\S{6,}", "medium"),
]

# --- PII ----------------------------------------------------------------------
_EMAIL = r"[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}"
_SSN = r"\b\d{3}-\d{2}-\d{4}\b"
_PHONE = r"\b(?:\+?1[-.\s]?)?\(?\d{3}\)?[-.\s]\d{3}[-.\s]\d{4}\b"
_CC_CANDIDATE = r"\b(?:\d[ -]?){13,19}\b"


def _compile(patterns: list[tuple[str, str, str]]) -> list[tuple[str, re.Pattern[str], str]]:
    return [(label, re.compile(pat, re.IGNORECASE), sev) for label, pat, sev in patterns]


_INJECTION = _compile(_INJECTION_PATTERNS)
_SECRETS = _compile(_SECRET_PATTERNS)
_EMAIL_RE = re.compile(_EMAIL)
_SSN_RE = re.compile(_SSN)
_PHONE_RE = re.compile(_PHONE)
_CC_RE = re.compile(_CC_CANDIDATE)


def _luhn_ok(digits: str) -> bool:
    nums = [int(c) for c in digits if c.isdigit()]
    if not 13 <= len(nums) <= 19:
        return False
    total = 0
    for i, n in enumerate(reversed(nums)):
        if i % 2 == 1:
            n *= 2
            if n > 9:
                n -= 9
        total += n
    return total % 10 == 0


def scan_injection(text: str) -> list[Finding]:
    findings: list[Finding] = []
    for label, rx, sev in _INJECTION:
        for m in rx.finditer(text):
            findings.append(Finding("injection", label, m.start(), m.end(), sev))
    return findings


def scan_secrets(text: str) -> list[Finding]:
    findings: list[Finding] = []
    for label, rx, sev in _SECRETS:
        for m in rx.finditer(text):
            findings.append(Finding("secret", label, m.start(), m.end(), sev))
    return findings


def scan_pii(text: str) -> list[Finding]:
    findings: list[Finding] = []
    for m in _EMAIL_RE.finditer(text):
        findings.append(Finding("pii", "email", m.start(), m.end(), "medium"))
    for m in _SSN_RE.finditer(text):
        findings.append(Finding("pii", "ssn", m.start(), m.end(), "high"))
    for m in _PHONE_RE.finditer(text):
        findings.append(Finding("pii", "phone", m.start(), m.end(), "low"))
    for m in _CC_RE.finditer(text):
        if _luhn_ok(m.group()):
            findings.append(Finding("pii", "credit_card", m.start(), m.end(), "high"))
    return findings


def scan_all(text: str) -> list[Finding]:
    """Every detector, sorted by position (handy for redaction)."""
    findings = scan_injection(text) + scan_secrets(text) + scan_pii(text)
    return sorted(findings, key=lambda f: (f.start, f.end))
