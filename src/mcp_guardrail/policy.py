"""The policy engine: the decision logic between a caller and an upstream tool.

`check_precall` decides whether a call may be forwarded at all. `process_result`
treats whatever the upstream returned as untrusted and sanitizes it before it can
reach the model or the user.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from urllib.parse import urlparse

from mcp_guardrail import detectors, redact
from mcp_guardrail.config import GatewayPolicy, ToolPolicy
from mcp_guardrail.ratelimit import RateLimiter


@dataclass
class Decision:
    allow: bool
    reasons: list[str] = field(default_factory=list)


@dataclass
class ResultReview:
    text: str
    findings: dict[str, int] = field(default_factory=dict)
    redacted: int = 0
    neutralized: int = 0


class PolicyEngine:
    def __init__(self, policy: GatewayPolicy, limiter: RateLimiter | None = None) -> None:
        self.policy = policy
        self.limiter = limiter or RateLimiter()

    # -- pre-call ------------------------------------------------------------
    def check_precall(self, role: str, tool_name: str, args: dict[str, object]) -> Decision:
        reasons: list[str] = []
        spec = self.policy.tool(tool_name)
        if spec is None:
            return Decision(False, [f"unknown tool '{tool_name}'"])
        if not spec.allows_role(role):
            return Decision(False, [f"role '{role}' not permitted to call '{tool_name}'"])

        self._check_constraints(spec, args, reasons)
        self._check_secret_egress(spec, args, reasons)

        if reasons:
            return Decision(False, reasons)

        if not self.limiter.allow(f"{role}:{tool_name}", spec.max_calls_per_minute):
            return Decision(False, [f"rate limit exceeded for '{tool_name}'"])
        return Decision(True, ["ok"])

    def _check_constraints(self, spec: ToolPolicy, args: dict[str, object], reasons: list[str]) -> None:
        for arg_name, constraint in spec.arg_constraints.items():
            value = args.get(arg_name)
            if not isinstance(value, str):
                continue
            if constraint.path_prefixes and not any(value.startswith(p) for p in constraint.path_prefixes):
                reasons.append(f"argument '{arg_name}' outside allowed paths")
            if constraint.allowed_hosts:
                host = urlparse(value).hostname or ""
                if host not in constraint.allowed_hosts:
                    reasons.append(f"host '{host or value}' not in egress allowlist")
            low = value.lower()
            for bad in constraint.deny_substrings:
                if bad in low:
                    reasons.append(f"argument '{arg_name}' contains blocked pattern '{bad.strip()}'")

    def _check_secret_egress(self, spec: ToolPolicy, args: dict[str, object], reasons: list[str]) -> None:
        if not (spec.egress and self.policy.block_secret_egress):
            return
        blob = " ".join(str(v) for v in args.values())
        if detectors.scan_secrets(blob):
            reasons.append("secret detected in arguments of an egress tool")

    # -- post-call -----------------------------------------------------------
    def process_result(self, text: str) -> ResultReview:
        findings = detectors.scan_all(text)
        sanitized = redact.apply(
            text,
            findings,
            redact_pii=self.policy.redact_pii,
            redact_secrets=self.policy.redact_secrets,
            neutralize_injection=self.policy.neutralize_result_injection,
        )
        counts: dict[str, int] = {}
        for f in findings:
            counts[f.kind] = counts.get(f.kind, 0) + 1
        return ResultReview(
            text=sanitized.text,
            findings=counts,
            redacted=sanitized.redacted,
            neutralized=sanitized.neutralized,
        )
