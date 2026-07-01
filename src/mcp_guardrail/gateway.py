"""The gateway: the single choke point every tool call passes through."""

from __future__ import annotations

from dataclasses import dataclass, field

from mcp_guardrail.audit import AuditLog
from mcp_guardrail.config import GatewayPolicy
from mcp_guardrail.policy import PolicyEngine
from mcp_guardrail.upstream import DemoUpstream, ToolSpec, Upstream


@dataclass
class CallOutcome:
    allowed: bool
    text: str
    reasons: list[str] = field(default_factory=list)
    findings: dict[str, int] = field(default_factory=dict)
    redacted: int = 0
    neutralized: int = 0


class Gateway:
    """Wrap an upstream with policy enforcement, result sanitizing, and audit."""

    def __init__(
        self,
        policy: GatewayPolicy,
        upstream: Upstream | None = None,
        engine: PolicyEngine | None = None,
        audit: AuditLog | None = None,
    ) -> None:
        self.policy = policy
        self.upstream = upstream or DemoUpstream()
        self.engine = engine or PolicyEngine(policy)
        self.audit = audit or AuditLog()

    def list_tools(self, role: str) -> list[ToolSpec]:
        """Only the tools this role is allowed to see, filtered against the upstream."""
        allowed = {t.name for t in self.policy.tools_for_role(role)}
        return [spec for spec in self.upstream.list_tools() if spec.name in allowed]

    def call(self, role: str, tool: str, args: dict[str, object]) -> CallOutcome:
        decision = self.engine.check_precall(role, tool, args)
        if not decision.allow:
            self.audit.append(role, tool, "deny", decision.reasons, {})
            return CallOutcome(
                allowed=False,
                text=f"blocked: {'; '.join(decision.reasons)}",
                reasons=decision.reasons,
            )

        raw = self.upstream.call(tool, args)
        review = self.engine.process_result(raw)
        self.audit.append(role, tool, "allow", decision.reasons, review.findings)
        return CallOutcome(
            allowed=True,
            text=review.text,
            reasons=decision.reasons,
            findings=review.findings,
            redacted=review.redacted,
            neutralized=review.neutralized,
        )
