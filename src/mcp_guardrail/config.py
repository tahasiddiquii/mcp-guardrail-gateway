"""Policy configuration models and loader.

A policy is deliberately declarative and reviewable: a security engineer can read
the YAML and know exactly which role may call which tool, with which argument
constraints. Nothing about tool access is implicit.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any

import yaml
from pydantic import BaseModel, Field


class ArgConstraint(BaseModel):
    """Constraints applied to a single tool argument before the call is forwarded."""

    path_prefixes: list[str] = Field(default_factory=list)
    """If set, a string argument must start with one of these prefixes (path allowlisting)."""

    allowed_hosts: list[str] = Field(default_factory=list)
    """If set, a URL argument must resolve to one of these hosts (egress allowlisting)."""

    deny_substrings: list[str] = Field(default_factory=list)
    """If any of these appear (case-insensitive) the call is blocked (e.g. SQL DDL)."""


class ToolPolicy(BaseModel):
    """Access rules for one upstream tool."""

    name: str
    allowed_roles: list[str] = Field(default_factory=list)
    max_calls_per_minute: int = 60
    egress: bool = False
    """Marks a tool that sends data out of the trust boundary (email, webhook, write)."""

    arg_constraints: dict[str, ArgConstraint] = Field(default_factory=dict)

    def allows_role(self, role: str) -> bool:
        return role in self.allowed_roles


class GatewayPolicy(BaseModel):
    """The complete gateway policy."""

    roles: list[str] = Field(default_factory=list)
    tools: list[ToolPolicy] = Field(default_factory=list)
    redact_pii: bool = True
    redact_secrets: bool = True
    block_secret_egress: bool = True
    neutralize_result_injection: bool = True

    def tool(self, name: str) -> ToolPolicy | None:
        return next((t for t in self.tools if t.name == name), None)

    def tools_for_role(self, role: str) -> list[ToolPolicy]:
        return [t for t in self.tools if t.allows_role(role)]


def load_policy(source: str | Path | dict[str, Any]) -> GatewayPolicy:
    """Load a policy from a dict, a YAML string, or a path to a YAML file."""
    if isinstance(source, dict):
        return GatewayPolicy.model_validate(source)
    if isinstance(source, Path):
        return GatewayPolicy.model_validate(yaml.safe_load(source.read_text()))
    text = str(source)
    candidate = Path(text)
    if candidate.exists():
        return GatewayPolicy.model_validate(yaml.safe_load(candidate.read_text()))
    return GatewayPolicy.model_validate(yaml.safe_load(text))


def default_policy() -> GatewayPolicy:
    """The policy used by the demo and the eval harness.

    `analyst` can read company files, fetch approved docs, and run read-only SQL.
    `admin` can additionally send email, but never with secrets in the body.
    """
    return GatewayPolicy(
        roles=["analyst", "admin"],
        redact_pii=True,
        redact_secrets=True,
        block_secret_egress=True,
        neutralize_result_injection=True,
        tools=[
            ToolPolicy(
                name="read_file",
                allowed_roles=["analyst", "admin"],
                arg_constraints={"path": ArgConstraint(path_prefixes=["/company/"])},
            ),
            ToolPolicy(
                name="fetch_url",
                allowed_roles=["analyst", "admin"],
                arg_constraints={"url": ArgConstraint(allowed_hosts=["docs.company.com"])},
            ),
            ToolPolicy(
                name="query_db",
                allowed_roles=["analyst", "admin"],
                arg_constraints={
                    "sql": ArgConstraint(
                        deny_substrings=["drop ", "delete ", "update ", "insert ", "alter ", ";--"]
                    )
                },
            ),
            ToolPolicy(name="send_email", allowed_roles=["admin"], egress=True),
        ],
    )
