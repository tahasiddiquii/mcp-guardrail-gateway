"""A security gateway for the Model Context Protocol.

The gateway wraps an upstream MCP server (or the bundled offline demo upstream)
and enforces a policy on every tool call: role-based tool access, argument
constraints, prompt-injection and secret scanning on both arguments and results,
PII redaction, rate limiting, and a tamper-evident audit log.
"""

from mcp_guardrail.config import GatewayPolicy, ToolPolicy, load_policy
from mcp_guardrail.gateway import CallOutcome, Gateway

__all__ = ["CallOutcome", "Gateway", "GatewayPolicy", "ToolPolicy", "load_policy"]
__version__ = "0.1.0"
