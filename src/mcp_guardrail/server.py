"""The live MCP server, built on FastMCP.

The `mcp` transport dependency is imported lazily so the policy engine, evals, and
tests stay fast and fully offline. Every tool registered here routes through the
`Gateway`, so the model only ever sees policy-checked, sanitized output. The set
of tools exposed is filtered by the caller's role.
"""

from __future__ import annotations

import os

from mcp_guardrail.config import GatewayPolicy, default_policy, load_policy
from mcp_guardrail.gateway import Gateway


def build_server(role: str | None = None, policy: GatewayPolicy | None = None, gateway: Gateway | None = None):
    """Construct a FastMCP server whose tools are wrapped by the gateway."""
    from mcp.server.fastmcp import FastMCP  # lazy: keeps the core dependency-light

    role = role or os.environ.get("GUARDRAIL_ROLE", "analyst")
    gw = gateway or Gateway(policy or default_policy())
    server = FastMCP("mcp-guardrail-gateway")
    allowed = {spec.name for spec in gw.list_tools(role)}

    if "read_file" in allowed:

        @server.tool()
        def read_file(path: str) -> str:
            """Read a company file through the security gateway."""
            return gw.call(role, "read_file", {"path": path}).text

    if "fetch_url" in allowed:

        @server.tool()
        def fetch_url(url: str) -> str:
            """Fetch an approved web page through the security gateway."""
            return gw.call(role, "fetch_url", {"url": url}).text

    if "query_db" in allowed:

        @server.tool()
        def query_db(sql: str) -> str:
            """Run a read-only SQL query through the security gateway."""
            return gw.call(role, "query_db", {"sql": sql}).text

    if "send_email" in allowed:

        @server.tool()
        def send_email(to: str, body: str) -> str:
            """Send an email through the security gateway (egress; secrets blocked)."""
            return gw.call(role, "send_email", {"to": to, "body": body}).text

    return server


def main() -> None:
    policy_path = os.environ.get("GUARDRAIL_POLICY")
    policy = load_policy(policy_path) if policy_path else default_policy()
    build_server(policy=policy).run()


if __name__ == "__main__":
    main()
