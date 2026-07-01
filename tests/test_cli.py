from mcp_guardrail.cli import main


def test_demo_runs(capsys):
    assert main(["demo"]) == 0
    out = capsys.readouterr().out
    assert "Gateway demo" in out
    assert "audit chain verified" in out


def test_eval_passes_and_exits_zero(tmp_path):
    report = tmp_path / "r.md"
    assert main(["eval", "--report", str(report)]) == 0
    assert report.exists()
    assert "gate: PASS" in report.read_text()


def test_probe_blocks_disallowed_tool(capsys):
    assert main(["probe", "--role", "analyst", "--tool", "send_email", "--arg", "to=x", "--arg", "body=y"]) == 0
    assert "BLOCKED" in capsys.readouterr().out


def test_audit_reports_verified_chain(capsys):
    assert main(["audit"]) == 0
    assert "chain verified: True" in capsys.readouterr().out
