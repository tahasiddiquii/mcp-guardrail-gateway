from mcp_guardrail.config import default_policy
from mcp_guardrail.gateway import Gateway


def gw():
    return Gateway(default_policy())


def test_list_tools_is_role_filtered():
    g = gw()
    analyst_tools = {t.name for t in g.list_tools("analyst")}
    admin_tools = {t.name for t in g.list_tools("admin")}
    assert "send_email" not in analyst_tools
    assert "send_email" in admin_tools


def test_blocked_call_returns_reason_and_audits_deny():
    g = gw()
    out = g.call("analyst", "send_email", {"to": "x", "body": "y"})
    assert not out.allowed
    assert "not permitted" in out.text
    assert g.audit.entries[-1].action == "deny"


def test_result_pii_is_redacted():
    g = gw()
    out = g.call("analyst", "query_db", {"sql": "SELECT id, name, email, phone FROM customers"})
    assert out.allowed
    assert "dana.lee@example.com" not in out.text
    assert out.redacted >= 1


def test_indirect_injection_is_neutralized():
    g = gw()
    out = g.call("analyst", "read_file", {"path": "/company/notes.txt"})
    from mcp_guardrail import detectors

    assert detectors.scan_injection(out.text) == []
    assert out.neutralized >= 1


def test_benign_read_is_untouched():
    g = gw()
    out = g.call("analyst", "read_file", {"path": "/company/handbook.txt"})
    assert out.allowed
    assert out.redacted == 0 and out.neutralized == 0


def test_audit_chain_holds_after_mixed_traffic():
    g = gw()
    g.call("analyst", "read_file", {"path": "/company/handbook.txt"})
    g.call("analyst", "send_email", {"to": "x", "body": "y"})
    g.call("admin", "send_email", {"to": "o", "body": "hi"})
    assert g.audit.verify()
