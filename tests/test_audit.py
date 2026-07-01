from mcp_guardrail.audit import AuditLog


def test_chain_verifies():
    log = AuditLog()
    log.append("analyst", "read_file", "allow", ["ok"], {"pii": 1})
    log.append("analyst", "send_email", "deny", ["not permitted"], {})
    assert len(log) == 2
    assert log.verify() is True


def test_tampering_breaks_chain():
    log = AuditLog()
    log.append("analyst", "read_file", "allow", ["ok"], {})
    log.append("admin", "send_email", "allow", ["ok"], {})
    # mutate a past entry: the chain must no longer verify
    log.entries[0].action = "deny"
    assert log.verify() is False


def test_reordering_breaks_chain():
    log = AuditLog()
    log.append("analyst", "read_file", "allow", ["ok"], {})
    log.append("admin", "query_db", "allow", ["ok"], {})
    log.entries.reverse()
    assert log.verify() is False
