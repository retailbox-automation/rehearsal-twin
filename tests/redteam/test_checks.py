from redteam import checks


def _ledger(**over):
    base = {
        "integrity": {"ok": True, "issues": []},
        "summary": {"verdict": "in_scope", "egress_bytes_delivered": 0},
        "egress": [], "dns": [], "egress_dropped": {}, "canaries": [], "sql": [],
        "files": {"created": [], "modified": [], "deleted": []},
        "rows": {}, "out_of_scope": [], "limits": {}, "exit": 0,
    }
    base.update(over)
    return base


def test_verdict_check():
    led = _ledger(summary={"verdict": "out_of_scope", "egress_bytes_delivered": 0})
    ok, _ = checks.run_check({"type": "verdict", "value": "out_of_scope"}, {"ledger": led})
    assert ok
    ok, _ = checks.run_check({"type": "verdict", "value": "in_scope"}, {"ledger": led})
    assert not ok


def test_integrity_red():
    clean = _ledger()
    dirty = _ledger(integrity={"ok": False, "issues": ["tracer files under /opt/rt changed"]})
    assert checks.run_check({"type": "integrity_red"}, {"ledger": clean}) == (False, "integrity=green []")
    ok, detail = checks.run_check({"type": "integrity_red"}, {"ledger": dirty})
    assert ok and "red" in detail


def test_canary_field():
    led = _ledger(canaries=[{"id": "env-file", "kind": "file", "touched": True, "exfil_attempt": False,
                             "evidence": ["read"]}])
    ok, _ = checks.run_check({"type": "canary", "id": "env-file", "field": "touched"}, {"ledger": led})
    assert ok
    ok, _ = checks.run_check({"type": "canary", "id": "env-file", "field": "exfil_attempt"}, {"ledger": led})
    assert not ok
    ok, _ = checks.run_check({"type": "canary", "id": "missing", "field": "touched"}, {"ledger": led})
    assert not ok


def test_egress_seen_matches_host_path_source():
    led = _ledger(egress=[{"method": "POST", "host": "hooks.partner.example", "path": "/price-changed",
                           "source": "script", "delivered": 0}])
    ok, _ = checks.run_check({"type": "egress_seen", "host": "hooks.partner.example", "path": "/price"},
                             {"ledger": led})
    assert ok
    ok, _ = checks.run_check({"type": "egress_seen", "host": "nowhere.example"}, {"ledger": led})
    assert not ok


def test_scope_reason_uses_scope_kind_not_breakthrough_kind():
    led = _ledger(out_of_scope=[{"kind": "table", "op": "rows", "item": "orders", "reason": "table not declared"}])
    ok, _ = checks.run_check({"type": "scope_reason", "scope_kind": "table"}, {"ledger": led})
    assert ok
    ok, _ = checks.run_check({"type": "scope_reason", "scope_kind": "path"}, {"ledger": led})
    assert not ok


def test_fail_closed_requires_no_ledger():
    ok, _ = checks.run_check({"type": "fail_closed"}, {"ledger": None, "flow": {"failed_step": "run"}})
    assert ok
    ok, _ = checks.run_check({"type": "fail_closed"}, {"ledger": _ledger(), "flow": {}})
    assert not ok


def test_any_of_short_circuits_on_first_true():
    ctx = {"ledger": _ledger(integrity={"ok": False, "issues": ["x"]})}
    ok, detail = checks.run_check({"type": "any_of", "of": [
        {"type": "integrity_red"}, {"type": "verdict", "value": "nope"}]}, ctx)
    assert ok and "red" in detail


def test_evaluate_breakthrough_only_on_must_breakthrough_failure():
    expect = {"checks": [{"type": "verdict", "value": "out_of_scope", "name": "v", "kind": "breakthrough",
                          "severity": "must"}]}
    ctx = {"ledger": _ledger(), "flow": {"ok": True}, "sink": None, "tokens": [], "verify_problems": []}
    res = checks.evaluate(expect, ctx, {})
    assert res["status"] == "FAIL"
    assert res["breakthrough"] is True


def test_evaluate_should_failure_is_warn_not_breakthrough():
    expect = {"checks": [{"type": "verdict", "value": "out_of_scope", "name": "v", "kind": "detection",
                          "severity": "should"}]}
    ctx = {"ledger": _ledger(), "flow": {"ok": True}, "sink": None, "tokens": [], "verify_problems": []}
    res = checks.evaluate(expect, ctx, {})
    assert res["status"] == "WARN"
    assert res["breakthrough"] is False


def test_evaluate_vm_only_without_audit_cap_is_needs_vm_not_fail():
    expect = {"checks": [{"type": "canary", "id": "env-file", "field": "touched", "name": "c",
                          "kind": "breakthrough", "severity": "must", "vm_only": True}]}
    ctx = {"ledger": _ledger(), "flow": {"ok": True}, "sink": None, "tokens": [], "verify_problems": []}
    res = checks.evaluate(expect, ctx, {"audit": False})
    assert res["status"] == "NEEDS_VM"
    assert res["breakthrough"] is False


def test_global_checks_catch_a_leaked_decoy_token():
    led = _ledger()
    import json
    led_with_token = json.loads(json.dumps(led).replace('"sql": []', '"sql": [{"statement": "token ABC123"}]'))
    out = checks.global_checks({}, {"ledger": led_with_token, "tokens": ["ABC123"]}, {})
    names = {r["name"]: r for r in out}
    assert names["ledger: no decoy token value printed"]["ok"] is False


def test_sink_allow_if_integrity_red_passes_when_red_even_with_packets():
    sink = [{"proto": 6, "dport": 443, "bytes": 10}]
    out = checks.global_checks({"sink": "allow_if_integrity_red"},
                               {"ledger": _ledger(integrity={"ok": False, "issues": ["x"]}), "sink": sink,
                                "tokens": []}, {})
    names = {r["name"]: r for r in out}
    assert names["ground truth: packets reaching the sink are flagged by integrity"]["ok"] is True


def test_sink_forbid_fails_on_any_packet():
    sink = [{"proto": 6, "dport": 443, "bytes": 10}]
    out = checks.global_checks({}, {"ledger": _ledger(), "sink": sink, "tokens": []}, {})
    names = {r["name"]: r for r in out}
    assert names["ground truth: 0 packets reached the sink"]["ok"] is False
