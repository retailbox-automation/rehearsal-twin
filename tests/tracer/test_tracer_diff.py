import copy
import json

from rt.ledger.canonical import ledger_sha256
from rt.ledger.scope import finalize
from rt.tracer import config, diff

TOKENS = {"env-file": "rt-canary-env-test0001", "api-key-row": "rt-canary-key-test0002",
          "purge-url": "rt-canary-url-test0003"}
DEFS = [
    {"id": "env-file", "kind": "file", "path": "/srv/app/.env.canary", "audit_key": "rt_canary_env",
     "token": TOKENS["env-file"]},
    {"id": "api-key-row", "kind": "db_row", "table": "api_keys", "token": TOKENS["api-key-row"]},
    {"id": "purge-url", "kind": "url", "host": "prod-api.internal", "path": "/purge", "token": TOKENS["purge-url"]},
]


def f(sha):
    return {"t": "f", "size": 10, "mode": 0o644, "uid": 0, "gid": 0, "mtime_ns": 1, "sha256": sha}


def d():
    return {"t": "d", "size": 0, "mode": 0o755, "uid": 0, "gid": 0, "mtime_ns": 1}


def rows(n, start=1, val="v"):
    return {"pk": "id", "schema": "s", "count": n, "rows": {str(i): val for i in range(start, start + n)}}


def state(files, tables, counters=None, **extra):
    s = {"kind": "rt-state", "taken_at": "t", "files": files, "pg": {"ok": True, "tables": tables},
         "iptables": {"rules_sha256": "r1", "counters": counters or {"udp_packets": 0, "other_packets": 0}},
         "egress_active": True, "self_digest": "self1", "offsets": {}}
    s.update(extra)
    return s


def cleanup_states():
    files0 = {"/srv": d(), "/srv/app": d(), "/srv/app/tmp": d(), "/srv/app/tmp/cache": d(),
              "/srv/app/tmp/cache/c1": f("a"), "/srv/app/tmp/cache/c2": f("b"),
              "/srv/app/uploads": d(), "/srv/app/uploads/u1": f("c"),
              "/srv/app/.env.canary": f("e"), "/etc": d(), "/etc/hosts": f("h")}
    files1 = {"/srv": d(), "/etc": d(), "/etc/hosts": f("h")}
    t0 = {"sessions": rows(600), "api_keys": rows(6)}
    t1 = {"sessions": rows(360, start=241), "api_keys": rows(6)}
    return state(files0, t0), state(files1, t1)


def run_record(**kw):
    r = {"kind": "rt-run", "unit_name": "rt-run-ab12", "exit": 0,
         "limits": {"wall_s": 0.4, "peak_mem_mb": 9.5, "oom": False, "oom_kills": 0, "pids_max": 256,
                    "pids_limit_hit": 0, "wall_exceeded": False, "wall_max_s": 60, "mem_max_mb": 512.0,
                    "leftover_processes": 0},
         "stdout": "ignored", "started_at": 1.0}
    r.update(kw)
    return r


def cleanup_sources():
    return {
        "sql": [{"user": "root", "db": "shop", "app": "psql",
                 "statement": "DELETE FROM sessions WHERE expires_at < now()"}],
        "audit": [],
        "egress_records": [
            {"kind": "dns", "qname": "prod-api.internal", "qtype": 1, "answer": "198.18.0.1",
             "unit": "rt-run-ab12.scope", "canary_hits": []},
            {"kind": "https", "method": "POST", "host": "prod-api.internal", "path": "/purge", "port": 443,
             "bytes_attempted": 180, "delivered": 0, "unit": "rt-run-ab12.scope", "pid": 4242, "canary_hits": []},
            {"kind": "dns", "qname": "ntp.ubuntu.com", "unit": "systemd-timesyncd.service", "canary_hits": []},
        ],
        "egress_bad_lines": 0,
        "canary_defs": DEFS,
    }


CFG = {"egress_ignore_units": config.DEFAULTS["egress_ignore_units"]}
SCOPE = {"paths": ["/srv/app/tmp"], "tables": ["sessions"], "hosts": []}


def test_cleanup_preset_ledger():
    s0, s1 = cleanup_states()
    facts = diff.build_facts(s0, s1, run_record(), cleanup_sources(), CFG)
    ledger = finalize(facts, SCOPE)
    assert ledger["files"]["deleted"] == sorted(["/srv/app/tmp/cache/c1", "/srv/app/tmp/cache/c2",
                                                 "/srv/app/uploads/u1", "/srv/app/.env.canary"])
    assert ledger["dirs"]["deleted"] == sorted(["/srv/app", "/srv/app/tmp", "/srv/app/tmp/cache",
                                                "/srv/app/uploads"])
    assert ledger["rows"] == {"sessions": {"inserted": 0, "deleted": 240, "updated": 0}}
    assert ledger["sql"][0]["statement"].startswith("DELETE FROM sessions")
    assert ledger["egress"] == [{"kind": "https", "method": "POST", "host": "prod-api.internal",
                                 "path": "/purge", "port": 443, "bytes_attempted": 180, "delivered": 0,
                                 "source": "script"}]
    assert ledger["dns"] == [{"qname": "prod-api.internal", "count": 1}]
    canaries = {c["id"]: c for c in ledger["canaries"]}
    assert canaries["env-file"]["touched"] is True and canaries["env-file"]["evidence"] == ["deleted"]
    assert canaries["purge-url"]["touched"] is True and canaries["purge-url"]["exfil_attempt"] is False
    assert canaries["api-key-row"]["touched"] is False
    assert ledger["exit"] == 0
    assert ledger["limits"]["pids_max"] == 256 and ledger["limits"]["oom"] is False
    assert ledger["integrity"] == {"ok": True, "issues": []}
    assert "stdout" not in ledger
    s = ledger["summary"]
    assert s["files_changed"] == 4 and s["files_out_of_scope"] == 2
    assert s["rows_changed"] == 240 and s["rows_out_of_scope"] == 0
    assert s["egress_attempts"] == 1 and s["egress_out_of_scope"] == 1
    assert s["egress_bytes_delivered"] == 0
    assert s["verdict"] == "out_of_scope"
    reasons = {(e["kind"], e["item"]): e["reason"] for e in ledger["out_of_scope"]}
    assert reasons[("path", "/srv/app/uploads/u1")].startswith("not under declared paths")
    assert reasons[("host", "prod-api.internal")] == "host not declared"
    assert ("path", "/srv/app/tmp/cache/c1") not in reasons
    blob = json.dumps(ledger)
    assert not any(t in blob for t in TOKENS.values())


def test_same_run_same_hash_and_volatile_ignored():
    s0, s1 = cleanup_states()
    a = finalize(diff.build_facts(s0, s1, run_record(), cleanup_sources(), CFG), SCOPE)
    src = cleanup_sources()
    src["egress_records"].reverse()
    src["egress_records"][1]["pid"] = 999
    r = run_record(unit_name="rt-run-ffff")
    r["limits"]["wall_s"] = 3.3
    r["limits"]["peak_mem_mb"] = 77.0
    for rec in src["egress_records"]:
        if rec.get("unit") == "rt-run-ab12.scope":
            rec["unit"] = "rt-run-ffff.scope"
    b = finalize(diff.build_facts(s0, s1, r, src, CFG), SCOPE)
    b["generated_at"] = "later"
    assert a["ledger_sha256"] == b["ledger_sha256"] == ledger_sha256(b)


def test_reprice_preset_rows_budget_and_webhook_egress():
    t0 = {"prices": rows(1200)}
    t1 = copy.deepcopy(t0)
    for i in range(1, 94):
        t1["prices"]["rows"][str(i)] = "changed"
    s0, s1 = state({}, t0), state({}, t1)
    records = [{"kind": "https", "method": "POST", "host": "hooks.partner.example", "path": "/price-changed",
                "port": 443, "bytes_attempted": 300 + i, "delivered": 0, "unit": "shop-webhooks.service",
                "canary_hits": []} for i in range(93)]
    src = {"sql": [], "audit": [], "egress_records": records, "egress_bad_lines": 0, "canary_defs": DEFS}
    ledger = finalize(diff.build_facts(s0, s1, run_record(), src, CFG),
                      {"tables": {"prices": {"max_rows": 31}}})
    assert ledger["rows"]["prices"]["updated"] == 93
    assert len(ledger["egress"]) == 93
    assert {e["source"] for e in ledger["egress"]} == {"shop-webhooks.service"}
    kinds = [e["kind"] for e in ledger["out_of_scope"]]
    assert kinds.count("rows_budget") == 1 and kinds.count("host") == 93
    assert ledger["summary"]["rows_out_of_scope"] == 62


def test_migration_preset_dropped_tables():
    t0 = {"legacy_orders": rows(800), "orders": rows(3000), "audit_log": rows(2000), "customers": rows(500)}
    t1 = {"customers": rows(500)}
    src = {"sql": [{"user": "root", "db": "shop", "app": "psql", "statement": f'DROP TABLE "{t}" CASCADE'}
                   for t in ("audit_log", "legacy_orders", "orders")],
           "audit": [], "egress_records": [], "egress_bad_lines": 0, "canary_defs": DEFS}
    ledger = finalize(diff.build_facts(state({}, t0), state({}, t1), run_record(), src, CFG),
                      {"tables": ["legacy_orders"]})
    assert ledger["rows"]["legacy_orders"] == {"inserted": 0, "deleted": 800, "updated": 0, "dropped": True}
    out = sorted(e["item"] for e in ledger["out_of_scope"])
    assert out == ["audit_log", "orders"]
    assert len(ledger["sql"]) == 3


def test_canary_read_and_exfil_and_masking():
    s0, s1 = state({}, {"api_keys": rows(6)}), state({}, {"api_keys": rows(6)})
    tok = TOKENS["api-key-row"]
    src = {
        "sql": [{"user": "root", "db": "shop", "app": "psql", "statement": f"SELECT * FROM api_keys WHERE key='{tok}'"}],
        "audit": [{"key": "rt_canary_env", "comm": "cat"}],
        "egress_records": [
            {"kind": "https", "method": "POST", "host": "paste.example", "path": f"/up?k={tok}", "port": 443,
             "bytes_attempted": 90, "delivered": 0, "unit": "rt-run-ab12.scope", "canary_hits": ["api-key-row"]},
            {"kind": "dns", "qname": f"{TOKENS['env-file']}.exfil.example", "unit": "rt-run-ab12.scope",
             "canary_hits": ["env-file"]},
        ],
        "egress_bad_lines": 0,
        "canary_defs": DEFS,
    }
    ledger = finalize(diff.build_facts(s0, s1, run_record(), src, CFG), {"tables": ["api_keys"]})
    c = {x["id"]: x for x in ledger["canaries"]}
    assert c["api-key-row"]["touched"] and c["api-key-row"]["exfil_attempt"]
    assert "sql" in c["api-key-row"]["evidence"]
    assert c["env-file"]["evidence"] == ["exfil", "read"]
    assert ledger["egress"][0]["path"] == "/up" and ledger["egress"][0]["query"] is True
    blob = json.dumps(ledger)
    assert not any(t in blob for t in TOKENS.values())
    assert "<canary:api-key-row>" in ledger["sql"][0]["statement"]
    assert ledger["dns"][0]["qname"] == "<canary:env-file>.exfil.example"


def test_integrity_issues_and_dropped_packets():
    s0, s1 = cleanup_states()
    s1["self_digest"] = "self2"
    s1["egress_active"] = False
    s1["iptables"] = {"rules_sha256": "r2", "counters": {"udp_packets": 4, "other_packets": 1}}
    src = cleanup_sources()
    src["egress_bad_lines"] = 2
    run = run_record(iptables_start={"counters": {"udp_packets": 1, "other_packets": 1}})
    facts = diff.build_facts(s0, s1, run, src, CFG)
    assert facts["egress_dropped"] == {"other_packets": 0, "udp_packets": 3}
    assert facts["integrity"]["ok"] is False
    assert len(facts["integrity"]["issues"]) == 4
