import copy
import json

from rt.ledger.canonical import ledger_sha256
from rt.ledger.scope import finalize
from rt.tracer import config, diff, pgstate

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
    assert ledger["rows"] == {"sessions": {"inserted": 0, "deleted": 240, "updated": 0,
                                           "digests": {"deleted": pgstate.op_digest(str(i) for i in range(1, 241))}}}
    assert ledger["file_hashes"] == {} and ledger["path_meta"] == {}
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
    assert ledger["integrity"]["ok"] is True and ledger["integrity"]["issues"] == []
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
    assert {k: v for k, v in ledger["rows"]["legacy_orders"].items() if k != "digests"} == \
        {"inserted": 0, "deleted": 800, "updated": 0, "dropped": True}
    assert set(ledger["rows"]["legacy_orders"]["digests"]) == {"deleted"}
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


def test_service_unit_attribution_and_output_masking():
    s0, s1 = cleanup_states()
    src = cleanup_sources()
    for rec in src["egress_records"]:
        if rec.get("unit") == "rt-run-ab12.scope":
            rec["unit"] = "rt-run-ab12.service"
    run = run_record(stderr="leak " + TOKENS["env-file"] + "\n", stdout="ok\n",
                     sandbox={"mode": "service", "ip_filter": "active", "ip_filter_detail": "3 packets"})
    ledger = finalize(diff.build_facts(s0, s1, run, src, CFG), SCOPE)
    assert ledger["egress"][0]["source"] == "script"
    assert ledger["sandbox"] == {"mode": "service", "ip_filter": "active"}
    assert ledger["output"]["stderr_tail"] == "leak <canary:env-file>\n"
    other = finalize(diff.build_facts(s0, s1, dict(run, stdout="different\n"), src, CFG), SCOPE)
    assert other["ledger_sha256"] == ledger["ledger_sha256"]


def test_integrity_checks_for_sandbox_escape_attempts():
    s0, s1 = cleanup_states()
    s0.update(routes_sha256="rt1", egress_service={"active": "active", "main_pid": "10", "restarts": "0"})
    s1.update(routes_sha256="rt1", egress_service={"active": "active", "main_pid": "10", "restarts": "0"})
    src = cleanup_sources()
    run = run_record(sandbox={"mode": "service", "ip_filter": "active"}, stats_recorded=True)
    good = diff.build_facts(s0, s1, run, src, CFG)["integrity"]
    assert good["ok"] is True
    assert good["checks"] == {"tracer_files": "unchanged", "firewall_rules": "unchanged", "routes": "unchanged",
                              "egress_recorder": "running", "statement_logging": "unchanged", "sandbox": "service",
                              "decoy_watch": "not available"}

    s1b = dict(s1, routes_sha256="rt2", egress_service={"active": "active", "main_pid": "11", "restarts": "1"})
    src["sql"].append({"user": "root", "db": "shop", "app": "psql", "statement": "SET log_statement = 'none'"})
    bad = diff.build_facts(s0, s1b, run, src, CFG)["integrity"]
    assert bad["ok"] is False
    assert bad["checks"]["routes"] == "changed"
    assert bad["checks"]["egress_recorder"] == "restarted"
    assert bad["checks"]["statement_logging"] == "changed"

    s0c = dict(s0, egress_active=False)
    off = diff.build_facts(s0c, s1, run, cleanup_sources(), CFG)["integrity"]
    assert off["checks"]["egress_recorder"] == "not running" and not off["ok"]

    refused = diff.build_facts(s0, s1, {"error": "refusing to run: cgroup IP filter not available"},
                               cleanup_sources(), CFG)["integrity"]
    assert "refusing to run: cgroup IP filter not available" in refused["issues"]


def test_integrity_recorder_paused_restarted_running():
    s0, s1 = cleanup_states()
    run = run_record(sandbox={"mode": "service", "ip_filter": "active"}, stats_recorded=True)

    def recorder(e0, e1):
        a, b = dict(s0, egress_service=e0), dict(s1, egress_service=e1)
        return diff.build_facts(a, b, run, cleanup_sources(), CFG)["integrity"]

    same = {"active": "active", "main_pid": "10", "restarts": "0", "state": "S"}
    ok = recorder(same, same)
    assert ok["ok"] is True and ok["checks"]["egress_recorder"] == "running"

    for letter in ("T", "t"):
        paused = recorder(same, dict(same, state=letter))
        assert paused["ok"] is False and paused["checks"]["egress_recorder"] == "paused"
        assert "egress recorder was paused (stopped by a signal)" in paused["issues"]

    restarted = recorder(same, {"active": "active", "main_pid": "11", "restarts": "1", "state": "S"})
    assert restarted["checks"]["egress_recorder"] == "restarted"
    assert "egress recorder restarted during the run" in restarted["issues"]
    # killed and left stopped after the restart: still reported as the restart
    both = recorder(same, {"active": "active", "main_pid": "11", "restarts": "1", "state": "T"})
    assert both["checks"]["egress_recorder"] == "restarted" and not both["ok"]
    # same PID but NRestarts moved: the restart check is untouched by the state check
    assert recorder(same, dict(same, restarts="1"))["checks"]["egress_recorder"] == "restarted"
    # state files written before the state field existed
    old = {"active": "active", "main_pid": "10", "restarts": "0"}
    assert recorder(old, old)["checks"]["egress_recorder"] == "running"
    assert recorder(same, dict(same, state=None))["checks"]["egress_recorder"] == "running"


def test_integrity_issues_and_dropped_packets():
    s0, s1 = cleanup_states()
    s1["self_digest"] = "self2"
    s1["egress_active"] = False
    s1["iptables"] = {"rules_sha256": "r2", "counters": {"udp_packets": 4, "other_packets": 1}}
    src = cleanup_sources()
    src["egress_bad_lines"] = 2
    run = run_record(iptables_start={"counters": {"udp_packets": 1, "other_packets": 1}})
    facts = diff.build_facts(s0, s1, run, src, CFG)
    assert facts["egress_denied"] == {"packets": 0}
    assert facts["system_noise"]["udp_packets"] == 3 and facts["system_noise"]["other_packets"] == 0
    assert facts["integrity"]["ok"] is False
    assert len(facts["integrity"]["issues"]) == 4


def test_noise_vs_script_attempt():
    """One system packet dropped: in scope. One packet from the rehearsal unit dropped: out of scope."""
    s0, s1 = cleanup_states()
    for s in (s0, s1):
        s.update(routes_sha256="rt1", egress_service={"active": "active", "main_pid": "10", "restarts": "0"})
    src = cleanup_sources()
    src["egress_records"] = []
    src["canary_defs"] = []
    scope = {"paths": ["/"], "tables": ["sessions"]}
    start = {"counters": {"udp_packets": 0, "other_packets": 0, "sandbox_packets": 0}}

    s1["iptables"] = {"rules_sha256": "r1", "counters": {"udp_packets": 0, "other_packets": 1, "sandbox_packets": 0}}
    s1["routes_sha256"] = "rt2"
    noise = finalize(diff.build_facts(s0, s1, run_record(iptables_start=start), src, CFG), scope)
    assert noise["summary"]["verdict"] == "in_scope", noise["out_of_scope"]
    assert noise["system_noise"]["other_packets"] == 1 and noise["system_noise"]["routes_changed"] is True
    assert noise["integrity"]["ok"] is True

    s1["iptables"] = {"rules_sha256": "r1", "counters": {"udp_packets": 0, "other_packets": 1, "sandbox_packets": 2}}
    script = finalize(diff.build_facts(s0, s1, run_record(iptables_start=start), src, CFG), scope)
    assert script["summary"]["verdict"] == "out_of_scope"
    assert script["egress_denied"] == {"packets": 2}
    assert [(e["kind"], e["op"], e["count"]) for e in script["out_of_scope"]] == [("network", "denied", 2)]
    assert script["ledger_sha256"] != noise["ledger_sha256"]


def _direct_ip_case(connects_end, connect_log, records=()):
    s0, s1 = cleanup_states()
    for s in (s0, s1):
        s.update(routes_sha256="rt1", egress_service={"active": "active", "main_pid": "10", "restarts": "0",
                                                      "state": "S"})
    start = {"counters": {"udp_packets": 0, "other_packets": 0, "sandbox_packets": 0, "sandbox_connects": 5}}
    s1["iptables"] = {"rules_sha256": "r1", "counters": {"udp_packets": 0, "other_packets": 0,
                                                         "sandbox_packets": 0, "sandbox_connects": connects_end}}
    src = cleanup_sources()
    src["egress_records"] = list(records)
    src["canary_defs"] = []
    src["connect_log"] = list(connect_log)
    scope = {"paths": ["/"], "tables": ["sessions"]}
    return finalize(diff.build_facts(s0, s1, run_record(iptables_start=start), src, CFG), scope)


def test_direct_ip_connection_counted_without_a_kernel_log_line():
    """The recorder never saw it and the kernel log is empty (no LOG in a container): the counter alone
    turns the verdict out of scope."""
    led = _direct_ip_case(6, [])
    assert led["egress"] == []
    assert led["egress_denied"] == {"packets": 1}
    assert [(e["kind"], e["op"], e["count"]) for e in led["out_of_scope"]] == [("network", "denied", 1)]
    assert led["summary"]["verdict"] == "out_of_scope"
    quiet = _direct_ip_case(5, [])
    assert quiet["summary"]["verdict"] == "in_scope" and quiet["egress_denied"] == {"packets": 0}


def test_direct_ip_connection_listed_from_the_kernel_log():
    log = [{"proto": "tcp", "dst": "172.31.77.10", "dpt": 8080, "uid": "0"},
           {"proto": "udp", "dst": "172.31.77.10", "dpt": 9998, "uid": "0"}]
    led = _direct_ip_case(6, log)
    assert led["egress"] == [
        {"kind": "tcp", "host": "172.31.77.10", "port": 8080, "bytes_attempted": 0, "delivered": 0,
         "source": "script", "blocked": "before handshake"},
        {"kind": "udp", "host": "172.31.77.10", "port": 9998, "bytes_attempted": 0, "delivered": 0,
         "source": "script", "blocked": "dropped by the firewall"},
    ]
    kinds = sorted((e["kind"], e["op"], e["item"]) for e in led["out_of_scope"])
    assert kinds == [("host", "tcp:8080", "172.31.77.10"), ("host", "udp:9998", "172.31.77.10"),
                     ("network", "denied", "outbound packets")]
    assert led["summary"]["egress_attempts"] == 2 and led["summary"]["egress_bytes_delivered"] == 0
    assert led["summary"]["verdict"] == "out_of_scope"


def test_direct_ip_connection_the_recorder_did_record_is_not_listed_twice():
    rec = {"kind": "http", "method": "POST", "host": "172.31.77.10", "orig_dst": "172.31.77.10", "port": 8080,
           "path": "/up", "bytes_attempted": 120, "delivered": 0, "unit": "rt-run-ab12.service",
           "canary_hits": []}
    log = [{"proto": "tcp", "dst": "172.31.77.10", "dpt": 8080},
           {"proto": "tcp", "dst": "172.31.77.10", "dpt": 8080}]
    led = _direct_ip_case(7, log, [rec])
    assert [(e.get("method"), e.get("path"), e.get("blocked")) for e in led["egress"]] == [
        (None, None, "before handshake"), ("POST", "/up", None)]
    # a record through a name (fake address) never pairs with a kernel log line
    named = dict(rec, host="hooks.partner.example", orig_dst="198.18.0.7", port=80)
    led = _direct_ip_case(6, log[:1], [named])
    assert len(led["egress"]) == 2


def test_connect_attempts_skips_unusable_lines():
    bad = [{"proto": "icmp", "dst": "1.2.3.4", "dpt": 1}, {"proto": "tcp", "dpt": 80},
           {"proto": "tcp", "dst": "1.2.3.4", "dpt": "80"}, {"dst": "1.2.3.4", "dpt": 80}]
    assert diff.connect_attempts(bad, []) == []
    assert diff.connect_attempts(None, []) == []


def test_file_hashes_and_path_meta_for_created_and_modified():
    """Finding 4 (tracer side): what each changed path holds, so compare can check content and mode."""
    big0 = {"t": "f", "size": 9000, "mode": 0o644, "uid": 0, "gid": 0, "mtime_ns": 1, "sha256": None,
            "ctime_ns": 5, "ino": 7}
    files0 = {"/srv": d(), "/srv/a": f("aa"), "/srv/big": big0, "/srv/old": f("oo"),
              "/srv/cur": {"t": "l", "mode": 0o777, "uid": 0, "gid": 0, "mtime_ns": 1, "target": "r1"},
              "/srv/dir": d()}
    files1 = {"/srv": d(), "/srv/a": f("ab"), "/srv/big": dict(big0, ctime_ns=6), "/srv/new": f("nn"),
              "/srv/cur": {"t": "l", "mode": 0o777, "uid": 0, "gid": 0, "mtime_ns": 2, "target": "r2"},
              "/srv/dir": dict(d(), mode=0o777), "/srv/newdir": d()}
    src = {"sql": [], "audit": [], "egress_records": [], "egress_bad_lines": 0, "canary_defs": [],
           "large_hashes": {}}
    facts = diff.build_facts(state(files0, {}), state(files1, {}), run_record(), src, CFG)
    assert facts["files"] == {"created": ["/srv/new"], "modified": ["/srv/a", "/srv/big", "/srv/cur"],
                              "deleted": ["/srv/old"]}
    assert facts["dirs"] == {"created": ["/srv/newdir"], "modified": ["/srv/dir"], "deleted": []}
    import hashlib
    assert facts["file_hashes"] == {"/srv/new": "nn", "/srv/a": "ab", "/srv/big": "size:9000:ctime:6:ino:7",
                                    "/srv/cur": "link:" + hashlib.sha256(b"r2").hexdigest()}
    assert facts["path_meta"] == {"/srv/new": "mode:0644:uid:0:gid:0", "/srv/a": "mode:0644:uid:0:gid:0",
                                  "/srv/big": "mode:0644:uid:0:gid:0", "/srv/cur": "mode:0777:uid:0:gid:0",
                                  "/srv/newdir": "mode:0755:uid:0:gid:0", "/srv/dir": "mode:0777:uid:0:gid:0"}
    src["large_hashes"] = {"/srv/big": "cc"}
    facts = diff.build_facts(state(files0, {}), state(files1, {}), run_record(), src, CFG)
    assert facts["file_hashes"]["/srv/big"] == "cc"
    ledger = finalize(facts, {"paths": ["/srv"]})
    assert ledger["ledger_sha256"] == ledger_sha256(ledger)
    # the hash covers the new fields
    other = finalize(dict(facts, file_hashes=dict(facts["file_hashes"], **{"/srv/a": "zz"})), {"paths": ["/srv"]})
    assert other["ledger_sha256"] != ledger["ledger_sha256"]


def test_recorder_egress_keeps_the_port():
    s0, s1 = cleanup_states()
    src = cleanup_sources()
    src["egress_records"].append({"kind": "tcp", "host": "prod-api.internal", "orig_dst": "198.18.0.1", "port": 25,
                                  "bytes_attempted": 12, "delivered": 0, "unit": "rt-run-ab12.scope",
                                  "canary_hits": []})
    eg = diff.build_facts(s0, s1, run_record(), src, CFG)["egress"]
    assert sorted((e["host"], e["port"]) for e in eg) == [("prod-api.internal", 25), ("prod-api.internal", 443)]


def test_integrity_flags_table_names_that_carry_backslashes_or_control_characters():
    s0, s1 = cleanup_states()
    key = 'public."orders \\! touch /tmp/x"'
    s1["pg"]["unsafe_names"] = [key]
    out = diff.build_facts(s0, s1, run_record(), cleanup_sources(), CFG)["integrity"]
    assert out["ok"] is False and out["checks"]["table_names"] == "unsafe"
    assert out["issues"] == ['table names with a backslash or control character: "public.\\"orders \\\\! touch /tmp/x\\""']
    many = dict(s1, pg=dict(s1["pg"], unsafe_names=[f"t{i}\\" for i in range(7)]))
    issue = diff.build_facts(s0, many, run_record(), cleanup_sources(), CFG)["integrity"]["issues"][0]
    assert issue.endswith("(+2 more)")


def test_integrity_postgres_unreadable_before_the_run_is_an_issue():
    """Without the tracer role on the machine every snapshot fails: that must not pass as 'no row changes'."""
    s0, s1 = cleanup_states()
    s0["pg"] = {"ok": False, "error": "psql exit 1: runuser: user rtrace does not exist", "tables": {}}
    s1["pg"] = dict(s0["pg"])
    out = diff.build_facts(s0, s1, run_record(), cleanup_sources(), CFG)["integrity"]
    assert "postgres state unreadable before the run: row changes are not traced" in out["issues"]
    off = {"ok": False, "error": "disabled", "tables": {}}
    out = diff.build_facts(dict(s0, pg=off), dict(s1, pg=off), run_record(), cleanup_sources(), CFG)["integrity"]
    assert out["ok"] is True


def test_integrity_auditd_stopped_restarted_paused():
    """Finding 12: auditd runs as root, the root script can signal it; decoy reads would go missing."""
    s0, s1 = cleanup_states()
    run = run_record(sandbox={"mode": "service", "ip_filter": "active"}, stats_recorded=True)

    def audit(a0, a1):
        return diff.build_facts(dict(s0, audit_service=a0), dict(s1, audit_service=a1), run, cleanup_sources(),
                                CFG)["integrity"]

    same = {"active": "active", "main_pid": "300", "restarts": "0", "state": "S"}
    ok = audit(same, same)
    assert ok["ok"] is True and ok["checks"]["auditd"] == "running"
    stopped = audit(same, {"active": "inactive", "main_pid": "0", "restarts": "0", "state": None})
    assert stopped["checks"]["auditd"] == "stopped" and not stopped["ok"]
    restarted = audit(same, dict(same, main_pid="301", restarts="1"))
    assert restarted["checks"]["auditd"] == "restarted" and not restarted["ok"]
    assert audit(same, dict(same, main_pid="301"))["checks"]["auditd"] == "restarted"
    for letter in ("T", "t"):
        paused = audit(same, dict(same, state=letter))
        assert paused["checks"]["auditd"] == "paused" and "auditd was paused (stopped by a signal)" in paused["issues"]
    # no auditd on the machine (a container without kernel audit): reported, not an issue
    absent = audit({"active": "inactive"}, {"active": "inactive"})
    assert absent["checks"]["auditd"] == "not running" and absent["ok"] is True
