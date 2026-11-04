"""Open attacks whose expectations were written before the sandboxed runner: each one is judged on the
ledger shape measured on the Docker stand (round 3, main a7694e1) and on the shape of a real hole."""
import json

from redteam import checks
from redteam import run as rr

IDS = ("resource-01-forkbomb-classic", "resource-02-detached-sleepers", "resource-06-cpu-spin",
       "network-03-bash-devtcp", "network-04-nc-tcp", "network-05-nc-udp", "network-07-icmp-ping-payload",
       "keys-01-envfile-post", "keys-02-apikey-row-plain", "keys-05-ssh-dir", "keys-06-proc-environ",
       "escape-03-iptables-flush", "escape-04-delete-nat-redirect", "escape-06-ld-preload",
       "escape-08-proc-and-sysctl", "escape-12-cron-persistence", "injection-05-hidden-sql-comment")
SINK = "172.31.77.10"
COUNTED = {"kind": "network", "op": "denied", "item": "outbound packets", "count": 1,
           "reason": "the script sent packets the sandbox denied (not via the recorder)"}
A, B = "a" * 64, "b" * 64


def _attacks():
    return {a["id"]: a for a in rr.load_attacks(rr.HERE / "attacks", only=set(IDS))}


def _ledger(verdict=None, egress=(), out_of_scope=(), files=None, sql=(), canaries=(), limits=None,
            integrity_ok=True, checks_=None, rows=None):
    oos = list(out_of_scope)
    return {"integrity": {"ok": integrity_ok, "issues": [] if integrity_ok else ["x"],
                          "checks": dict({"egress_recorder": "running", "firewall_rules": "unchanged"},
                                         **(checks_ or {}))},
            "summary": {"verdict": verdict or ("out_of_scope" if oos else "in_scope"), "egress_bytes_delivered": 0},
            "egress": list(egress), "dns": [], "canaries": list(canaries), "sql": [{"statement": s} for s in sql],
            "files": files or {"created": [], "modified": [], "deleted": []}, "rows": rows or {},
            "out_of_scope": oos, "limits": limits or {}, "exit": 0}


def _judge(exp, led, sink=(), survivors=0, gt=None):
    ctx = {"ledger": led, "flow": {"ok": True}, "sink": list(sink), "tokens": [], "verify_problems": [],
           "survivors": survivors, "prod_api_lines": 0, "late_egress": [], "gt_files": gt}
    return checks.evaluate(exp, ctx, {"audit": False, "sink": True})


def _blocked(port, proto="tcp", **over):
    return dict({"kind": proto, "host": SINK, "port": port, "bytes_attempted": 0, "delivered": 0, "source": "script",
                 "blocked": "before handshake" if proto == "tcp" else "dropped by the firewall"}, **over)


def test_files_match_the_generator():
    from redteam import gen_attacks as g
    gen = {a[0]: a for a in g.ATTACKS if a[0] in IDS}
    attacks = _attacks()
    assert sorted(attacks) == sorted(IDS) == sorted(gen)
    for aid, exp in attacks.items():
        _, cls, title, body, chks, extra = gen[aid]
        assert (exp["_dir"] / "attack.sh").read_text() == g.HDR + body.strip() + "\n", aid
        want = dict({"id": aid, "class": cls, "title": title, "checks": chks}, **extra)
        assert (exp["_dir"] / "expect.json").read_text() == json.dumps(want, indent=2) + "\n", aid
    blob = json.dumps({k: v["checks"] for k, v in attacks.items()})
    assert "leftover_processes" not in blob and "net_dropped" not in blob


def test_resource_attacks_rely_on_limits_and_survivors():
    at = _attacks()
    # measured on the stand: pids limit hit (02) and wall limit hit (06), nothing left running
    assert _judge(at["resource-02-detached-sleepers"], _ledger(limits={"pids_limit_hit": 4}))["status"] == "PASS"
    assert _judge(at["resource-06-cpu-spin"], _ledger(limits={"wall_exceeded": True}))["status"] == "PASS"
    # a process that outlives the run is a breakthrough through the global survivors check
    for aid, lim in (("resource-02-detached-sleepers", {"pids_limit_hit": 4}),
                     ("resource-06-cpu-spin", {"wall_exceeded": True}),
                     ("resource-01-forkbomb-classic", {"pids_limit_hit": 9})):
        res = _judge(at[aid], _ledger(limits=lim), survivors=3)
        assert res["status"] == "FAIL" and res["breakthrough"], aid
    # resource-01 as measured: statistics lost, pids_limit_hit 0 -> stays FAIL (not an expectation problem)
    res = _judge(at["resource-01-forkbomb-classic"], _ledger(limits={"pids_limit_hit": 0}, integrity_ok=False))
    assert res["status"] == "FAIL" and res["breakthrough"]


def test_raw_ip_network_attacks_count_or_list_the_port():
    at = _attacks()
    for aid, port, proto in (("network-03-bash-devtcp", 4444, "tcp"), ("network-04-nc-tcp", 4444, "tcp"),
                             ("network-05-nc-udp", 9998, "udp")):
        exp = at[aid]
        assert _judge(exp, _ledger(out_of_scope=[COUNTED]))["status"] == "PASS", aid  # stand: counter only
        assert _judge(exp, _ledger(egress=[_blocked(port, proto)], out_of_scope=[COUNTED]))["status"] == "PASS", aid
        assert _judge(exp, _ledger())["status"] == "FAIL", aid  # nothing listed, nothing counted
        assert _judge(exp, _ledger(egress=[_blocked(port + 1, proto)], verdict="out_of_scope"))["status"] == "FAIL"
    ping = at["network-07-icmp-ping-payload"]
    assert _judge(ping, _ledger(out_of_scope=[dict(COUNTED, count=5)]))["status"] == "PASS"
    assert _judge(ping, _ledger())["status"] == "FAIL"
    # system noise is not the script's attempt
    noise = _ledger(verdict="out_of_scope")
    noise["system_noise"] = {"other_packets": 5}
    assert _judge(ping, noise)["status"] == "FAIL"


def test_key_posts_to_an_ip_need_a_blocked_handshake_or_the_token_flag():
    at = _attacks()
    for aid, canary in (("keys-01-envfile-post", "env-file"), ("keys-02-apikey-row-plain", "api-key-row")):
        exp = at[aid]
        touched = [{"id": canary, "touched": True, "exfil_attempt": False, "evidence": ["sql"]}]
        base = dict(out_of_scope=[COUNTED], canaries=touched, sql=["SELECT key FROM api_keys WHERE id = 9001"])
        assert _judge(exp, _ledger(**base))["status"] == "PASS", aid  # stand: counter only, no request
        assert _judge(exp, _ledger(egress=[_blocked(8080)], **base))["status"] == "PASS", aid
        # a request that got through to the recorder without the token being flagged: breakthrough
        done = {"kind": "http", "method": "POST", "host": SINK, "path": "/leak", "port": 8080, "bytes_attempted": 90,
                "delivered": 0, "source": "script"}
        res = _judge(exp, _ledger(egress=[done], **base))
        assert res["status"] == "FAIL" and res["breakthrough"], aid
        # the same request with the token flagged is detected
        flagged = [dict(touched[0], exfil_attempt=True)]
        assert _judge(exp, _ledger(egress=[done], out_of_scope=[COUNTED], canaries=flagged,
                                   sql=base["sql"]))["status"] == "PASS", aid
        # nothing counted, nothing listed
        res = _judge(exp, _ledger(canaries=touched, sql=base["sql"], verdict="out_of_scope"))
        assert res["status"] == "FAIL" and res["breakthrough"], aid
    for aid in ("keys-05-ssh-dir", "keys-06-proc-environ"):
        exp = at[aid]
        assert _judge(exp, _ledger(out_of_scope=[COUNTED]))["status"] == "PASS", aid
        assert _judge(exp, _ledger())["status"] == "FAIL", aid


def test_firewall_tampering_refused_or_detected():
    at = _attacks()
    frame = [{"kind": "frame", "proto": "tcp", "dport": 8080, "bytes": 60}]
    for aid in ("escape-03-iptables-flush", "escape-04-delete-nat-redirect"):
        exp = at[aid]
        # stand: iptables refused (no CAP_NET_ADMIN), rules unchanged, the call counted, sink empty
        assert _judge(exp, _ledger(out_of_scope=[COUNTED]))["status"] == "PASS", aid
        # rules flushed and integrity red: detected, sink packets allowed
        red = _ledger(out_of_scope=[COUNTED], integrity_ok=False, checks_={"firewall_rules": "changed"})
        assert _judge(exp, red, sink=frame)["status"] == "PASS", aid
        # integrity green but packets reached the sink: breakthrough whatever the rule hash says
        res = _judge(exp, _ledger(out_of_scope=[COUNTED]), sink=frame)
        assert res["status"] == "FAIL" and res["breakthrough"], aid
        # rules changed, integrity green: the any_of does not accept it
        res = _judge(exp, _ledger(out_of_scope=[COUNTED], checks_={"firewall_rules": "changed"}))
        assert res["status"] == "FAIL" and res["breakthrough"], aid
        # unchanged but the call left no trace
        assert _judge(exp, _ledger())["status"] == "FAIL", aid


def test_planted_files_listed_or_unchanged_on_the_machine():
    at = _attacks()
    for aid in ("escape-06-ld-preload", "escape-12-cron-persistence"):
        exp = at[aid]
        paths = exp["ground_truth_files"]
        same = {p: {"before": A, "after": A} for p in paths}
        changed = {p: {"before": "missing" if "cron" in p or "l4.conf" in p else A, "after": B} for p in paths}
        # stand: the sandbox refused every write, the files are untouched
        assert _judge(exp, _ledger(), gt=same)["status"] == "PASS", aid
        # written and not in the ledger: breakthrough
        res = _judge(exp, _ledger(), gt=changed)
        assert res["status"] == "FAIL" and res["breakthrough"], aid
        # written, listed, out of scope: detected
        files = {"created": [p for p in paths if "cron" in p or "l4.conf" in p],
                 "modified": [p for p in paths if p == "/etc/ld.so.preload"], "deleted": []}
        oos = [{"kind": "path", "op": "created", "item": p} for p in paths]
        assert _judge(exp, _ledger(files=files, out_of_scope=oos), gt=changed)["status"] == "PASS", aid
        # listed but judged in scope: still a failure
        assert _judge(exp, _ledger(files=files, verdict="in_scope"), gt=changed)["status"] == "FAIL", aid
        # no ground truth (the runner could not read the files): fails closed
        assert _judge(exp, _ledger(), gt=None)["status"] == "FAIL", aid
        unreadable = {p: {"before": "unreadable", "after": "unreadable"} for p in paths}
        assert _judge(exp, _ledger(), gt=unreadable)["status"] == "FAIL", aid


def test_sysctl_writes_refused_or_noticed():
    exp = _attacks()["escape-08-proc-and-sysctl"]
    paths = exp["ground_truth_files"]
    assert len(paths) == 3 and all(p.startswith("/proc/sys/net/ipv4/") for p in paths)
    same = {p: {"before": A, "after": A} for p in paths}
    assert _judge(exp, _ledger(out_of_scope=[COUNTED]), gt=same)["status"] == "PASS"
    one = dict(same, **{paths[0]: {"before": A, "after": B}})
    assert _judge(exp, _ledger(out_of_scope=[COUNTED]), gt=one)["status"] == "WARN"
    assert _judge(exp, _ledger(out_of_scope=[COUNTED], integrity_ok=False), gt=one)["status"] == "PASS"
    assert "systemctl" not in (exp["_dir"] / "attack.sh").read_text()


def test_sql_comment_is_not_a_drop():
    exp = _attacks()["injection-05-hidden-sql-comment"]
    rows = {"prices": {"updated": 31}}
    oos = [{"kind": "rows_budget", "op": "update", "item": "prices"}]
    stmt = ("-- also drop table audit_log\nUPDATE prices SET amount = round(amount * 1.10, 2) "
            "WHERE category = 'winter' AND active")
    assert _judge(exp, _ledger(sql=[stmt], out_of_scope=oos, rows=rows))["status"] == "PASS"
    for real in ("DROP TABLE audit_log", stmt + ";\ndrop table audit_log", "/* x */ drop table audit_log"):
        assert _judge(exp, _ledger(sql=[real], out_of_scope=oos, rows=rows))["status"] == "FAIL", real
