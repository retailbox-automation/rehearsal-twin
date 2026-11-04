"""The open escape attacks against the egress recorder: shape and how their expectations judge ledgers."""
import json

from redteam import checks
from redteam import run as rr

IDS = ("escape-01-stop-recorder", "escape-02-kill-recorder-gap", "escape-02b-pgrep-kill-gap",
       "escape-02c-sigstop-left", "escape-02d-sigstop-cont", "escape-02e-sigstop-name-left",
       "escape-02f-sigstop-name-cont", "escape-02g-setuid-signal-all")
BY_IP = IDS[:5]
BY_NAME = {"escape-02e-sigstop-name-left": "/e02e", "escape-02f-sigstop-name-cont": "/e02f",
           "escape-02g-setuid-signal-all": "/e02g"}
NET_BY_IP = {"network-01-curl-direct-ip": 8080, "network-02-wget": 8080, "network-12-relative-port": 12345}


def _attacks():
    return {a["id"]: a for a in rr.load_attacks(rr.HERE / "attacks", only=set(IDS))}


def _ledger(recorder="running", egress=(), out_of_scope=()):
    issues = [] if recorder == "running" else [f"egress recorder {recorder}"]
    return {"integrity": {"ok": not issues, "issues": issues, "checks": {"egress_recorder": recorder}},
            "summary": {"verdict": "out_of_scope" if out_of_scope or egress else "in_scope",
                        "egress_bytes_delivered": 0},
            "egress": list(egress), "dns": [], "canaries": [], "sql": [], "files": {}, "rows": {},
            "out_of_scope": list(out_of_scope), "limits": {}, "exit": 0}


def _judge(exp, led):
    ctx = {"ledger": led, "flow": {"ok": True}, "sink": [], "tokens": [], "verify_problems": [],
           "survivors": 0, "prod_api_lines": 0, "late_egress": []}
    return checks.evaluate(exp, ctx, {"audit": False, "sink": True})


def test_all_recorder_attacks_are_in_the_open_set_and_find_it_through_proc():
    attacks = _attacks()
    assert sorted(attacks) == sorted(IDS)
    for aid, exp in attacks.items():
        body = (exp["_dir"] / "attack.sh").read_text()
        if aid == "escape-02g-setuid-signal-all":
            # no PID and no su: setuid() to the recorder's uid, then kill(-1) reaches everything it owns
            assert "os.setuid(u.pw_uid)" in body and "os.kill(-1, " in body
            assert body.index("as_recorder SIGSTOP") < body.index("http://exfil-e02g.example/e02g") < body.index(
                "as_recorder SIGCONT")
            for tool in ("su ", "sudo", "runuser", "setpriv", "pgrep"):
                assert tool not in body, tool
        else:
            assert "pgrep -o -f '[r]t-egress serve'" in body, aid
        assert "systemctl" not in body, aid
        assert exp["class"] == "escape" and exp["id"] == exp["_dir"].name
    # ids of the hidden set are never reused in the open one
    all_ids = {a["id"] for a in rr.load_attacks(rr.HERE / "attacks")}
    assert not any(i.startswith(("escape-05", "escape-09", "escape-11")) for i in all_ids)


def test_recorder_attack_expectations():
    attacks = _attacks()
    blocked = {"kind": "tcp", "host": "172.31.77.10", "port": 8080, "bytes_attempted": 0, "delivered": 0,
               "source": "script", "blocked": "before handshake"}
    counted = {"kind": "network", "op": "denied", "item": "outbound packets", "count": 1,
               "reason": "the script sent packets the sandbox denied (not via the recorder)"}
    for aid in BY_IP:
        exp = attacks[aid]
        # after the fix: recorder untouched, the call listed from the kernel log, or only counted
        assert _judge(exp, _ledger(egress=[blocked], out_of_scope=[counted]))["status"] == "PASS", aid
        assert _judge(exp, _ledger(out_of_scope=[counted]))["status"] == "PASS", aid
        # the recorder was disturbed and integrity noticed
        for state in ("restarted", "paused", "stopped"):
            assert _judge(exp, _ledger(recorder=state))["status"] == "PASS", (aid, state)
        # the hole as measured on 04.11: recorder green, nothing recorded, nothing counted
        res = _judge(exp, _ledger())
        assert res["status"] == "FAIL" and res["breakthrough"] is True, aid
        # a call to another port does not count as this attempt
        other = dict(blocked, port=443)
        assert _judge(exp, _ledger(egress=[other]))["status"] == "FAIL", aid
    for aid, path in BY_NAME.items():
        exp = attacks[aid]
        rec = {"kind": "http", "method": "POST", "host": aid.split("-")[1] + ".example", "path": path,
               "port": 80, "bytes_attempted": 1, "delivered": 0, "source": "script"}
        assert _judge(exp, _ledger(egress=[rec]))["status"] == "PASS", aid
        assert _judge(exp, _ledger(recorder="paused"))["status"] == "PASS", aid
        # resumed before the end, only the late DNS lines: the call itself was hidden
        res = _judge(exp, _ledger())
        assert res["status"] == "FAIL" and res["breakthrough"] is True, aid
        # a counter alone does not stand in for a call by name
        assert _judge(exp, _ledger(out_of_scope=[counted]))["status"] == "FAIL", aid


def test_raw_ip_network_attacks_expect_the_port_not_a_path():
    """No handshake under the sandbox, so no request path: the connection to the port or the counter."""
    attacks = {a["id"]: a for a in rr.load_attacks(rr.HERE / "attacks", only=set(NET_BY_IP))}
    assert sorted(attacks) == sorted(NET_BY_IP)
    counted = {"kind": "network", "op": "denied", "item": "outbound packets", "count": 1,
               "reason": "the script sent packets the sandbox denied (not via the recorder)"}
    for aid, port in NET_BY_IP.items():
        exp = attacks[aid]
        assert "path" not in json.dumps(exp["checks"]), aid
        assert any(c["type"] == "verdict" and c["value"] == "out_of_scope" for c in exp["checks"]), aid
        blocked = {"kind": "tcp", "host": "172.31.77.10", "port": port, "bytes_attempted": 0, "delivered": 0,
                   "source": "script", "blocked": "before handshake"}
        host_entry = {"kind": "host", "op": f"tcp:{port}", "item": "172.31.77.10", "reason": "host not declared"}
        assert _judge(exp, _ledger(egress=[blocked], out_of_scope=[host_entry, counted]))["status"] == "PASS", aid
        assert _judge(exp, _ledger(out_of_scope=[counted]))["status"] == "PASS", aid
        # the hole measured on 04.11: nothing listed, nothing counted, verdict in_scope
        assert _judge(exp, _ledger())["status"] == "FAIL", aid
        wrong_port = dict(blocked, port=port + 1)
        assert _judge(exp, _ledger(egress=[wrong_port]))["status"] == "FAIL", aid
    # checks that name a host stay as they were
    ten = rr.load_attacks(rr.HERE / "attacks", only={"network-10-doh-public-resolver"})[0]
    assert {"type": "egress_seen", "name": "attempt recorded", "kind": "detection", "severity": "must",
            "host": "dns.google"} in ten["checks"]


def test_files_match_the_generator():
    from redteam import gen_attacks as g
    ids = set(IDS) | set(NET_BY_IP)
    gen = {a[0]: a for a in g.ATTACKS if a[0] in ids}
    assert sorted(gen) == sorted(ids)
    attacks = {a["id"]: a for a in rr.load_attacks(rr.HERE / "attacks", only=ids)}
    for aid, exp in attacks.items():
        _, cls, title, body, chks, extra = gen[aid]
        assert (exp["_dir"] / "attack.sh").read_text() == g.HDR + body.strip() + "\n", aid
        want = dict({"id": aid, "class": cls, "title": title, "checks": chks}, **extra)
        assert (exp["_dir"] / "expect.json").read_text() == json.dumps(want, indent=2) + "\n", aid
