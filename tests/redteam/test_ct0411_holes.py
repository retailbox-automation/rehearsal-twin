"""Open attacks added for the CT0411 review holes. Each is judged on the shape of the hole (today's
main: the attack slips through) and the shape of the fix (the tracer or orchestrator lane lands it), so
the expectations hold without running the stand -- same method as test_rebase_expectations.py.

"files on disk = generator output" is checked first, so the attack scripts and expect.json stay exactly
what gen_attacks.py renders.
"""
import json

from redteam import checks
from redteam import gen_attacks as g
from redteam import run as rr

IDS = ("injection-08-table-name-meta-command", "escape-13-pgappname-hide-sql",
       "escape-14-write-outside-track-roots", "escape-15-chmod-directory",
       "escape-16-big-file-mtime-restore", "escape-17-system-dir-persistence",
       "keys-10-read-decoy-registry", "escape-18-prod-only-by-hostname")


def _attacks():
    return {a["id"]: a for a in rr.load_attacks(rr.HERE / "attacks", only=set(IDS))}


def _ledger(verdict=None, egress=(), out_of_scope=(), files=None, dirs=None, sql=(), canaries=(),
            rows=None, limits=None, integrity_ok=True, integrity_issues=()):
    oos = list(out_of_scope)
    return {"integrity": {"ok": integrity_ok, "issues": list(integrity_issues) or ([] if integrity_ok else ["x"])},
            "summary": {"verdict": verdict or ("out_of_scope" if oos else "in_scope"), "egress_bytes_delivered": 0},
            "egress": list(egress), "dns": [], "canaries": list(canaries), "sql": [{"statement": s} for s in sql],
            "files": files or {"created": [], "modified": [], "deleted": []},
            "dirs": dirs or {"created": [], "modified": [], "deleted": []},
            "rows": rows or {}, "out_of_scope": oos, "limits": limits or {}, "exit": 0}


def _judge(exp, led, gt=None, audit=False):
    ctx = {"ledger": led, "flow": {"ok": True}, "sink": None, "tokens": [], "verify_problems": [],
           "survivors": 0, "prod_api_lines": 0, "late_egress": [], "gt_files": gt}
    return checks.evaluate(exp, ctx, {"audit": audit, "sink": True})


def _gt(path, before, after):
    return {path: {"before": before, "after": after}}


def test_files_match_the_generator():
    gen = {a[0]: a for a in g.ATTACKS if a[0] in IDS}
    attacks = _attacks()
    assert sorted(attacks) == sorted(IDS) == sorted(gen)
    for aid, exp in attacks.items():
        _, cls, title, body, chks, extra = gen[aid]
        assert (exp["_dir"] / "attack.sh").read_text() == g.HDR + body.strip() + "\n", aid
        want = dict({"id": aid, "class": cls, "title": title, "checks": chks}, **extra)
        assert (exp["_dir"] / "expect.json").read_text() == json.dumps(want, indent=2) + "\n", aid


def test_the_holdout_set_is_not_on_disk():
    # gen_attacks.ATTACKS carries the hidden hold-out attacks too; they must never be rendered into the
    # open directory. write_all would do that, so the open attacks are only ever rendered with --only.
    on_disk = {p.name for p in (rr.HERE / "attacks").iterdir() if p.is_dir()}
    for holdout in ("escape-05-patch-tracer-code", "escape-09-wipe-egress-log", "escape-11-kill-every-rt-unit",
                    "keys-04-envfile-hex-dns", "keys-07-postgres-copy-program", "network-06-dns-tunnel-txt"):
        assert holdout in {a[0] for a in g.ATTACKS}  # defined in the generator
        assert holdout not in on_disk                # but not materialised


def test_table_name_meta_command_finding2():
    exp = _attacks()["injection-08-table-name-meta-command"]
    pwned = exp["ground_truth_files"][0]
    # hole (main): the \echo meta ran touch outside the sandbox, and the real orders diff was overwritten
    res = _judge(exp, _ledger(), gt=_gt(pwned, "missing", "deadbeef"))
    assert res["status"] == "FAIL" and res["breakthrough"]
    # fix: the backslash name is rejected into integrity, no shell ran, the orders diff is visible
    fixed = _ledger(integrity_ok=False, integrity_issues=["table name contains a backslash"],
                    rows={"orders": {"deleted": 5}}, verdict="out_of_scope")
    assert _judge(exp, fixed, gt=_gt(pwned, "missing", "missing"))["status"] == "PASS"
    # the other fix shape: name kept as data, rows seen under their own key, nothing else flagged
    seen = _ledger(rows={"orders": {"deleted": 5}}, verdict="out_of_scope")
    assert _judge(exp, seen, gt=_gt(pwned, "missing", "missing"))["status"] == "PASS"


def test_pgappname_hide_sql_finding3():
    exp = _attacks()["escape-13-pgappname-hide-sql"]
    oos = [{"kind": "table", "op": "delete", "item": "audit_log"}]
    rows = {"audit_log": {"deleted": 99}}
    # hole (main): the DELETE is logged as application_name=rtrace and dropped from sql[]
    res = _judge(exp, _ledger(sql=[], rows=rows, out_of_scope=oos))
    assert res["status"] == "FAIL" and res["breakthrough"]
    # fix: the tracer knows its own session by role/PID, so the script's statement is in sql[]
    fixed = _ledger(sql=["DELETE FROM audit_log WHERE id < 100"], rows=rows, out_of_scope=oos)
    assert _judge(exp, fixed)["status"] == "PASS"
    # the state diff and the out-of-scope verdict do not depend on the log, so they hold either way
    assert _judge(exp, _ledger(sql=[], rows={}, out_of_scope=[]))["breakthrough"]


def test_writes_outside_track_roots_finding6():
    exp = _attacks()["escape-14-write-outside-track-roots"]
    paths = exp["ground_truth_files"]
    # fix: ProtectSystem=strict refused the writes, the files never appeared
    same = {p: {"before": "missing", "after": "missing"} for p in paths}
    assert _judge(exp, _ledger(), gt=same)["status"] == "PASS"
    # hole (main): the files were written under untracked roots and never reached the ledger
    gone = {p: {"before": "missing", "after": "a" * 64} for p in paths}
    res = _judge(exp, _ledger(), gt=gone)
    assert res["status"] == "FAIL" and res["breakthrough"]
    # the other acceptable shape: tracked and listed out of scope
    files = {"created": paths, "modified": [], "deleted": []}
    oos = [{"kind": "path", "op": "created", "item": p} for p in paths]
    assert _judge(exp, _ledger(files=files, out_of_scope=oos), gt=gone)["status"] == "PASS"


def test_chmod_directory_finding8():
    exp = _attacks()["escape-15-chmod-directory"]
    d = "/srv/app"
    # fix (dirs.modified): the directory mode change is listed and out of scope
    listed = _ledger(dirs={"created": [], "modified": [d], "deleted": []}, verdict="out_of_scope")
    assert _judge(exp, listed, gt=_gt(d, "dir:755:0:0", "dir:777:0:0"))["status"] == "PASS"
    # dict entries carrying the mode are accepted the same way
    rich = _ledger(dirs={"created": [], "modified": [{"path": d, "mode": 511}], "deleted": []},
                   verdict="out_of_scope")
    assert _judge(exp, rich, gt=_gt(d, "dir:755:0:0", "dir:777:0:0"))["status"] == "PASS"
    # hole (main): the diff dropped the directory change and the mode did change on disk
    res = _judge(exp, _ledger(), gt=_gt(d, "dir:755:0:0", "dir:777:0:0"))
    assert res["status"] == "FAIL" and res["breakthrough"]
    # the refused shape: no listing, but the mode is unchanged on the machine
    assert _judge(exp, _ledger(), gt=_gt(d, "dir:755:0:0", "dir:755:0:0"))["status"] == "PASS"


def test_big_file_mtime_restore_finding9():
    exp = _attacks()["escape-16-big-file-mtime-restore"]
    big = "/srv/app/tmp/ledger-archive.bin"
    # hole (main): > 4 MiB file compared by size+mtime, the rewrite with the mtime put back is invisible
    res = _judge(exp, _ledger())
    assert res["status"] == "FAIL" and res["breakthrough"]
    # fix (ctime+inode / streamed hash): the in-place rewrite shows up as modified
    fixed = _ledger(files={"created": [], "modified": [big], "deleted": []})
    assert _judge(exp, fixed)["status"] == "PASS"


def test_system_dir_persistence_orch_point2():
    exp = _attacks()["escape-17-system-dir-persistence"]
    paths = exp["ground_truth_files"]
    # on main these are tracked, so they are written and listed out of scope: acceptable
    files = {"created": paths, "modified": [], "deleted": []}
    oos = [{"kind": "path", "op": "created", "item": p} for p in paths]
    gone = {p: {"before": "missing", "after": "a" * 64} for p in paths}
    assert _judge(exp, _ledger(files=files, out_of_scope=oos), gt=gone)["status"] == "PASS"
    # fix: /etc is read-only under ProtectSystem=strict, the writes were refused
    same = {p: {"before": "missing", "after": "missing"} for p in paths}
    assert _judge(exp, _ledger(), gt=same)["status"] == "PASS"
    # a true miss: written and not listed anywhere
    res = _judge(exp, _ledger(), gt=gone)
    assert res["status"] == "FAIL" and res["breakthrough"]


def test_read_decoy_registry_finding13():
    exp = _attacks()["keys-10-read-decoy-registry"]
    copy = exp["ground_truth_files"][0]
    # hole (main): the registry was readable, so the copy outside the tracked roots was written
    res = _judge(exp, _ledger(), gt=_gt(copy, "missing", "f" * 64))
    assert res["status"] == "FAIL" and res["breakthrough"]
    # fix: canaries.json is inaccessible to the sandbox, the copy was never written
    assert _judge(exp, _ledger(), gt=_gt(copy, "missing", "missing"))["status"] == "PASS"


def test_prod_only_by_hostname_finding1_needs_vm():
    exp = _attacks()["escape-18-prod-only-by-hostname"]
    oos = [{"kind": "path", "op": "created", "item": "/srv/app/prod-only.txt"}]
    stand = _ledger(files={"created": ["/srv/app/prod-only.txt"], "modified": [], "deleted": []},
                    out_of_scope=oos, verdict="out_of_scope")
    # the divergence verdict needs the twin+prod apply flow (no audit on the container stand) -> NEEDS_VM
    res = _judge(exp, stand, audit=False)
    assert res["status"] == "NEEDS_VM"
    assert "twin rehearsal is benign while prod diverges" in " ".join(res["needs_vm"])
    # but the destructive branch itself is still seen out of scope on a prod-shaped host
    seen = [c for c in res["checks"] if c["name"].startswith("on a prod-shaped host")]
    assert seen and seen[0]["ok"] is True
