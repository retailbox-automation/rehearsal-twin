import os

from rt.tracer import cli


def test_self_digest_ignores_work_state_certs_and_bytecode(tmp_path):
    root = tmp_path / "rt"
    for d in ("bin", "work", "state", "egress/certs", "lib/rt/__pycache__"):
        os.makedirs(root / d)
    (root / "bin" / "rtrace").write_text("v1\n")
    cfg = {"self_root": str(root)}
    d0 = cli.self_digest(cfg)
    (root / "work" / "s.state0.json").write_text("{}")
    (root / "state" / "rt-run-x.stats").write_text("rc=0")
    (root / "egress" / "certs" / "prod-api.internal.pem").write_text("cert")
    (root / "lib" / "rt" / "__pycache__" / "cli.cpython-312.pyc").write_bytes(b"\0")
    assert cli.self_digest(cfg) == d0
    (root / "bin" / "rtrace").write_text("tampered\n")
    assert cli.self_digest(cfg) != d0


def test_process_state_from_fake_proc(tmp_path):
    def stat(pid, text):
        (tmp_path / str(pid)).mkdir()
        (tmp_path / str(pid) / "stat").write_text(text)

    stat(10, "10 (python3) S 1 10 10 0 -1 4194560 2185 0 0 0 5 3 0 0 20 0 3 0 1234\n")
    stat(11, "11 (python3) T 1 11 11 0 -1 4194560 2185 0 0 0 5 3 0 0 20 0 3 0 1234\n")
    stat(12, "12 (odd) name (x) t 1 12 12 0 -1 0\n")
    root = str(tmp_path)
    assert cli.process_state("10", root) == "S"
    assert cli.process_state(11, root) == "T"
    assert cli.process_state("12", root) == "t"
    for missing in ("13", "0", "", None, "abc", "-1"):
        assert cli.process_state(missing, root) is None


def test_egress_service_reports_the_main_process_state(tmp_path, monkeypatch):
    (tmp_path / "42").mkdir()
    (tmp_path / "42" / "stat").write_text("42 (python3) T 1 42 42 0 -1 0\n")
    seen = {}

    def fake_show(unit, *props):
        seen["unit"], seen["props"] = unit, props
        return {"ActiveState": "active", "MainPID": "42", "NRestarts": "0"}

    monkeypatch.setattr(cli.runner, "show", fake_show)
    assert cli.egress_service(str(tmp_path)) == {"active": "active", "main_pid": "42", "restarts": "0", "state": "T"}
    assert seen == {"unit": "rt-egress.service", "props": ("ActiveState", "MainPID", "NRestarts")}
    monkeypatch.setattr(cli.runner, "show", lambda unit, *props: {"ActiveState": "inactive", "MainPID": "0"})
    assert cli.egress_service(str(tmp_path))["state"] is None


def test_read_sources_parses_drops_and_connects_from_one_kernel_log_read(tmp_path, monkeypatch):
    calls = []
    klog = ("1.0 twin kernel: rt-egress sandbox-connect: IN= OUT=eth0 SRC=10.0.0.2 DST=192.0.2.5 LEN=60 "
            "PROTO=TCP SPT=40000 DPT=443 UID=0 GID=0\n"
            "1.1 twin kernel: rt-egress other: IN= OUT=eth0 SRC=10.0.0.2 DST=192.0.2.6 LEN=40 PROTO=TCP "
            "SPT=1 DPT=80\n")

    def fake_kernel_log(since, until):
        calls.append((since, until))
        return klog

    monkeypatch.setattr(cli, "kernel_log", fake_kernel_log)
    cfg = {"pg": {"log_path": str(tmp_path / "pg.log")}, "audit_log": str(tmp_path / "audit.log"),
           "egress_log": str(tmp_path / "egress.jsonl"), "canaries_path": str(tmp_path / "canaries.json")}
    src = cli.read_sources(cfg, {"offsets": {}}, {"offsets": {}, "taken_epoch": 20.0}, {"started_at": 10.0})
    assert calls == [(10.0, 20.0)]
    assert src["connect_log"] == [{"proto": "tcp", "dst": "192.0.2.5", "dpt": 443, "uid": "0"}]
    assert [r["chain"] for r in src["drop_log"]] == ["other"]


def test_kernel_log_needs_a_window():
    assert cli.kernel_log(None, 20.0) == "" and cli.kernel_log(10.0, None) == ""


def test_route_lifetimes_do_not_count_as_changes():
    a = ("default via fe80::1 dev enp1s0 proto ra metric 100 expires 26sec hoplimit 64 pref medium\n"
         "10.77.0.0/24 dev enp1s0 proto kernel scope link src 10.77.0.5 metric 100\n")
    b = a.replace("expires 26sec", "expires 23sec")
    assert cli.normalize_routes(a) == cli.normalize_routes(b)
    c = a.replace("10.77.0.0/24", "10.78.0.0/24")
    assert cli.normalize_routes(a) != cli.normalize_routes(c)


class _P:
    def __init__(self, rc, out=""):
        self.returncode, self.stdout = rc, out


def test_decoy_watch_rearm(tmp_path):
    decoy = tmp_path / ".env.canary"
    decoy.write_text("x\n")
    defs = [{"id": "env-file", "kind": "file", "path": str(decoy), "audit_key": "rt_canary_env"}]
    calls = []

    def listed(rules):
        def run(args):
            calls.append(args)
            return _P(0, rules) if args == ["-l"] else _P(0)
        return run

    assert cli.decoy_watches(defs, True, listed(f"-w {decoy} -p rwa -k rt_canary_env\n")) == "armed"
    calls.clear()
    assert cli.decoy_watches(defs, False, listed("No rules\n")) == "missing"
    assert calls == [["-l"]]
    assert cli.decoy_watches(defs, True, listed("No rules\n")) == "rearmed"
    assert calls[-1] == ["-w", str(decoy), "-p", "rwa", "-k", "rt_canary_env"]
    assert cli.decoy_watches(defs, True, lambda args: None) == "unavailable"
    decoy.unlink()
    assert cli.decoy_watches(defs, True, listed("No rules\n")) == "missing"
    assert cli.decoy_watches([], True, listed("")) == "none"


def test_tracked_roots_add_declared_paths_outside_defaults():
    cfg = {"track_roots": ["/srv", "/etc"]}
    assert cli.tracked_roots(cfg, None) == ["/srv", "/etc"]
    assert cli.tracked_roots(cfg, {"paths": ["/srv/app/tmp", "/var/lib/app"]}) == ["/srv", "/etc", "/var/lib/app"]


def test_run_makes_tracked_roots_and_scope_writable_and_logs_in_as_the_script_role(tmp_path, monkeypatch):
    """Finding 6 (writable = traced) and finding 3/5 (PGUSER=shop) wired through `rtrace run`."""
    seen = {}

    def fake_run_script(script, **kw):
        seen.update(kw)
        return {"script": script, "sandbox": {"mode": "service"}}

    monkeypatch.setattr(cli.runner, "run_script", fake_run_script)
    monkeypatch.setattr(cli, "iptables_state", lambda: {})
    monkeypatch.setattr(cli, "log_offsets", lambda cfg: {})
    monkeypatch.setattr(cli.runner.os.path, "realpath", lambda p: p)  # this Mac has /etc -> /private/etc
    scope = tmp_path / "scope.json"
    scope.write_text('{"paths": ["/srv/app/tmp", "/var/lib/app", "/usr/local/bin"]}')
    cfg = {"track_roots": ["/srv", "/etc", "/root", "/usr/local", "/var/spool/cron"], "exclude": ["/opt/rt"],
           "self_root": str(tmp_path), "pg": {"script_user": "shop"}}

    class A:
        script, wall, mem, pids, cwd = "/opt/rt/work/r/script.sh", 60, "512M", 256, None

    a = A()
    a.scope = str(scope)
    cli.cmd_run(a, cfg)
    assert seen["rw_paths"] == ["/srv", "/etc", "/var/lib/app"]
    assert seen["env"] == ("PGUSER=shop",)
    a.scope = None
    cli.cmd_run(a, cfg)
    assert seen["rw_paths"] == ["/srv", "/etc"]
    cli.cmd_run(a, dict(cfg, pg={}))
    assert seen["env"] == ()


def test_capture_records_auditd_state(monkeypatch):
    calls = []
    monkeypatch.setattr(cli.runner, "show", lambda unit, *p: calls.append(unit) or {"ActiveState": "active",
                                                                                     "MainPID": "0"})
    assert cli.audit_service()["active"] == "active"
    assert calls == ["auditd.service"]
