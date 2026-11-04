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
