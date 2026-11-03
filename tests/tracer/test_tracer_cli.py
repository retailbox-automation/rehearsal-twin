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


def test_route_lifetimes_do_not_count_as_changes():
    a = ("default via fe80::1 dev enp1s0 proto ra metric 100 expires 26sec hoplimit 64 pref medium\n"
         "10.77.0.0/24 dev enp1s0 proto kernel scope link src 10.77.0.5 metric 100\n")
    b = a.replace("expires 26sec", "expires 23sec")
    assert cli.normalize_routes(a) == cli.normalize_routes(b)
    c = a.replace("10.77.0.0/24", "10.78.0.0/24")
    assert cli.normalize_routes(a) != cli.normalize_routes(c)


def test_tracked_roots_add_declared_paths_outside_defaults():
    cfg = {"track_roots": ["/srv", "/etc"]}
    assert cli.tracked_roots(cfg, None) == ["/srv", "/etc"]
    assert cli.tracked_roots(cfg, {"paths": ["/srv/app/tmp", "/var/lib/app"]}) == ["/srv", "/etc", "/var/lib/app"]
