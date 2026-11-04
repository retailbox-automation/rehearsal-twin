import os
import subprocess

import pytest

from rt.tracer import runner


def test_parse_size():
    assert runner.parse_size("512M") == 512 * 1024 * 1024
    assert runner.parse_size("1G") == 1024 ** 3
    assert runner.parse_size("64k") == 64 * 1024
    assert runner.parse_size("100") == 100
    assert runner.parse_size(7) == 7
    with pytest.raises(ValueError):
        runner.parse_size("lots")


def cmd():
    return runner.build_command("rt-run-ab12", "/opt/rt/work/s.sh", 536870912, 256, 60, "/opt/rt/state/x.stats",
                                "/opt/rt/state/rt-stoppost.sh", "/opt/rt/work")


def props(argv):
    return [argv[i + 1] for i, a in enumerate(argv) if a == "-p"]


def test_service_mode_command():
    argv = cmd()
    assert argv[:5] == ["systemd-run", "--wait", "--pipe", "--collect", "--quiet"]
    assert "--scope" not in argv
    assert "--unit=rt-run-ab12" in argv and "--slice=rt.slice" in argv
    assert "--working-directory=/opt/rt/work" in argv
    assert argv[argv.index("--") + 1:] == ["/bin/bash", "/opt/rt/work/s.sh"]
    p = props(argv)
    for want in ("MemoryMax=536870912", "MemorySwapMax=0", "TasksMax=256", "RuntimeMaxSec=60",
                 "OOMPolicy=continue", "IPAddressDeny=any", "IPAddressAllow=localhost",
                 "IPAddressAllow=198.18.0.0/15", "ProtectControlGroups=yes", "ProtectKernelModules=yes",
                 "ProtectKernelTunables=yes", "ProtectClock=yes", "RestrictAddressFamilies=AF_UNIX AF_INET AF_INET6",
                 "NoNewPrivileges=yes", "PrivateDevices=yes", "ProtectSystem=strict", "ProtectHome=read-only",
                 "PrivateTmp=yes", "ProtectProc=invisible"):
        assert want in p, want
    caps = next(x for x in p if x.startswith("CapabilityBoundingSet=~"))
    for cap in ("CAP_NET_ADMIN", "CAP_NET_RAW", "CAP_SYS_ADMIN", "CAP_SYS_MODULE", "CAP_SYS_PTRACE", "CAP_BPF",
                "CAP_SYS_BOOT", "CAP_SYS_RAWIO", "CAP_SYS_TIME", "CAP_MKNOD", "CAP_DAC_READ_SEARCH", "CAP_KILL"):
        assert cap in caps.split("~", 1)[1].split()
    ro = next(x for x in p if x.startswith("ReadOnlyPaths=")).split("=", 1)[1].split()
    for path in ("-/opt/rt", "-/etc/cron.d", "-/etc/systemd", "-/etc/ld.so.preload"):
        assert path in ro
    hidden = next(x for x in p if x.startswith("InaccessiblePaths=")).split("=", 1)[1].split()
    assert "-/run/systemd/private" in hidden and "-/run/dbus/system_bus_socket" in hidden
    assert not any(x.startswith("ReadWritePaths=") for x in p)  # nothing writable unless given
    assert p[-1] == "ExecStopPost=+/bin/bash /opt/rt/state/rt-stoppost.sh /opt/rt/state/x.stats rt-run-ab12.service"
    assert "IPAccounting=yes" in p
    assert not any("10.77.0.3" in x for x in p)
    assert not any(x.startswith("BindReadOnlyPaths=") for x in p)
    p2 = props(runner.build_command("u", "/s", 1, 1, 1, "/st", "/h", "/", resolv_path="/opt/rt/state/resolv.conf"))
    assert "BindReadOnlyPaths=/opt/rt/state/resolv.conf:/etc/resolv.conf" in p2


def test_sandbox_cannot_become_or_signal_another_user():
    """The recorder runs as rt-egress: the root script must not switch to that uid, signal it or see it."""
    p = props(cmd())
    caps = next(x for x in p if x.startswith("CapabilityBoundingSet=~")).split("~", 1)[1].split()
    for cap in ("CAP_SETUID", "CAP_SETGID", "CAP_KILL", "CAP_SYS_PTRACE"):
        assert cap in caps, cap
    assert "ProtectProc=invisible" in p
    assert "NoNewPrivileges=yes" in p  # no setuid binaries to get the capabilities back


def test_extra_allow_and_fractional_wall():
    argv = runner.build_command("u", "/s", 1, 1, 2.5, "/st", "/h", "/", allow=("10.77.0.3",))
    p = props(argv)
    assert "IPAddressAllow=10.77.0.3" in p and "RuntimeMaxSec=3" in p


def test_unit_names_are_unique():
    names = {runner.new_unit_name() for _ in range(50)}
    assert len(names) == 50 and all(n.startswith("rt-run-") for n in names)


def test_parse_stats_and_exit_codes():
    s = runner.parse_stats("service_result=exit-code\nexit_code=exited\nexit_status=3\nmemory_peak=4096\n"
                           "oom_kill=0\npids_max_events=\n")
    assert s == {"service_result": "exit-code", "exit_code": "exited", "exit_status": 3, "memory_peak": 4096,
                 "oom_kill": 0, "pids_max_events": None}
    assert runner.exit_from_stats(s, 99) == 3
    assert runner.exit_from_stats({"exit_code": "killed", "exit_status": "KILL"}, None) == 137
    assert runner.exit_from_stats({"exit_code": "dumped", "exit_status": "SEGV"}, None) == 139
    assert runner.exit_from_stats({}, -9) == 137
    assert runner.exit_from_stats({}, 2) == 2


def test_stoppost_helper_writes_systemd_result(tmp_path):
    helper = tmp_path / "sp.sh"
    helper.write_text(runner.STOPPOST)
    out = tmp_path / "x.stats"
    env = {"PATH": "/usr/bin:/bin", "SERVICE_RESULT": "timeout", "EXIT_CODE": "killed", "EXIT_STATUS": "TERM"}
    subprocess.run(["/bin/bash", str(helper), str(out)], env=env, check=True, capture_output=True)
    s = runner.parse_stats(out.read_text())
    assert s["service_result"] == "timeout" and runner.exit_from_stats(s, None) == 143


def test_run_refuses_without_ip_filter(tmp_path):
    script = tmp_path / "s.sh"
    script.write_text("echo should-not-run\n")
    res = runner.run_script(str(script), wall=5, mem="64M", pids=16, stats_dir=str(tmp_path / "state"),
                            preflight=lambda slice_name: (False, "cgroup IP filter not available"))
    assert res["exit"] is None
    assert res["error"].startswith("refusing to run")
    assert res["sandbox"] == {"mode": "service", "ip_filter": "unavailable",
                              "ip_filter_detail": "cgroup IP filter not available", "read_write": []}
    assert "unit_name" not in res


def test_strict_filesystem_writable_only_where_traced():
    """Finding 6: with ProtectSystem=yes /var, /opt, /mnt and /tmp were writable and not traced."""
    rw = ["/srv", "/etc", "/var/www", "/opt/shop", "/var/lib/app"]
    p = props(runner.build_command("u", "/s", 1, 1, 1, "/st", "/h", "/", rw_paths=rw))
    assert "ProtectSystem=strict" in p and "ProtectSystem=yes" not in p and "PrivateTmp=yes" in p
    assert "ReadWritePaths=-/srv -/etc -/var/www -/opt/shop -/var/lib/app" in p
    # read-only and hidden paths come after ReadWritePaths and are nested deeper, so they win
    order = [x.split("=", 1)[0] for x in p if x.split("=", 1)[0] in ("ReadWritePaths", "ReadOnlyPaths",
                                                                       "InaccessiblePaths")]
    assert order == ["ReadWritePaths", "ReadOnlyPaths", "InaccessiblePaths"]


def test_writable_paths_from_tracked_roots_and_scope():
    roots = ["/srv", "/etc", "/home", "/root", "/usr/local", "/var/spool/cron", "/var/www", "/opt/shop",
             "/var/lib/app", "/", "/usr", "/opt/rt/work", "/run/x", "/var/log/postgresql/x", "relative"]
    real = {"/var/www": "/data/www"}
    out = runner.writable_paths(roots, protected=["/opt/rt"], realpath=lambda p: real.get(p, p))
    assert out == ["/srv", "/etc", "/data/www", "/opt/shop", "/var/lib/app"]


def test_writable_paths_follow_symlinks_but_never_into_protected_trees():
    real = {"/srv": "/usr/local/srv", "/var/www": "/var/www", "/opt/shop": "/root/shop"}
    out = runner.writable_paths(["/srv", "/var/www", "/opt/shop"], realpath=lambda p: real.get(p, p))
    assert out == ["/var/www"]


def test_writable_paths_with_real_symlink(tmp_path):
    (tmp_path / "data").mkdir()
    (tmp_path / "link").symlink_to(tmp_path / "data")
    out = runner.writable_paths([str(tmp_path / "link")])
    assert out == [os.path.realpath(tmp_path / "data")]


def test_sandbox_hides_decoy_registry_ca_key_logs_and_user_manager():
    """Findings 13 and 16, and the logs that hold the decoy token or earlier decoy records."""
    p = props(cmd())
    hidden = next(x for x in p if x.startswith("InaccessiblePaths=")).split("=", 1)[1].split()
    for path in ("/opt/rt/canaries.json", "/opt/rt/egress", "/run/user", "/var/log/rt-egress",
                 "/var/log/postgresql", "/var/log/audit"):
        assert "-" + path in hidden, path
    ro = next(x for x in p if x.startswith("ReadOnlyPaths=")).split("=", 1)[1].split()
    assert not set(ro) & set(hidden)


def test_files_root_runs_later_stay_read_only_under_a_writable_etc():
    p = props(runner.build_command("u", "/s", 1, 1, 1, "/st", "/h", "/", rw_paths=["/etc"]))
    ro = next(x for x in p if x.startswith("ReadOnlyPaths=")).split("=", 1)[1].split()
    for path in ("/etc/update-motd.d", "/etc/logrotate.d", "/etc/logrotate.conf", "/etc/init.d", "/etc/rc.local",
                 "/etc/ld.so.cache", "/etc/cron.d", "/etc/systemd", "/etc/ssh", "/etc/pam.d", "/etc/profile.d"):
        assert "-" + path in ro, path


def test_script_env_and_extra_env():
    argv = runner.build_command("u", "/s", 1, 1, 1, "/st", "/h", "/", env=("PGUSER=shop",))
    envs = [argv[i + 1] for i, a in enumerate(argv) if a == "-E"]
    assert envs[-1] == "PGUSER=shop" and "HOME=/root" in envs
