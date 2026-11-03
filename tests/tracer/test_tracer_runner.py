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


def test_build_command_sets_limits_and_wrapper():
    argv = runner.build_command("rt-run-ab12", "/opt/rt/work/s.sh", 536870912, 256, "/opt/rt/state/x.stats")
    assert argv[:3] == ["systemd-run", "--scope", "--quiet"]
    assert "--unit=rt-run-ab12" in argv
    assert "--slice=rt.slice" in argv
    assert "MemoryMax=536870912" in argv
    assert "MemorySwapMax=0" in argv
    assert "TasksMax=256" in argv
    assert "OOMPolicy=continue" in argv
    sep = argv.index("--")
    assert argv[sep + 1:sep + 3] == ["/bin/bash", "-c"]
    assert argv[-3:] == ["/opt/rt/state/x.stats", "/bin/bash", "/opt/rt/work/s.sh"]


def test_unit_names_are_unique():
    names = {runner.new_unit_name() for _ in range(50)}
    assert len(names) == 50 and all(n.startswith("rt-run-") for n in names)


def test_parse_stats_and_events():
    stats = runner.parse_stats("rc=137\nmemory_peak=536870912\noom_kill=1\noom=1\npids_max_events=\n")
    assert stats == {"rc": 137, "memory_peak": 536870912, "oom_kill": 1, "oom": 1, "pids_max_events": None}
    ev = runner.parse_memory_events("low 0\nhigh 0\nmax 12\noom 1\noom_kill 1\noom_group_kill 0\n")
    assert ev["oom_kill"] == 1 and ev["max"] == 12


def test_wrapper_reads_cgroup_after_script(tmp_path):
    """The wrapper runs the script and writes rc even where cgroup files are missing."""
    import subprocess
    stats = tmp_path / "s.stats"
    script = tmp_path / "s.sh"
    script.write_text("echo hi\nexit 3\n")
    p = subprocess.run(["/bin/bash", "-c", runner.WRAPPER, "rt-scope-wrap", str(stats), "/bin/bash", str(script)],
                       capture_output=True, text=True)
    assert p.returncode == 3
    assert p.stdout == "hi\n"
    assert runner.parse_stats(stats.read_text())["rc"] == 3
