import json
import os

import pytest

from redteam import run as rr


def test_load_attacks_reads_generated_set():
    attacks = rr.load_attacks(rr.HERE / "attacks")
    assert len(attacks) >= 30
    ids = {a["id"] for a in attacks}
    assert len(ids) == len(attacks)
    classes = {a["class"] for a in attacks}
    assert classes == {"resource", "network", "keys", "escape", "injection"}


def test_load_attacks_only_filter():
    attacks = rr.load_attacks(rr.HERE / "attacks", only={"resource-01-forkbomb-classic"})
    assert [a["id"] for a in attacks] == ["resource-01-forkbomb-classic"]


def test_redact_strips_token_values():
    obj = {"detail": "leaked ABC123 right here", "nested": ["ABC123", "fine"]}
    out = rr.redact(obj, ["ABC123"])
    assert "ABC123" not in json.dumps(out)
    assert "<token>" in out["detail"]


def test_container_guard_rejects_wrong_prefix():
    with pytest.raises(rr.GuardError):
        rr.check_container_guard(lambda argv: (0, "ok"), "some-other-name", "img:local", "host")


def test_container_guard_rejects_inspect_mismatch():
    def run(argv):
        if argv[1] == "inspect":
            return 0, "/rt-l4-prod|true|wrong-image:local"
        return 0, "systemd host"
    with pytest.raises(rr.GuardError):
        rr.check_container_guard(run, "rt-l4-prod", "img:local", "host")


def test_container_guard_rejects_hostname_equal_to_host():
    def run(argv):
        if argv[1] == "inspect":
            return 0, "/rt-l4-prod|true|img:local"
        return 0, "systemd samehost"
    with pytest.raises(rr.GuardError):
        rr.check_container_guard(run, "rt-l4-prod", "img:local", "samehost")


def test_container_guard_passes_for_a_real_stand_container():
    def run(argv):
        if argv[1] == "inspect":
            return 0, "/rt-l4-prod|true|img:local"
        return 0, "systemd rt-l4-container-not-this-host"
    rr.check_container_guard(run, "rt-l4-prod", "img:local", "this-host")


def test_ssh_target_guard_requires_confirmation():
    t = rr.SshTarget("root@1.2.3.4", confirmed=False, reset_cmd=None)
    with pytest.raises(rr.GuardError):
        t.guard()


def test_ssh_target_guard_refuses_localhost():
    t = rr.SshTarget("root@localhost", confirmed=True, reset_cmd=None)
    with pytest.raises(rr.GuardError):
        t.guard()


def test_summarize_counts_breakthroughs_and_classes():
    results = [
        {"status": "PASS", "breakthrough": False, "class": "network"},
        {"status": "FAIL", "breakthrough": True, "class": "network"},
        {"status": "FAIL", "breakthrough": False, "class": "resource"},
    ]
    s = rr.summarize(results)
    assert s["attacks"] == 3
    assert s["breakthroughs"] == 1
    assert s["by_status"]["PASS"] == 1
    assert s["by_status"]["FAIL"] == 2
    assert s["by_class"] == {"network": 2, "resource": 1}


def test_compact_fact_trims_the_ledger():
    led = {"summary": {"verdict": "out_of_scope"}, "integrity": {"ok": True, "issues": []},
           "files": {"created": ["a", "b"], "modified": [], "deleted": []},
           "rows": {}, "egress": [{"host": "x"}] * 10, "dns": [], "egress_dropped": {},
           "canaries": [], "sql": [{"statement": "SELECT 1"}], "out_of_scope": [{"kind": "table"}]}
    facts = {"flow": {"ok": True}, "run": {"exit": 0, "limits": {"wall_s": 1}}, "survivors": 0,
             "late_egress": [], "prod_api_lines": 0, "ledger": led}
    out = rr.compact_fact(facts, sink=[{"a": 1}])
    assert out["verdict"] == "out_of_scope"
    assert out["files"] == {"created": 2, "modified": 0, "deleted": 0}
    assert len(out["egress"]) == 6
    assert out["sink_events"] == 1


def test_stand_addresses_default_and_override():
    expected_net24 = os.environ.get("RT_L4_NET24", "172.31.77")
    assert (rr.SUBNET, rr.SINK_IP, rr.CONTROL_IP, rr.GATEWAY) == rr.stand_addresses(expected_net24)
    assert rr.stand_addresses("172.31.77") == ("172.31.77.0/24", "172.31.77.10", "172.31.77.250", "172.31.77.1")
    assert rr.stand_addresses("10.213.77") == ("10.213.77.0/24", "10.213.77.10", "10.213.77.250", "10.213.77.1")
    for bad in ("10.213", "10.213.77.0", "10.213.x", "300.1.1", ""):
        with pytest.raises(ValueError):
            rr.stand_addresses(bad)


def test_stand_image_masks_systemd_binfmt():
    # a privileged systemd stand shares the Docker VM's binfmt_misc: its systemd-binfmt must never run
    assert set(rr.BINFMT_MASKED) == {"systemd-binfmt.service", "proc-sys-fs-binfmt_misc.automount",
                                     "proc-sys-fs-binfmt_misc.mount"}
    for unit in rr.BINFMT_MASKED:
        assert unit in rr.DOCKERFILE
    assert 'ln -sf /dev/null "/etc/systemd/system/$u"' in rr.DOCKERFILE


def test_up_refuses_unmasked_binfmt(monkeypatch):
    calls = []

    def fake_sh(argv, input=None, timeout=120, check=False):
        calls.append(argv)
        if argv[:2] == ["docker", "run"] and "readlink" in argv:
            return 0, "/lib/systemd/system/systemd-binfmt.service\n", ""   # not masked
        return 0, "", ""

    monkeypatch.setattr(rr, "sh", fake_sh)
    t = rr.DockerTarget()
    with pytest.raises(rr.GuardError):
        t.up()
    assert not any(a[:3] == ["docker", "network", "create"] for a in calls)  # nothing was started
    assert not any("--privileged" in a for a in calls)


def test_up_checks_every_masked_unit(monkeypatch):
    seen = []

    def fake_sh(argv, input=None, timeout=120, check=False):
        if argv[:2] == ["docker", "run"] and "readlink" in argv:
            seen.append(argv[-1])
            return 0, "/dev/null\n", ""
        raise RuntimeError("stop after the binfmt check")

    monkeypatch.setattr(rr, "sh", fake_sh)
    with pytest.raises(RuntimeError, match="stop after the binfmt check"):
        rr.DockerTarget().up()
    assert seen == [f"/etc/systemd/system/{u}" for u in rr.BINFMT_MASKED]
