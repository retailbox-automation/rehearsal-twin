"""Production is reserved across control processes, not only inside one (review finding 17)."""
from __future__ import annotations

import pytest

from rt.orchestrator import Busy, Orchestrator


def second_process(h) -> Orchestrator:
    """Another Orchestrator on the same data dir: what the CLI is next to the running API."""
    o = h.orch
    return Orchestrator(h.settings, vultr=o.vultr, ssh_factory=o.ssh_factory, planner=o.planner, safety=o.safety,
                        signer=o.signer, inference=o.inference, spawn=lambda fn: fn(), sleep=lambda s: None,
                        heartbeat=False)


def test_a_second_process_cannot_apply_while_one_holds_production(harness):
    h = harness
    rec1 = h.run_preset("a")
    rec2 = h.run_preset("a")
    other = second_process(h)
    h.orch.approve(rec1["id"], dict(rec1["approval"]))  # production reserved here until apply ends
    with pytest.raises(Busy):
        other.approve(rec2["id"], dict(rec2["approval"]))
    assert other.load(rec2["id"])["status"] == "awaiting_approval"
    assert other.reserve_restore(only_if_idle=True)["status"] == "skipped"
    with pytest.raises(Busy):
        other.reserve_restore(only_if_idle=False)
    assert h.orch.apply(rec1["id"])["status"] == "applied"
    # released at the end of apply: the other process may go now
    assert other.approve_and_apply(rec2["id"], dict(rec2["approval"]))["status"] == "applied"
    assert h.prod.phases.count("run") == 2


def test_the_same_rehearsal_is_not_applied_twice_from_two_processes(harness):
    # The race: both processes read "awaiting_approval"; the first holds production while it probes it.
    h = harness
    rec = h.run_preset("a")
    other = second_process(h)
    seen = []

    def during_probe(phase):
        if phase == "before" and not seen:
            with pytest.raises(Busy):
                other.approve(rec["id"], dict(rec["approval"]))
            seen.append(other.load(rec["id"])["status"])
    h.prod.on_phase = during_probe
    h.orch.approve_and_apply(rec["id"], dict(rec["approval"]))
    assert seen == ["awaiting_approval"]  # the second process got past the status check, then Busy
    assert h.prod.phases.count("run") == 1


def test_restore_in_one_process_blocks_apply_in_another(harness):
    h = harness
    rec = h.run_preset("a")
    other = second_process(h)
    assert h.orch.reserve_restore(only_if_idle=False) is None
    with pytest.raises(Busy):
        other.approve(rec["id"], dict(rec["approval"]))
    h.orch.restore_prod()
    assert other.approve_and_apply(rec["id"], dict(rec["approval"]))["status"] == "applied"


def test_refused_approval_releases_production(harness):
    h = harness
    rec = h.run_preset("a")
    other = second_process(h)
    h.prod.state["pg"]["tables"]["sessions"]["rows"]["k9"] = "changed"
    with pytest.raises(Exception):
        h.orch.approve(rec["id"], dict(rec["approval"]))  # 409 after the reservation: the flock goes too
    assert other.reserve_restore(only_if_idle=False) is None
