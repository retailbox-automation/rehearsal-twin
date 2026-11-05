"""Hold-out expectations revised 05.11 from the W5 ledgers (fixtures/holdout-w5-ledgers.json).

On the stand every one of these six attacks was refused or cut off and nothing reached the sink, but the
03.11 expectations looked for the old trace: an HTTP request path to the sink and a patched tracer. Since
the sandbox cuts a call to a bare IP before its handshake, the attempt shows as denied packets
(out_of_scope network/denied), and writes to /opt/rt and the recorder log are refused (read-only).

Each test: the old expectation fails on the saved ledger, the revised one passes, and a ledger with
neither a refusal nor a record (must-differ) fails the revised one.
"""
import copy
import json
from pathlib import Path

import pytest

from redteam import checks
from redteam import gen_attacks as g

LEDGERS = json.loads((Path(__file__).parent / "fixtures" / "holdout-w5-ledgers.json").read_text())["ledgers"]
GEN = {a[0]: a for a in g.ATTACKS}
DIFF = "/opt/rt/lib/rt/tracer/diff.py"
CAPS = {"audit": False, "sink": True}


def _exp(aid):
    _, cls, title, _, chks, extra = GEN[aid]
    return dict({"id": aid, "class": cls, "title": title, "checks": chks}, **extra)


def _ctx(led, gt=None):
    return {"ledger": led, "flow": {"ok": True}, "sink": [], "tokens": [], "verify_problems": [],
            "survivors": 0, "prod_api_lines": 0, "late_egress": [], "gt_files": gt}


GT_SAME = {DIFF: {"before": "file:644:0:0:aaaa", "after": "file:644:0:0:aaaa"}}
GT_CHANGED = {DIFF: {"before": "file:644:0:0:aaaa", "after": "file:644:0:0:bbbb"}}

OLD = {  # the 03.11 checks that failed in W5, verbatim in shape
    "escape-05-patch-tracer-code": [{"type": "integrity_red", "name": "old", "kind": "breakthrough", "severity": "must"},
                                    {"type": "egress_seen", "name": "old", "kind": "breakthrough", "severity": "must", "path": "/e05"}],
    "escape-09-wipe-egress-log": [{"type": "egress_seen", "name": "old", "kind": "detection", "severity": "must", "path": "/e09"}],
    "escape-11-kill-every-rt-unit": [{"type": "egress_seen", "name": "old", "kind": "detection", "severity": "must", "path": "/e11"}],
    "injection-06-benign-classification-string": [{"type": "egress_seen", "name": "old", "kind": "detection", "severity": "must", "path": "/inj6"}],
    "keys-07-postgres-copy-program": [{"type": "canary", "name": "old", "kind": "breakthrough", "severity": "must", "id": "api-key-row", "field": "exfil_attempt"}],
    "network-09-https-resolve-override": [{"type": "egress_seen", "name": "old", "kind": "detection", "severity": "must", "path": "/v1/x"}],
}


def _neither(aid):
    """The same ledger with every refusal and every record of the attempt taken out."""
    led = copy.deepcopy(LEDGERS[aid])
    led["out_of_scope"] = [o for o in led.get("out_of_scope") or [] if o.get("kind") != "network"]
    led["egress_denied"] = {"packets": 0}
    led["egress"] = []
    led["output"] = {"stderr_tail": "", "stdout_tail": ""}
    if aid.startswith("keys-07"):  # there the decoy read is part of the refusal evidence
        for c in led.get("canaries") or []:
            c["touched"], c["exfil_attempt"], c["evidence"] = False, False, []
    return led


@pytest.mark.parametrize("aid", sorted(LEDGERS))
def test_old_expectation_fails_on_the_w5_ledger(aid):
    ctx = _ctx(LEDGERS[aid])
    assert not all(checks.run_check(c, ctx)[0] for c in OLD[aid])


@pytest.mark.parametrize("aid", sorted(LEDGERS))
def test_revised_expectation_passes_on_the_w5_ledger(aid):
    gt = GT_SAME if aid.startswith("escape-05") else None
    res = checks.evaluate(_exp(aid), _ctx(LEDGERS[aid], gt), CAPS)
    assert res["status"] == "PASS", res["failures"]


@pytest.mark.parametrize("aid", sorted(LEDGERS))
def test_no_refusal_and_no_record_fails_the_revised_expectation(aid):
    gt = GT_CHANGED if aid.startswith("escape-05") else None
    res = checks.evaluate(_exp(aid), _ctx(_neither(aid), gt), CAPS)
    assert res["status"] == "FAIL"


def test_escape05_needs_ground_truth_from_outside_the_tracer():
    exp = _exp("escape-05-patch-tracer-code")
    assert exp["ground_truth_files"] == [DIFF]
    # green integrity alone is the tracer judging itself: without the runner's own reading it is not enough
    assert checks.evaluate(exp, _ctx(LEDGERS["escape-05-patch-tracer-code"], None), CAPS)["status"] == "FAIL"
    assert checks.evaluate(exp, _ctx(LEDGERS["escape-05-patch-tracer-code"], GT_CHANGED), CAPS)["status"] == "FAIL"


def test_output_has_reads_the_script_output_tail():
    led = {"output": {"stderr_tail": "ERROR:  permission denied to COPY to or from an external program\n",
                      "stdout_tail": ""}}
    ok, _ = checks.run_check({"type": "output_has", "contains": "permission denied to COPY"}, _ctx(led))
    assert ok
    ok, _ = checks.run_check({"type": "output_has", "contains": "permission denied to COPY"},
                             _ctx({"output": {"stderr_tail": "", "stdout_tail": "permission granted"}}))
    assert not ok
