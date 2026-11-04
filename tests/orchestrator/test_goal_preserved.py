"""Goal preserved: a safer variant that is in scope but does none of the task is not approvable.

Live run 04.11, preset b: the original dropped legacy_orders (in scope) and orders and audit_log
(out of scope). The safer script read /etc/app/schema_tables.txt, which does not exist, its guard
skipped the migration, it exited 0 and changed nothing, and it was approved as a no-op.
"""
from __future__ import annotations



from rt.orchestrator import goal
from tests.orchestrator.conftest import EXPLAIN_A, REPO
from tests.orchestrator.fakes import sha

B_SCRIPT = (REPO / "presets" / "b-migrate" / "migrate_0042.sh").read_bytes()
B_SCOPE = {"paths": [], "tables": ["legacy_orders"], "hosts": []}
DROP_B = ("set -euo pipefail\n"
          "psql shop -v ON_ERROR_STOP=1 -c 'BEGIN; DROP TABLE IF EXISTS legacy_orders; COMMIT;'\n")


def noop_script(i: int) -> str:
    return ("set -euo pipefail\n"
            f"# variant {i}\n"
            "[ -f /etc/app/schema_tables.txt ] || { echo 'no table list, nothing to do'; exit 0; }\n")


def facts(dropped=(), rows=None) -> dict:
    r = {t: {"inserted": 0, "deleted": 800, "updated": 0, "dropped": True} for t in dropped}
    r.update(rows or {})
    return {"version": 1, "files": {"created": [], "modified": [], "deleted": []},
            "dirs": {"created": [], "modified": [], "deleted": []},
            "rows": r, "sql": [], "egress": [], "dns": [], "canaries": [], "exit": 0, "limits": {"oom": False},
            "integrity": {"ok": True, "issues": []}}


ORIGINAL_B = facts(dropped=("legacy_orders", "orders", "audit_log"))
NOTHING = facts()


def explain_with(script: str) -> dict:
    return {**EXPLAIN_A, "safer_script": script, "notes": [], "why_safer": "drops legacy_orders by name only"}


def explain_requests(h) -> list[str]:
    return [b["messages"][1]["content"] for b in h.inference_fake.bodies()
            if (b.get("response_format") or {}).get("json_schema", {}).get("name") == "rehearsal_explain"]


def run_b(h, original: dict, safer: list[tuple[str, dict]]) -> dict:
    h.fleet.twin_ledgers[sha(B_SCRIPT)] = original
    for script, f in safer:
        h.fleet.twin_ledgers[sha(script.encode())] = f
    h.explain_replies += [explain_with(script) for script, _ in safer]
    return h.run_preset("b")


# ---------------------------------------------------------------- unit: the effect sets

def test_in_scope_effects_leave_out_of_scope_items():
    assert goal.in_scope_effects(ORIGINAL_B, B_SCOPE) == {("table", "dropped", "legacy_orders"),
                                                         ("table", "deleted", "legacy_orders")}
    assert goal.in_scope_effects(NOTHING, B_SCOPE) == set()
    f = facts()
    f["files"]["deleted"] = ["/srv/app/tmp/cache/a.bin", "/srv/app/uploads/u.dat"]
    f["dirs"]["modified"] = ["/srv/app/tmp/cache"]
    assert goal.in_scope_effects(f, {"paths": ["/srv/app/tmp"]}) == {("file", "deleted", "/srv/app/tmp/cache/a.bin"),
                                                                     ("dir", "modified", "/srv/app/tmp/cache")}


def test_check_names_the_missing_effect_and_skips_an_empty_task():
    task = goal.in_scope_effects(ORIGINAL_B, B_SCOPE)
    found = goal.check(task, set())
    assert found["reason"] == ("the safer script did nothing the task needs: "
                               "expected e.g. legacy_orders dropped, legacy_orders rows deleted")
    assert goal.check(task, {("table", "dropped", "legacy_orders")}) is None
    assert goal.check(set(), set()) is None


# ---------------------------------------------------------------- the attempt loop

def test_noop_safer_is_no_effect_then_a_real_variant_is_approvable(harness):
    h = harness
    rec = run_b(h, ORIGINAL_B, [(noop_script(1), NOTHING), (DROP_B, facts(dropped=("legacy_orders",)))])
    assert rec["status"] == "awaiting_approval", rec.get("error")
    a1, a2, a3 = rec["attempts"]
    assert (a1["kind"], a1["verdict"]) == ("original", "out_of_scope")
    assert (a2["kind"], a2["verdict"], a2["exit"], a2["status"], a2["acceptable"]) == (
        "safer", "in_scope", 0, "no_effect", False)
    assert a2["goal_check"]["expected"] == ["legacy_orders dropped", "legacy_orders rows deleted"]
    assert (a3["status"], a3["acceptable"]) == ("done", True) and rec["approvable"] == 3
    assert rec["approval"]["ledger_sha256"] == a3["ledger_sha256"]
    assert rec["task_effects"] == {"total": 2, "examples": ["legacy_orders dropped", "legacy_orders rows deleted"]}

    events = h.events(rec["id"])
    no_effect = [e["data"] for e in events if e["type"] == "no_effect"]
    assert len(no_effect) == 1 and no_effect[0]["n"] == 2
    assert "expected e.g. legacy_orders dropped" in no_effect[0]["reason"]

    # the reason reaches the next explain input; the first explain had no <rejected> block
    first, second = explain_requests(h)
    assert "<rejected>" not in first
    assert "<rejected>\nthe safer script did nothing the task needs: expected e.g. legacy_orders dropped" in second

    view = h.orch.view(rec["id"])
    assert [a["status_text"] for a in view["attempts"]][1].startswith(
        "no effect: the safer script did nothing the task needs: expected e.g. legacy_orders dropped")
    assert "no_effect" in [t["type"] for t in view["timeline"]]


def test_safer_that_drops_legacy_orders_is_approvable_at_once(harness):
    h = harness
    rec = run_b(h, ORIGINAL_B, [(DROP_B, facts(dropped=("legacy_orders",)))])
    assert rec["status"] == "awaiting_approval", rec.get("error")
    assert [a["status"] for a in rec["attempts"]] == ["done", "done"] and rec["approvable"] == 2
    assert not [e for e in h.events(rec["id"]) if e["type"] == "no_effect"]


def test_original_without_in_scope_effects_does_not_apply_the_rule(harness):
    h = harness
    rec = run_b(h, facts(dropped=("orders", "audit_log")), [(noop_script(1), NOTHING)])
    assert rec["status"] == "awaiting_approval", rec.get("error")
    assert rec["task_effects"] == {"total": 0, "examples": []}
    assert [a["status"] for a in rec["attempts"]] == ["done", "done"] and rec["approvable"] == 2


def test_only_noop_variants_end_in_no_safe_variant(harness):
    h = harness
    rec = run_b(h, ORIGINAL_B, [(noop_script(i), NOTHING) for i in (1, 2, 3)])
    assert rec["status"] == "no_safe_variant"
    assert [a["status"] for a in rec["attempts"]] == ["done", "no_effect", "no_effect", "no_effect"]
    assert "expected e.g. legacy_orders dropped" in rec["error"]
    assert rec["approval"] is None and rec["approvable"] is None


# ---------------------------------------------------------------- companion files in the explain input

def test_explain_input_names_the_companion_file_by_relative_name(harness):
    h = harness
    run_b(h, ORIGINAL_B, [(DROP_B, facts(dropped=("legacy_orders",)))])
    (user,) = explain_requests(h)
    block = user[user.index("<files>"):user.index("</files>")]
    assert "current working directory" in block and "- schema_tables.txt" in block
    assert "`schema_tables.txt`" in block
