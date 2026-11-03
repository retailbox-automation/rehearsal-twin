import copy

from rt.ledger.compare import compare, normalize


def twin_ledger():
    return {
        "files": {"created": [], "modified": ["/srv/app/tmp/cache/index"],
                  "deleted": ["/srv/app/tmp/cache/a", "/srv/app/tmp/cache/b"]},
        "dirs": {"created": [], "deleted": []},
        "rows": {"sessions": {"inserted": 0, "deleted": 240, "updated": 0},
                 "orders": {"inserted": 0, "deleted": 0, "updated": 0}},
        "egress": [
            {"kind": "https", "method": "POST", "host": "hooks.partner.example", "path": "/price-changed",
             "port": 443, "bytes_attempted": 120, "delivered": 0},
            {"kind": "https", "method": "POST", "host": "hooks.partner.example", "path": "/price-changed",
             "port": 443, "bytes_attempted": 121, "delivered": 0},
        ],
        "canaries": [{"id": "env-file", "touched": False, "exfil_attempt": False}],
        "exit": 0,
        "limits": {"oom": False, "wall_s": 0.3},
        "ledger_sha256": "t" * 64,
    }


def test_identical_prediction_matches():
    twin = twin_ledger()
    prod = copy.deepcopy(twin)
    prod["limits"]["wall_s"] = 0.9
    prod["egress"][0]["bytes_attempted"] = 999
    prod["ledger_sha256"] = "p" * 64
    res = compare(twin, prod)
    assert res["match"] is True
    assert res["surprises"] == []
    assert res["counts"] == {"predicted": 3 + 240 + 2, "happened": 3 + 240 + 2, "surprises": 0}
    assert res["twin_ledger_sha256"] == "t" * 64 and res["prod_ledger_sha256"] == "p" * 64


def test_normalization_of_paths_hosts_and_zero_rows():
    twin = twin_ledger()
    prod = copy.deepcopy(twin)
    prod["files"]["deleted"] = ["//srv/app/./tmp/cache/a", "/srv/app/tmp/cache/x/../b"]
    prod["egress"][1]["host"] = "HOOKS.partner.example."
    prod["rows"].pop("orders")
    assert compare(twin, prod)["match"] is True
    assert "orders" not in normalize(twin)["rows"]


def test_surprises_are_listed():
    twin = twin_ledger()
    prod = copy.deepcopy(twin)
    prod["files"]["deleted"].append("/srv/app/uploads/u1")
    prod["files"]["modified"] = []
    prod["rows"]["sessions"]["deleted"] = 250
    prod["egress"].append(dict(prod["egress"][0]))
    prod["exit"] = 1
    prod["canaries"][0]["touched"] = True
    res = compare(twin, prod)
    assert res["match"] is False
    got = {(s["kind"], s["item"]) for s in res["surprises"]}
    assert got == {
        ("file", "/srv/app/uploads/u1"),
        ("file", "/srv/app/tmp/cache/index"),
        ("rows", "sessions"),
        ("egress", "POST hooks.partner.example/price-changed"),
        ("canary", "canaries"),
        ("exit", "exit"),
    }
    by = {(s["kind"], s["item"]): s for s in res["surprises"]}
    assert by[("file", "/srv/app/uploads/u1")]["happened"] == "deleted"
    assert by[("file", "/srv/app/tmp/cache/index")]["predicted"] == "modified"
    assert by[("egress", "POST hooks.partner.example/price-changed")]["predicted"] == 2
    assert by[("egress", "POST hooks.partner.example/price-changed")]["happened"] == 3
    assert res["counts"]["surprises"] == 6


def test_dropped_table_flag_compared():
    twin = {"rows": {"legacy_orders": {"inserted": 0, "deleted": 800, "updated": 0, "dropped": True}}}
    prod = {"rows": {"legacy_orders": {"inserted": 0, "deleted": 800, "updated": 0}}}
    res = compare(twin, prod)
    assert [s["kind"] for s in res["surprises"]] == ["rows"]
