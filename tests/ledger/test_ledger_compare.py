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


# --- content, not counts (review finding 4) --------------------------------------------------

def _h(tag: str) -> str:
    import hashlib
    return hashlib.sha256(tag.encode()).hexdigest()


def content_ledger():
    led = twin_ledger()
    led["rows"]["sessions"]["digests"] = {"deleted": _h("sessions 0-239")}
    led["file_hashes"] = {"/srv/app/tmp/cache/index": _h("index v2"), "/srv/app/tmp/cache/a": None,
                          "/srv/app/tmp/cache/b": None}
    return led


def test_old_ledgers_compare_by_counts_and_say_so():
    twin = twin_ledger()
    res = compare(twin, copy.deepcopy(twin))
    assert res["match"] is True
    assert res["compare_basis"] == "counts"
    assert res["compare_detail"] == {"rows": "counts", "files": "paths", "egress": "port"}


def test_same_content_matches_on_content():
    twin = content_ledger()
    prod = copy.deepcopy(twin)
    prod["egress"][0]["bytes_attempted"] = 999
    res = compare(twin, prod)
    assert res["match"] is True and res["surprises"] == []
    assert res["compare_basis"] == "content"
    assert res["compare_detail"] == {"rows": "digests", "files": "sha256", "egress": "port"}


def test_same_counts_other_rows_is_a_surprise():
    # the twin deleted sessions 0-239, production deleted 1000-1239: 240 = 240, still not as rehearsed
    twin = content_ledger()
    prod = copy.deepcopy(twin)
    prod["rows"]["sessions"]["digests"] = {"deleted": _h("sessions 1000-1239")}
    res = compare(twin, prod)
    assert res["match"] is False
    assert [(s["kind"], s["item"]) for s in res["surprises"]] == [("rows", "sessions")]
    assert "different rows" in res["surprises"][0]["reason"]
    assert res["counts"]["predicted"] == res["counts"]["happened"]


def test_updated_rows_with_other_values_are_a_surprise():
    twin = content_ledger()
    twin["rows"]["prices"] = {"inserted": 0, "deleted": 0, "updated": 31,
                              "digests": {"updated": _h("k:+10%")}}
    prod = copy.deepcopy(twin)
    prod["rows"]["prices"]["digests"] = {"updated": _h("k:+90%")}
    res = compare(twin, prod)
    assert [(s["kind"], s["item"]) for s in res["surprises"]] == [("rows", "prices")]


def test_other_port_is_a_surprise():
    twin = content_ledger()
    prod = copy.deepcopy(twin)
    prod["egress"][1]["port"] = 25  # same method, host and path, other port
    res = compare(twin, prod)
    assert res["match"] is False
    ports = sorted((s["port"], s["predicted"], s["happened"]) for s in res["surprises"] if s["kind"] == "egress")
    assert ports == [(25, 0, 1), (443, 2, 1)]


def test_same_path_other_content_is_a_surprise():
    twin = content_ledger()
    prod = copy.deepcopy(twin)
    prod["file_hashes"]["/srv/app/tmp/cache/index"] = _h("index evil")
    res = compare(twin, prod)
    assert [(s["kind"], s["item"]) for s in res["surprises"]] == [("file_content", "/srv/app/tmp/cache/index")]
    prod["file_hashes"]["/srv/app/tmp/cache/index"] = None
    res = compare(twin, prod)
    assert res["surprises"][0]["reason"] == "content hashed on one side only"


def test_large_files_compare_by_size_and_mark_it_partial():
    twin = content_ledger()
    twin["file_hashes"]["/srv/app/tmp/cache/index"] = "size:5000000:ctime:1:ino:7"
    prod = copy.deepcopy(twin)
    prod["file_hashes"]["/srv/app/tmp/cache/index"] = "size:5000000:ctime:99:ino:12"
    res = compare(twin, prod)
    assert res["match"] is True and res["compare_basis"] == "counts"
    assert res["compare_detail"]["files"] == "partial"
    prod["file_hashes"]["/srv/app/tmp/cache/index"] = "size:5000001:ctime:99:ino:12"
    assert compare(twin, prod)["match"] is False


def test_one_old_side_falls_back_to_counts():
    twin = twin_ledger()
    prod = content_ledger()  # production traced by a newer tracer than the twin
    res = compare(twin, prod)
    assert res["match"] is True
    assert res["compare_basis"] == "counts"
    assert res["compare_detail"]["rows"] == "counts" and res["compare_detail"]["files"] == "paths"


def test_missing_port_on_one_side_compares_without_ports():
    twin = content_ledger()
    prod = copy.deepcopy(twin)
    prod["egress"][0].pop("port")
    res = compare(twin, prod)
    assert res["match"] is True
    assert res["compare_detail"]["egress"] == "no_port" and res["compare_basis"] == "counts"


def test_directory_mode_changes_are_compared_when_listed():
    twin = content_ledger()
    prod = copy.deepcopy(twin)
    prod["dirs"]["modified"] = ["/srv/app"]
    res = compare(twin, prod)
    assert [(s["kind"], s["item"], s["happened"]) for s in res["surprises"]] == [("dir", "/srv/app", "modified")]
