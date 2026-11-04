import hashlib

from rt.tracer import pgstate

S = pgstate.SEP
EVIL = "orders \\! touch /tmp/PWNED_postgres"


def hx(s: str) -> str:
    return s.encode().hex()


def tline(oid, schema, name, pk="", digest="d0", kind="r", cols=("id",), vol="0"):
    return S.join(["T", str(oid), kind, hx(schema), hx(name), hx(pk), digest, ",".join(hx(c) for c in cols), vol])


def rline(oid, key, row, stable=None, sig="a" * 16):
    return S.join(["R", str(oid), key, row, stable or row, sig])


def val(row, stable=None, sig="a" * 16):
    return f"{row}:{stable or row}:{sig}"


def psql_meta_commands(script: str) -> list:
    """Backslash commands psql would run: a backslash outside quotes starts one (man psql), the
    command runs to the end of the line or to the next unquoted backslash."""
    out, i, quote = [], 0, None
    while i < len(script):
        c = script[i]
        if quote:
            if c == quote:
                quote = None
        elif c in ("'", '"'):
            quote = c
        elif c == "\\":
            j = i + 1
            while j < len(script) and script[j] not in "\\\n":
                j += 1
            out.append(script[i:j].strip())
            i = j
            continue
        i += 1
    return out


def test_psql_argv_runs_as_the_tracer_role():
    argv = pgstate.psql_argv({"pg": {"dbname": "shop", "run_as": "rtrace"}})
    assert argv[:4] == ["runuser", "-u", "rtrace", "--"]
    assert "dbname=shop" in argv[-1]
    assert "ON_ERROR_STOP=1" in argv


def test_the_psql_script_is_the_same_text_for_every_database():
    """Finding 2: a table name is never written into the psql script, so it cannot be a meta-command."""
    seen = []

    def runner(script, cfg):
        seen.append(script)
        return "\n".join([tline(16400, "public", "orders", "id"), tline(16401, "public", EVIL, "id")]) + "\n"

    pgstate.snapshot({"pg": {}}, runner=runner)
    pgstate.snapshot({"pg": {}}, runner=lambda s, c: seen.append(s) or "")
    assert seen == [pgstate.SNAPSHOT_SCRIPT, pgstate.SNAPSHOT_SCRIPT]
    script = seen[0]
    # The only backslash command is \gexec, which sends server-built statements straight to the server.
    assert psql_meta_commands(script) == ["\\gexec"]
    assert "\\echo" not in script and "orders" not in script and "touch" not in script
    # Names are quoted by the server (format %I) and travel back hex-encoded.
    assert "%I.%I" in script and "encode(convert_to(tbl.relname, 'UTF8'), 'hex')" in script


def test_meta_command_finder_sees_the_old_injection():
    """Control for the test above: the finder does catch `\\!` in an \\echo line like the old script's."""
    old_style = f"\\echo @@T {EVIL}\nSELECT 1;\n"
    assert psql_meta_commands(old_style) == ["\\echo @@T orders", "\\! touch /tmp/PWNED_postgres"]
    assert psql_meta_commands('SELECT "a\\!b", \'c\\!d\';\n') == []


def test_table_with_backslash_name_is_traced_under_its_own_key():
    out = "\n".join([
        tline(16400, "public", "orders", "id", "s1"),
        tline(16401, "public", EVIL, "id", "s2"),
        rline(16400, "k1", "r1"), rline(16400, "k2", "r2"),
        rline(16401, "k1", "x1"),
    ]) + "\n"
    snap = pgstate.snapshot({"pg": {}}, runner=lambda s, c: out)
    assert snap["ok"] is True
    key = 'public."orders \\! touch /tmp/PWNED_postgres"'
    assert sorted(snap["tables"]) == sorted(["orders", key])
    assert snap["tables"]["orders"] == {"pk": "id", "schema": "s1", "count": 2, "columns": ["id"], "volatile": [],
                                        "rows": {"k1": val("r1"), "k2": val("r2")}}
    assert snap["tables"][key]["rows"] == {"k1": val("x1")}
    assert snap["unsafe_names"] == [key]


def test_names_with_newline_or_separator_cannot_add_lines_or_fields():
    for name in ("a\nR\x1f16400\x1fk9\x1fr9", "b\x1fc", "d\re"):
        out = "\n".join([tline(16400, "public", "orders", "id"), tline(16401, "public", name),
                         rline(16400, "k1", "r1")]) + "\n"
        snap = pgstate.snapshot({"pg": {}}, runner=lambda s, c, out=out: out)
        assert snap["ok"] is True, snap
        assert snap["tables"]["orders"]["rows"] == {"k1": val("r1")}
        assert snap["unsafe_names"] == [pgstate.table_key("public", name)]


def test_table_key_has_no_collisions():
    """Finding 20: public."billing.invoices" and billing.invoices were one key."""
    pairs = [("public", "orders"), ("public", "billing.invoices"), ("billing", "invoices"),
             ("public", "Orders"), ("public", "order s"), ('we"ird', "x"), ("we", '"ird.x'), ("public", "user")]
    keys = [pgstate.table_key(s, n) for s, n in pairs]
    assert len(set(keys)) == len(keys), keys
    assert pgstate.table_key("public", "orders") == "orders"
    assert pgstate.table_key("billing", "invoices") == "billing.invoices"
    assert pgstate.table_key("public", "billing.invoices") == 'public."billing.invoices"'
    out = "\n".join([tline(1, "public", "billing.invoices", "id"), tline(2, "billing", "invoices", "id"),
                     rline(1, "a", "1"), rline(2, "b", "2")]) + "\n"
    snap = pgstate.snapshot({"pg": {}}, runner=lambda s, c: out)
    assert snap["tables"]['public."billing.invoices"']["rows"] == {"a": val("1")}
    assert snap["tables"]["billing.invoices"]["rows"] == {"b": val("2")}


def test_snapshot_parses_rows_and_multisets():
    out = "\n".join([tline(10, "public", "prices", "id", "aaa", cols=("id", "amount", "updated_at"), vol="001"),
                     tline(11, "public", "log", "", "bbb"),
                     rline(10, "k1", "r1", "s1", "a" * 48), rline(10, "k2", "r2", "s2", "b" * 48),
                     rline(11, "", "x"), rline(11, "", "x"), rline(11, "", "y")]) + "\n"
    snap = pgstate.snapshot({"pg": {}}, runner=lambda s, c: out)
    assert snap["ok"] is True and "unsafe_names" not in snap
    assert snap["tables"]["prices"] == {"pk": "id", "schema": "aaa", "count": 2,
                                        "columns": ["id", "amount", "updated_at"], "volatile": ["updated_at"],
                                        "rows": {"k1": val("r1", "s1", "a" * 48), "k2": val("r2", "s2", "b" * 48)}}
    assert snap["tables"]["log"]["multiset"] == {val("x"): 2, val("y"): 1}
    assert snap["tables"]["log"]["count"] == 3


def test_unexpected_output_is_an_error_not_a_guess():
    for out in (rline(99, "k", "r") + "\n", "@@T orders\n", tline("x", "public", "t") + "\n",
                S.join(["T", "1", "r", "zz", hx("t"), "", "d", hx("id"), "0"]) + "\n",
                tline(1, "public", "t", cols=("a", "b"), vol="0") + "\n",
                tline(1, "public", "t") + "\n" + rline(1, "k", "r", sig="a" * 15) + "\n"):
        snap = pgstate.snapshot({"pg": {}}, runner=lambda s, c, out=out: out)
        assert snap["ok"] is False, out


def test_session_pins_search_path_and_output_settings_and_reads_only_the_table_itself():
    script = pgstate.SNAPSHOT_SCRIPT
    first = script.index("BEGIN ISOLATION LEVEL REPEATABLE READ READ ONLY")
    for setting in ("SET search_path = pg_catalog;", "SET row_security = off;", "SET TimeZone = 'UTC';",
                    "SET DateStyle = 'ISO, MDY';", "SET bytea_output = 'hex';", "SET lc_monetary = 'C';"):
        assert 0 <= script.index(setting) < first, setting
    # a column named t cannot replace the row; rows of inheriting child tables are not counted here
    assert "ROW(t.*)::text" in script and "md5(t::text)" not in script
    assert "CASE WHEN tbl.relkind = 'r' THEN 'ONLY' ELSE '' END" in script
    assert script.rstrip().endswith("COMMIT;")
    # the stable hash leaves out time types and clock/random/sequence defaults; defaults are in the
    # schema digest, so making a column "volatile" during the run shows as a schema change
    assert "'timestamptz'::regtype" in script and "gen_random_uuid" in script and "nextval" in script
    assert "|| coalesce(pg_get_expr(d.adbin, d.adrelid), ''), ',' ORDER BY a.attnum)" in script


def test_snapshot_reports_errors_instead_of_raising():
    def boom(sql, cfg):
        raise pgstate.PgError("connection refused")
    snap = pgstate.snapshot({"pg": {}}, runner=boom)
    assert snap["ok"] is False and "connection refused" in snap["error"]
    assert pgstate.snapshot({"pg": {"enabled": False}})["error"] == "disabled"


def sha(text) -> str:
    return hashlib.sha256(str(text).encode()).hexdigest()


def sim(rows: dict, cols=("id", "amount"), volatile=(), pk="id", schema="s1") -> dict:
    """A table entry as the snapshot builds it, with the hashes computed here instead of in Postgres:
    rows {pk value: {column: value}}."""
    entry = {"pk": pk, "schema": schema, "count": len(rows), "columns": list(cols), "volatile": list(volatile)}
    vals = {}
    for pkv, r in rows.items():
        full = sha(repr([r.get(c) for c in cols]))
        stable = sha(repr([r.get(c) for c in cols if c not in volatile]))
        sig = "".join(sha("n" if r.get(c) is None else "v" + str(r.get(c)))[:16] for c in cols)
        vals[sha(pkv)] = f"{full}:{stable}:{sig}"
    if pk:
        entry["rows"] = vals
    else:
        entry["multiset"] = {}
        for v in vals.values():
            entry["multiset"][v] = entry["multiset"].get(v, 0) + 1
    return entry


def table(rows, schema="s1", pk="id"):
    """Old-style entry: one hash per row, no columns."""
    return {"pk": pk, "schema": schema, "count": len(rows), "rows": dict(rows)}


def dig(*items):
    return hashlib.sha256("\n".join(sorted(items)).encode()).hexdigest()


def test_diff_tables_inserted_deleted_updated_by_key():
    t0 = {"prices": table({"a": "1", "b": "2", "c": "3"})}
    t1 = {"prices": table({"a": "1", "b": "20", "d": "4"})}
    assert pgstate.diff_tables(t0, t1) == {"prices": {
        "inserted": 1, "deleted": 1, "updated": 1,
        "digests": {"inserted": dig("d:4"), "deleted": dig("c"), "updated": dig("b:[]:20")}}}


def test_updated_digest_names_the_changed_columns():
    before = sim({1: {"id": 1, "amount": "10.00", "note": "a"}}, cols=("id", "amount", "note"))
    after = sim({1: {"id": 1, "amount": "11.00", "note": "a"}}, cols=("id", "amount", "note"))
    d = pgstate.diff_tables({"p": before}, {"p": after})["p"]
    stable = pgstate.split_row(after["rows"][sha(1)])[1]
    assert d["digests"] == {"updated": dig(f'{sha(1)}:["amount"]:{stable}')}


PRICE_COLS = ("id", "sku", "amount", "updated_at")


def prices(n=10, **over):
    rows = {i: {"id": i, "sku": f"SKU-{i}", "amount": f"{10 + i}.00", "updated_at": "2026-10-01 00:00:00+00"}
            for i in range(1, n + 1)}
    for i, r in over.items():
        rows[int(i[1:])].update(r)
    return sim(rows, cols=PRICE_COLS, volatile=("updated_at",))


def test_same_update_at_another_time_gives_the_same_digests():
    """A correct apply is not 'diverged': twin and production write now() at different moments."""
    before = prices()
    twin = prices(r1={"amount": "12.10", "updated_at": "2026-11-04 10:00:00.123+00"},
                  r2={"amount": "13.20", "updated_at": "2026-11-04 10:00:00.123+00"})
    prod = prices(r1={"amount": "12.10", "updated_at": "2026-11-05 15:30:07.999+00"},
                  r2={"amount": "13.20", "updated_at": "2026-11-05 15:30:07.999+00"})
    assert twin["rows"] != prod["rows"]  # the rows themselves differ (the timestamp)
    dt = pgstate.diff_tables({"prices": before}, {"prices": twin})["prices"]
    dp = pgstate.diff_tables({"prices": before}, {"prices": prod})["prices"]
    assert dt == dp
    assert dt["updated"] == 2 and set(dt["digests"]) == {"updated"}

    # inserts whose created_at comes from DEFAULT now(): same keys and values, other times
    cols = ("id", "msg", "created_at")
    base = sim({1: {"id": 1, "msg": "a", "created_at": "t0"}}, cols=cols, volatile=("created_at",))
    ins_twin = sim({1: {"id": 1, "msg": "a", "created_at": "t0"}, 2: {"id": 2, "msg": "b", "created_at": "t1"}},
                   cols=cols, volatile=("created_at",))
    ins_prod = sim({1: {"id": 1, "msg": "a", "created_at": "t0"}, 2: {"id": 2, "msg": "b", "created_at": "t9"}},
                   cols=cols, volatile=("created_at",))
    assert pgstate.diff_tables({"log": base}, {"log": ins_twin}) == pgstate.diff_tables({"log": base}, {"log": ins_prod})

    # the same without a primary key
    nb = sim({1: {"msg": "a", "at": "t0"}}, cols=("msg", "at"), volatile=("at",), pk="")
    nt = sim({1: {"msg": "a", "at": "t0"}, 2: {"msg": "b", "at": "t1"}}, cols=("msg", "at"), volatile=("at",), pk="")
    np_ = sim({1: {"msg": "a", "at": "t0"}, 2: {"msg": "b", "at": "t5"}}, cols=("msg", "at"), volatile=("at",), pk="")
    assert pgstate.diff_tables({"l": nb}, {"l": nt}) == pgstate.diff_tables({"l": nb}, {"l": np_})


def test_other_rows_or_other_values_give_other_digests():
    before = prices()
    twin = prices(r1={"amount": "12.10", "updated_at": "T1"}, r2={"amount": "13.20", "updated_at": "T1"})
    dt = pgstate.diff_tables({"prices": before}, {"prices": twin})["prices"]["digests"]
    cases = {
        "other rows": prices(r3={"amount": "14.30", "updated_at": "T2"}, r4={"amount": "15.40", "updated_at": "T2"}),
        "other amount": prices(r1={"amount": "121.00", "updated_at": "T2"}, r2={"amount": "13.20", "updated_at": "T2"}),
        "another column too": prices(r1={"amount": "12.10", "sku": "X", "updated_at": "T2"},
                                     r2={"amount": "13.20", "updated_at": "T2"}),
        "timestamp left alone": prices(r1={"amount": "12.10"}, r2={"amount": "13.20"}),
    }
    for what, prod in cases.items():
        dp = pgstate.diff_tables({"prices": before}, {"prices": prod})["prices"]
        assert dp["updated"] == 2, what
        assert dp["digests"]["updated"] != dt["updated"], what
    # inserted rows: same key, other non-time value
    cols = ("id", "msg", "created_at")
    base = sim({}, cols=cols, volatile=("created_at",))
    a = sim({7: {"id": 7, "msg": "ok", "created_at": "t1"}}, cols=cols, volatile=("created_at",))
    b = sim({7: {"id": 7, "msg": "evil", "created_at": "t1"}}, cols=cols, volatile=("created_at",))
    da = pgstate.diff_tables({"log": base}, {"log": a})["log"]["digests"]
    db = pgstate.diff_tables({"log": base}, {"log": b})["log"]["digests"]
    assert da["inserted"] != db["inserted"]
    # deleted: other keys
    dela = pgstate.diff_tables({"p": before}, {"p": prices(5)})["p"]["digests"]
    rows_b = {i: {"id": i, "sku": f"SKU-{i}", "amount": f"{10 + i}.00", "updated_at": "2026-10-01 00:00:00+00"}
              for i in range(1, 11) if not 2 <= i <= 6}
    delb = pgstate.diff_tables({"p": before}, {"p": sim(rows_b, cols=PRICE_COLS, volatile=("updated_at",))})["p"]
    assert delb["deleted"] == 5 and delb["digests"]["deleted"] != dela["deleted"]


def test_digests_tell_which_rows_not_only_how_many():
    """Finding 4: deleting sessions 0-239 on the twin and 1000-1239 on production gave the same ledger."""
    base = {str(i): "v" for i in range(2000)}
    twin = {k: v for k, v in base.items() if not 0 <= int(k) < 240}
    prod = {k: v for k, v in base.items() if not 1000 <= int(k) < 1240}
    dt = pgstate.diff_tables({"sessions": table(base)}, {"sessions": table(twin)})["sessions"]
    dp = pgstate.diff_tables({"sessions": table(base)}, {"sessions": table(prod)})["sessions"]
    assert dt["deleted"] == dp["deleted"] == 240
    assert dt["digests"]["deleted"] != dp["digests"]["deleted"]
    assert set(dt["digests"]) == {"deleted"}


def test_changed_columns_with_added_or_dropped_columns_and_old_states():
    a = sim({1: {"id": 1, "x": "1"}}, cols=("id", "x"))
    b = sim({1: {"id": 1, "x": "1", "y": "2"}}, cols=("id", "x", "y"))
    k = sha(1)
    assert pgstate.changed_columns(a, a["rows"][k], b, b["rows"][k]) == ["y"]
    assert pgstate.changed_columns({}, "h1", {}, "h2") == []
    assert pgstate.split_row("h1") == ("h1", "h1", "")


def test_diff_tables_drop_create_schema_and_unchanged():
    t0 = {"orders": table({"1": "x", "2": "y"}), "same": table({"1": "x"}), "alt": table({"1": "x"})}
    t1 = {"newt": table({"1": "x"}), "same": table({"1": "x"}), "alt": table({"1": "x2"}, schema="s2")}
    d = pgstate.diff_tables(t0, t1)
    assert d["orders"] == {"inserted": 0, "deleted": 2, "updated": 0, "dropped": True,
                           "digests": {"deleted": dig("1", "2")}}
    assert d["newt"] == {"inserted": 1, "deleted": 0, "updated": 0, "created": True,
                         "digests": {"inserted": dig("1:x")}}
    assert d["alt"] == {"inserted": 0, "deleted": 0, "updated": 1, "schema_changed": True,
                        "digests": {"updated": dig("1:[]:x2")}}
    assert "same" not in d


def test_schema_change_alone_has_no_digests():
    d = pgstate.diff_tables({"t": table({"1": "x"})}, {"t": table({"1": "x"}, schema="s2")})
    assert d == {"t": {"inserted": 0, "deleted": 0, "updated": 0, "schema_changed": True}}


def test_diff_tables_without_primary_key_uses_multiset():
    t0 = {"log": {"pk": "", "schema": "s", "count": 3, "multiset": {"x": 2, "y": 1}}}
    t1 = {"log": {"pk": "", "schema": "s", "count": 3, "multiset": {"x": 1, "y": 1, "z": 1}}}
    assert pgstate.diff_tables(t0, t1) == {"log": {"inserted": 1, "deleted": 1, "updated": 0,
                                                   "digests": {"inserted": dig("z"), "deleted": dig("x")}}}
