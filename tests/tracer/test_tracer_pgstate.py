import hashlib

from rt.tracer import pgstate

S = pgstate.SEP
EVIL = "orders \\! touch /tmp/PWNED_postgres"


def hx(s: str) -> str:
    return s.encode().hex()


def tline(oid, schema, name, pk="", digest="d0", kind="r"):
    return S.join(["T", str(oid), kind, hx(schema), hx(name), hx(pk), digest])


def rline(oid, key, row):
    return S.join(["R", str(oid), key, row])


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
    assert snap["tables"]["orders"] == {"pk": "id", "schema": "s1", "count": 2, "rows": {"k1": "r1", "k2": "r2"}}
    assert snap["tables"][key]["rows"] == {"k1": "x1"}
    assert snap["unsafe_names"] == [key]


def test_names_with_newline_or_separator_cannot_add_lines_or_fields():
    for name in ("a\nR\x1f16400\x1fk9\x1fr9", "b\x1fc", "d\re"):
        out = "\n".join([tline(16400, "public", "orders", "id"), tline(16401, "public", name),
                         rline(16400, "k1", "r1")]) + "\n"
        snap = pgstate.snapshot({"pg": {}}, runner=lambda s, c, out=out: out)
        assert snap["ok"] is True, snap
        assert snap["tables"]["orders"]["rows"] == {"k1": "r1"}
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
    assert snap["tables"]['public."billing.invoices"']["rows"] == {"a": "1"}
    assert snap["tables"]["billing.invoices"]["rows"] == {"b": "2"}


def test_snapshot_parses_rows_and_multisets():
    out = "\n".join([tline(10, "public", "prices", "id", "aaa"), tline(11, "public", "log", "", "bbb"),
                     rline(10, "k1", "r1"), rline(10, "k2", "r2"),
                     rline(11, "", "x"), rline(11, "", "x"), rline(11, "", "y")]) + "\n"
    snap = pgstate.snapshot({"pg": {}}, runner=lambda s, c: out)
    assert snap["ok"] is True and "unsafe_names" not in snap
    assert snap["tables"]["prices"] == {"pk": "id", "schema": "aaa", "count": 2, "rows": {"k1": "r1", "k2": "r2"}}
    assert snap["tables"]["log"]["multiset"] == {"x": 2, "y": 1}
    assert snap["tables"]["log"]["count"] == 3


def test_unexpected_output_is_an_error_not_a_guess():
    for out in (rline(99, "k", "r") + "\n", "@@T orders\n", tline("x", "public", "t") + "\n",
                S.join(["T", "1", "r", "zz", hx("t"), "", "d"]) + "\n"):
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


def test_snapshot_reports_errors_instead_of_raising():
    def boom(sql, cfg):
        raise pgstate.PgError("connection refused")
    snap = pgstate.snapshot({"pg": {}}, runner=boom)
    assert snap["ok"] is False and "connection refused" in snap["error"]
    assert pgstate.snapshot({"pg": {"enabled": False}})["error"] == "disabled"


def table(rows, schema="s1", pk="id"):
    return {"pk": pk, "schema": schema, "count": len(rows), "rows": dict(rows)}


def dig(*items):
    return hashlib.sha256("\n".join(sorted(items)).encode()).hexdigest()


def test_diff_tables_inserted_deleted_updated_by_key():
    t0 = {"prices": table({"a": "1", "b": "2", "c": "3"})}
    t1 = {"prices": table({"a": "1", "b": "20", "d": "4"})}
    assert pgstate.diff_tables(t0, t1) == {"prices": {
        "inserted": 1, "deleted": 1, "updated": 1,
        "digests": {"inserted": dig("d"), "deleted": dig("c"), "updated": dig("b:20")}}}


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
    # same rows, same new values: same digest; different new value: different digest
    u1 = pgstate.diff_tables({"p": table({"1": "a"})}, {"p": table({"1": "b"})})["p"]["digests"]
    u2 = pgstate.diff_tables({"p": table({"1": "a"})}, {"p": table({"1": "b"})})["p"]["digests"]
    u3 = pgstate.diff_tables({"p": table({"1": "a"})}, {"p": table({"1": "c"})})["p"]["digests"]
    assert u1 == u2 != u3


def test_diff_tables_drop_create_schema_and_unchanged():
    t0 = {"orders": table({"1": "x", "2": "y"}), "same": table({"1": "x"}), "alt": table({"1": "x"})}
    t1 = {"newt": table({"1": "x"}), "same": table({"1": "x"}), "alt": table({"1": "x2"}, schema="s2")}
    d = pgstate.diff_tables(t0, t1)
    assert d["orders"] == {"inserted": 0, "deleted": 2, "updated": 0, "dropped": True,
                           "digests": {"deleted": dig("1", "2")}}
    assert d["newt"] == {"inserted": 1, "deleted": 0, "updated": 0, "created": True,
                         "digests": {"inserted": dig("1")}}
    assert d["alt"] == {"inserted": 0, "deleted": 0, "updated": 1, "schema_changed": True,
                        "digests": {"updated": dig("1:x2")}}
    assert "same" not in d


def test_schema_change_alone_has_no_digests():
    d = pgstate.diff_tables({"t": table({"1": "x"})}, {"t": table({"1": "x"}, schema="s2")})
    assert d == {"t": {"inserted": 0, "deleted": 0, "updated": 0, "schema_changed": True}}


def test_diff_tables_without_primary_key_uses_multiset():
    t0 = {"log": {"pk": "", "schema": "s", "count": 3, "multiset": {"x": 2, "y": 1}}}
    t1 = {"log": {"pk": "", "schema": "s", "count": 3, "multiset": {"x": 1, "y": 1, "z": 1}}}
    assert pgstate.diff_tables(t0, t1) == {"log": {"inserted": 1, "deleted": 1, "updated": 0,
                                                   "digests": {"inserted": dig("z"), "deleted": dig("x")}}}
