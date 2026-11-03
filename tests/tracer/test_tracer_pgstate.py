from rt.tracer import pgstate

S = pgstate.SEP


def test_psql_argv_runs_as_postgres_without_logging():
    argv = pgstate.psql_argv({"pg": {"dbname": "shop", "run_as": "postgres"}})
    assert argv[:4] == ["runuser", "-u", "postgres", "--"]
    conninfo = argv[-1]
    assert "dbname=shop" in conninfo
    assert "application_name=rtrace" in conninfo
    assert "log_statement=none" in conninfo
    assert "ON_ERROR_STOP=1" in argv


def test_rows_script_uses_primary_key_or_multiset():
    tables = [{"schema": "public", "name": "prices", "pk": "id", "schema_md5": "a"},
              {"schema": "public", "name": "pairs", "pk": "a,b", "schema_md5": "b"},
              {"schema": "app", "name": "nopk", "pk": "", "schema_md5": "c"}]
    script = pgstate.rows_script(tables)
    assert "\\echo @@T prices" in script
    assert 'SELECT md5((t.id)::text), md5(t::text) FROM "public"."prices" t;' in script
    assert "ROW(t.a, t.b)" in script
    assert "\\echo @@T app.nopk" in script
    assert "SELECT '', md5(t::text) FROM \"app\".\"nopk\" t;" in script


def fake_runner(listing, rows_out):
    def run(sql, cfg):
        return listing if "pg_class" in sql else rows_out
    return run


def test_snapshot_parses_rows_and_multisets():
    listing = f"public{S}prices{S}id{S}aaa\npublic{S}log{S}{S}bbb\n"
    rows_out = (f"@@T prices\nk1{S}r1\nk2{S}r2\n"
                f"@@T log\n{S}x\n{S}x\n{S}y\n")
    snap = pgstate.snapshot({"pg": {}}, runner=fake_runner(listing, rows_out))
    assert snap["ok"] is True
    assert snap["tables"]["prices"] == {"pk": "id", "schema": "aaa", "count": 2, "rows": {"k1": "r1", "k2": "r2"}}
    assert snap["tables"]["log"]["multiset"] == {"x": 2, "y": 1}
    assert snap["tables"]["log"]["count"] == 3


def test_snapshot_reports_errors_instead_of_raising():
    def boom(sql, cfg):
        raise pgstate.PgError("connection refused")
    snap = pgstate.snapshot({"pg": {}}, runner=boom)
    assert snap["ok"] is False and "connection refused" in snap["error"]


def table(rows, schema="s1", pk="id"):
    return {"pk": pk, "schema": schema, "count": len(rows), "rows": dict(rows)}


def test_diff_tables_inserted_deleted_updated_by_key():
    t0 = {"prices": table({"a": "1", "b": "2", "c": "3"})}
    t1 = {"prices": table({"a": "1", "b": "20", "d": "4"})}
    assert pgstate.diff_tables(t0, t1) == {"prices": {"inserted": 1, "deleted": 1, "updated": 1}}


def test_diff_tables_drop_create_schema_and_unchanged():
    t0 = {"orders": table({"1": "x", "2": "y"}), "same": table({"1": "x"}), "alt": table({"1": "x"})}
    t1 = {"newt": table({"1": "x"}), "same": table({"1": "x"}), "alt": table({"1": "x2"}, schema="s2")}
    d = pgstate.diff_tables(t0, t1)
    assert d["orders"] == {"inserted": 0, "deleted": 2, "updated": 0, "dropped": True}
    assert d["newt"] == {"inserted": 1, "deleted": 0, "updated": 0, "created": True}
    assert d["alt"] == {"inserted": 0, "deleted": 0, "updated": 1, "schema_changed": True}
    assert "same" not in d


def test_diff_tables_without_primary_key_uses_multiset():
    t0 = {"log": {"pk": "", "schema": "s", "count": 3, "multiset": {"x": 2, "y": 1}}}
    t1 = {"log": {"pk": "", "schema": "s", "count": 3, "multiset": {"x": 1, "y": 1, "z": 1}}}
    assert pgstate.diff_tables(t0, t1) == {"log": {"inserted": 1, "deleted": 1, "updated": 0}}
