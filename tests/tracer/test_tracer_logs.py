import json

from rt.tracer import config, logs

PG = (
    "2026-11-03 16:10:00.100 UTC [101] root@shop psql: LOG:  statement: DELETE FROM sessions WHERE expires_at < now()\n"
    "2026-11-03 16:10:00.200 UTC [102] rtrace@shop rtrace: LOG:  statement: SELECT 1\n"
    "2026-11-03 16:10:00.300 UTC [103] root@shop psql: LOG:  statement: UPDATE prices\n"
    "\tSET amount = amount * 1.1\n"
    "\tWHERE category = 'winter'\n"
    "2026-11-03 16:10:00.400 UTC [104] root@shop psql: LOG:  statement: DROP TABLE nope\n"
    "2026-11-03 16:10:00.401 UTC [104] root@shop psql: ERROR:  table \"nope\" does not exist\n"
    "2026-11-03 16:10:00.402 UTC [104] root@shop psql: STATEMENT:  DROP TABLE nope\n"
    "2026-11-03 16:10:01.000 UTC [7] @ : LOG:  checkpoint starting: time\n"
    "2026-11-03 16:10:02.000 UTC [105] app@shop my app: LOG:  execute <unnamed>: SELECT * FROM api_keys\n"
)


def test_parse_pg_log_statements_multiline_errors_and_excludes():
    out = logs.parse_pg_log(PG, exclude_users=("rtrace",))
    assert [s["statement"] for s in out] == [
        "DELETE FROM sessions WHERE expires_at < now()",
        "UPDATE prices\nSET amount = amount * 1.1\nWHERE category = 'winter'",
        "DROP TABLE nope",
        "SELECT * FROM api_keys",
    ]
    assert out[0] == {"user": "root", "db": "shop", "app": "psql",
                      "statement": "DELETE FROM sessions WHERE expires_at < now()"}
    assert out[2]["error"] == 'table "nope" does not exist'
    assert out[3]["app"] == "my app"


AUDIT = (
    'type=SYSCALL msg=audit(1762186200.123:501): arch=c000003e syscall=257 success=yes exit=3 '
    'a0=ffffff9c items=1 ppid=1 pid=900 auid=0 uid=0 comm="cat" exe="/usr/bin/cat" key="rt_canary_env"\n'
    'type=PATH msg=audit(1762186200.123:501): item=0 name="/srv/app/.env.canary"\n'
    'type=SYSCALL msg=audit(1762186201.000:502): arch=c000003e syscall=59 success=yes comm="ls" key=(null)\n'
    'type=SYSCALL msg=audit(1762186202.000:503): arch=c000003e syscall=257 success=no comm="x" key="other"\n'
)


def test_parse_audit_log_filters_by_key():
    out = logs.parse_audit_log(AUDIT, keys={"rt_canary_env"})
    assert out == [{"key": "rt_canary_env", "syscall": "257", "success": "yes", "comm": "cat",
                    "exe": "/usr/bin/cat", "serial": 501}]
    assert len(logs.parse_audit_log(AUDIT)) == 2


def test_read_window_and_rotation(tmp_path):
    p = tmp_path / "log"
    p.write_text("aaaa\nbbbb\ncccc\n")
    assert logs.read_window(str(p), 5, 10) == "bbbb\n"
    assert logs.read_window(str(p), 5) == "bbbb\ncccc\n"
    assert logs.read_window(str(p), 999, 1000) == "aaaa\nbbbb\ncccc\n"
    assert logs.read_window(str(tmp_path / "missing"), 0, 10) == ""
    assert logs.size_of(str(p)) == 15


def test_parse_jsonl_counts_bad_lines():
    text = json.dumps({"kind": "dns"}) + "\n{broken\n[1]\n\n" + json.dumps({"kind": "https"}) + "\n"
    recs, bad = logs.parse_jsonl(text)
    assert [r["kind"] for r in recs] == ["dns", "https"]
    assert bad == 2


def test_application_name_cannot_hide_a_statement():
    """Finding 3: PGAPPNAME=rtrace (or shop-webhooks) used to drop the script's SQL from sql[]."""
    text = (
        "2026-11-04 10:00:00.000 UTC [201] shop@shop rtrace: LOG:  statement: DELETE FROM orders\n"
        "2026-11-04 10:00:00.100 UTC [202] shop@shop shop-webhooks: LOG:  statement: ALTER SYSTEM SET log_statement = 'none'\n"
        "2026-11-04 10:00:00.200 UTC [203] rtrace@shop psql: LOG:  statement: SELECT 'T', 1\n"
    )
    out = logs.parse_pg_log(text, exclude_users=tuple(config.DEFAULTS["pg"]["exclude_users"]))
    assert [(s["user"], s["app"], s["statement"]) for s in out] == [
        ("shop", "rtrace", "DELETE FROM orders"),
        ("shop", "shop-webhooks", "ALTER SYSTEM SET log_statement = 'none'"),
    ]


def test_tracer_reads_as_its_own_role_not_a_superuser_or_the_script_role():
    pg = config.DEFAULTS["pg"]
    assert pg["run_as"] == "rtrace" and pg["exclude_users"] == ["rtrace"]
    assert pg["script_user"] == "shop" and pg["script_user"] not in pg["exclude_users"]
    assert "exclude_apps" not in pg
