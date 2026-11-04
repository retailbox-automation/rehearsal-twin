"""The red-team stand helper against the demo PROD fixture's roles (checked on the script text).

OS root logs in to Postgres as role shop (no superuser), so every database step of stand.sh must
run as postgres, the restored database must be owned by shop again, and the golden copy must be
out of shop's reach (owned by postgres, no connections).
"""
import re
import subprocess
from pathlib import Path

STAND = Path(__file__).resolve().parents[2] / "redteam" / "stand" / "stand.sh"
DDL = re.compile(r"\b(CREATE|DROP|ALTER)\s+(DATABASE|ROLE|TABLE|SCHEMA)\b|\bREASSIGN\b|\bGRANT\b|\bREVOKE\b", re.I)


def code_lines():
    """(number, text) of every shell line: no comments, no heredoc bodies (data fed to the command
    that opens the heredoc, which is itself checked)."""
    out = []
    end = None
    for n, line in enumerate(STAND.read_text().splitlines(), 1):
        if end is not None:
            if line == end:
                end = None
            continue
        if line.lstrip().startswith("#"):
            continue
        out.append((n, line))
        m = re.search(r"<<-?\s*'?([A-Za-z_]+)'?", line)
        if m:
            end = m.group(1)
    assert end is None, "unterminated heredoc"
    return out


def test_heredoc_bodies_are_skipped_but_their_command_is_kept():
    lines = [line for _, line in code_lines()]
    assert any("PGDB=shop pg_admin <<'SQL'" in line for line in lines)
    assert not any(line.startswith("UPDATE customers") for line in lines)


def section(name):
    text = STAND.read_text()
    start = text.index(f"\n{name})\n")
    return text[start:text.index("\n  ;;\n", start)]


def test_stand_parses():
    subprocess.run(["/bin/bash", "-n", str(STAND)], check=True)


def test_psql_only_runs_as_postgres():
    calls = [(n, line) for n, line in code_lines() if re.search(r"\bpsql\b", line)]
    assert calls, "no psql call found: the test would see nothing"
    for n, line in calls:
        assert "runuser -u postgres -- psql " in line, f"line {n}: psql not run as postgres: {line.strip()}"
    assert len(calls) == 1  # the one helper, so no step can bypass it


def test_every_ddl_goes_through_the_postgres_helper():
    ddl = [(n, line) for n, line in code_lines() if DDL.search(line)]
    assert ddl, "no DDL found: the test would see nothing"
    for n, line in ddl:
        assert re.search(r"\bpg_admin -c ", line), f"line {n}: DDL not through pg_admin: {line.strip()}"
    # the old helper ran psql as OS root (role root, a superuser in earlier fixtures)
    assert not any(re.match(r"\s*pg\s*\(\)", line) or re.search(r"(^|[;&|]\s*)pg\s", line)
                   for _, line in code_lines())


def test_no_role_root_anywhere():
    assert not re.search(r"OWNER\s+root\b", STAND.read_text(), re.I)


def test_reset_restores_shop_owned_by_shop_and_clears_role_settings():
    reset = section("reset")
    drop = reset.index('pg_admin -c "DROP DATABASE IF EXISTS shop WITH (FORCE)"')
    create = reset.index('pg_admin -c "CREATE DATABASE shop TEMPLATE shop_golden OWNER shop"')
    clear = reset.index('pg_admin -c "ALTER ROLE shop RESET ALL"')
    assert drop < create < clear
    # a failed restore stops the reset instead of running the next attack on a broken database
    assert "|| { echo \"reset: database restore failed\" >&2; exit 5; }" in reset[clear:]


def test_golden_copy_is_owned_by_postgres_and_closed():
    golden = section("golden")
    assert 'pg_admin -c "CREATE DATABASE shop_golden TEMPLATE shop OWNER postgres"' in golden
    assert not re.search(r"shop_golden[^\n]*OWNER\s+shop\b", golden)
    create = golden.index("CREATE DATABASE shop_golden")
    closed = golden.index('pg_admin -c "ALTER DATABASE shop_golden ALLOW_CONNECTIONS false"')
    assert create < closed
    # the webhook sender (a session on shop) is stopped for the copy and started again either way
    assert golden.index("systemctl stop shop-webhooks") < create
    assert "systemctl start shop-webhooks; echo \"golden: database copy failed\" >&2; exit 5;" in golden


def test_planted_data_goes_in_as_postgres():
    golden = section("golden")
    assert "PGDB=shop pg_admin <<'SQL'" in golden
