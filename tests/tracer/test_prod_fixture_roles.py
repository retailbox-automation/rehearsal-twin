"""Database roles of the demo PROD fixture (findings 3 and 5), checked on the script text and by
running its pg_hba / pg_ident block on temporary copies."""
import re
import subprocess
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
CLOUD_INIT = ROOT / "fixtures" / "prod" / "cloud-init.sh"
SMOKE = ROOT / "tests" / "tracer" / "prod_smoke_inside.sh"


def _text():
    return CLOUD_INIT.read_text()


def test_no_superuser_login_role_for_the_script():
    text = _text()
    assert "CREATE ROLE root SUPERUSER" not in text
    assert not re.search(r"CREATE ROLE \w+ SUPERUSER", text)
    assert "ALTER ROLE shop NOSUPERUSER NOCREATEDB NOCREATEROLE NOREPLICATION NOBYPASSRLS LOGIN;" in text
    # the old superuser role keeps no login and owns nothing in shop
    assert 'PGDB=shop pg_admin -c "REASSIGN OWNED BY root TO shop"' in text
    assert "ALTER ROLE root NOSUPERUSER NOCREATEDB NOCREATEROLE NOREPLICATION NOBYPASSRLS NOLOGIN" in text
    assert 'pg_admin -c "CREATE DATABASE shop OWNER shop"' in text
    assert 'pg_admin -c "ALTER DATABASE shop OWNER TO shop"' in text
    # tables are created by shop, so shop owns them (presets drop and update them)
    assert 'pg_shop -f "$RT_SRC/fixtures/prod/shop.sql"' in text
    assert "pg_shop() { PGUSER=shop psql" in text


def test_tracer_role_reads_everything_from_its_own_os_user():
    text = _text()
    assert "useradd --system --user-group --no-create-home --home-dir /nonexistent --shell /usr/sbin/nologin " \
           "rtrace" in text
    assert "ALTER ROLE rtrace NOSUPERUSER NOCREATEDB NOCREATEROLE NOREPLICATION BYPASSRLS LOGIN;" in text
    assert "GRANT pg_read_all_data TO rtrace;" in text
    # no peer map for rtrace: only the OS user rtrace can log in as it
    assert "rtrace" not in "".join(l for l in text.splitlines() if "rt_shop" in l)


def test_decoy_token_insert_is_not_written_to_the_postgres_log():
    text = _text()
    i = text.index('PGDB=shop pg_admin -v token="$KEY_TOKEN" <<\'SQL\'')
    block = text[i:text.index("\nSQL\n", i)]
    assert block.index("SET log_statement = 'none';") < block.index("INSERT INTO api_keys")


def _hba_block():
    text = _text()
    start = text.index("HBA_SHOP=")
    end = text.index('pg_admin -c "SELECT pg_reload_conf()"')
    return text[start:end]


def test_hba_and_ident_block_puts_the_map_first_and_is_idempotent(tmp_path):
    hba, ident = tmp_path / "pg_hba.conf", tmp_path / "pg_ident.conf"
    hba.write_text("local   all             postgres                                peer\n"
                   "local   all             all                                     peer\n"
                   "host    all             all             127.0.0.1/32            scram-sha-256\n")
    ident.write_text("# MAPNAME       SYSTEM-USERNAME         PG-USERNAME\n")
    script = f'set -euo pipefail\nPG_HBA="{hba}"\nPG_IDENT="{ident}"\n' + _hba_block()
    for _ in range(2):
        subprocess.run(["/bin/bash", "-c", script], check=True, capture_output=True, text=True)
    rules = [l for l in hba.read_text().splitlines() if l and not l.startswith("#")]
    assert rules[0] == "local all shop peer map=rt_shop"
    assert len(rules) == 4 and rules[2].split()[2] == "all"
    maps = [l for l in ident.read_text().splitlines() if l and not l.startswith("#")]
    assert maps == ["rt_shop root shop"]


def test_smoke_reseeds_as_shop_and_runs_with_the_scope():
    smoke = SMOKE.read_text()
    assert 'reseed() { PGUSER=shop psql' in smoke
    assert 'rtrace run --script "$2" --wall 60 --mem 512M --pids 256 --scope "$W/$name.scope.json"' in smoke
