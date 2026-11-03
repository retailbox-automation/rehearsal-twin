"""Postgres state: per table row hashes (keyed by primary key) and a schema digest.

Only `psql` is needed on the machine. The tracer's own session runs with
log_statement=none and application_name=rtrace, so it never shows up in sql[].
"""
from __future__ import annotations

import subprocess
from collections import Counter

SEP = "\x1f"

LIST_TABLES_SQL = r"""
SELECT n.nspname, c.relname,
  coalesce((SELECT string_agg(quote_ident(a.attname), ',' ORDER BY array_position(i.indkey::int2[], a.attnum))
            FROM pg_index i JOIN pg_attribute a ON a.attrelid = i.indrelid AND a.attnum = ANY(i.indkey)
            WHERE i.indrelid = c.oid AND i.indisprimary), ''),
  md5(coalesce((SELECT string_agg(a.attname || ':' || format_type(a.atttypid, a.atttypmod), ',' ORDER BY a.attnum)
                FROM pg_attribute a WHERE a.attrelid = c.oid AND a.attnum > 0 AND NOT a.attisdropped), '')
      || '|' ||
      coalesce((SELECT string_agg(t.tgname, ',' ORDER BY t.tgname)
                FROM pg_trigger t WHERE t.tgrelid = c.oid AND NOT t.tgisinternal), ''))
FROM pg_class c JOIN pg_namespace n ON n.oid = c.relnamespace
WHERE c.relkind IN ('r', 'p')
  AND n.nspname NOT IN ('pg_catalog', 'information_schema')
  AND n.nspname NOT LIKE 'pg_toast%'
ORDER BY 1, 2;
"""


class PgError(RuntimeError):
    pass


def psql_argv(cfg: dict) -> list:
    pg = cfg.get("pg") or {}
    conninfo = f"dbname={pg.get('dbname', 'shop')} application_name=rtrace options='-c log_statement=none'"
    argv = ["psql", "-X", "-q", "-At", "-F", SEP, "-v", "ON_ERROR_STOP=1", conninfo]
    run_as = pg.get("run_as")
    if run_as:
        argv = ["runuser", "-u", run_as, "--"] + argv
    return argv


def run_psql(script: str, cfg: dict, timeout: int = 120) -> str:
    p = subprocess.run(psql_argv(cfg), input=script, capture_output=True, text=True, timeout=timeout)
    if p.returncode != 0:
        raise PgError(f"psql exit {p.returncode}: {p.stderr.strip()[:500]}")
    return p.stdout


def _qi(name: str) -> str:
    return '"' + name.replace('"', '""') + '"'


def table_key(schema: str, name: str) -> str:
    return name if schema == "public" else f"{schema}.{name}"


def parse_table_list(out: str) -> list:
    tables = []
    for line in out.splitlines():
        if not line.strip():
            continue
        parts = line.split(SEP)
        if len(parts) != 4:
            raise PgError(f"unexpected table list line: {line[:200]!r}")
        schema, name, pk, schema_md5 = parts
        tables.append({"schema": schema, "name": name, "pk": pk, "schema_md5": schema_md5})
    return tables


def rows_script(tables: list) -> str:
    lines = []
    for t in tables:
        q = f"{_qi(t['schema'])}.{_qi(t['name'])}"
        key = table_key(t["schema"], t["name"])
        lines.append(f"\\echo @@T {key}")
        if t["pk"]:
            cols = [c.strip() for c in t["pk"].split(",")]
            pk_expr = f"t.{cols[0]}" if len(cols) == 1 else "ROW(" + ", ".join(f"t.{c}" for c in cols) + ")"
            lines.append(f"SELECT md5(({pk_expr})::text), md5(t::text) FROM {q} t;")
        else:
            lines.append(f"SELECT '', md5(t::text) FROM {q} t;")
    return "\n".join(lines) + "\n"


def parse_rows(out: str, tables: list) -> dict:
    meta = {table_key(t["schema"], t["name"]): t for t in tables}
    result = {}
    current = None
    for line in out.splitlines():
        if line.startswith("@@T "):
            current = line[4:].strip()
            t = meta[current]
            result[current] = {"pk": t["pk"], "schema": t["schema_md5"], "count": 0}
            if t["pk"]:
                result[current]["rows"] = {}
            else:
                result[current]["multiset"] = {}
            continue
        if current is None or not line:
            continue
        key, _, row = line.partition(SEP)
        entry = result[current]
        entry["count"] += 1
        if "rows" in entry:
            entry["rows"][key] = row
        else:
            entry["multiset"][row] = entry["multiset"].get(row, 0) + 1
    return result


def snapshot(cfg: dict, runner=run_psql) -> dict:
    pg = cfg.get("pg") or {}
    if not pg.get("enabled", True):
        return {"ok": False, "error": "disabled", "tables": {}}
    try:
        tables = parse_table_list(runner(LIST_TABLES_SQL, cfg))
        rows = parse_rows(runner(rows_script(tables), cfg), tables) if tables else {}
        return {"ok": True, "tables": rows}
    except (PgError, OSError, subprocess.SubprocessError) as exc:
        return {"ok": False, "error": str(exc)[:500], "tables": {}}


def _multiset(entry: dict) -> Counter:
    if "multiset" in entry:
        return Counter(entry["multiset"])
    return Counter(entry.get("rows", {}).values())


def diff_tables(t0: dict, t1: dict) -> dict:
    """Per table {inserted, deleted, updated} plus dropped/created/schema_changed flags."""
    out = {}
    for name in sorted(set(t0) | set(t1)):
        a, b = t0.get(name), t1.get(name)
        if a is None:
            ch = {"inserted": b.get("count", 0), "deleted": 0, "updated": 0, "created": True}
        elif b is None:
            ch = {"inserted": 0, "deleted": a.get("count", 0), "updated": 0, "dropped": True}
        else:
            if "rows" in a and "rows" in b and a.get("pk") == b.get("pk"):
                ra, rb = a["rows"], b["rows"]
                ins = len(rb.keys() - ra.keys())
                dele = len(ra.keys() - rb.keys())
                upd = sum(1 for k in ra.keys() & rb.keys() if ra[k] != rb[k])
            else:
                ma, mb = _multiset(a), _multiset(b)
                ins = sum((mb - ma).values())
                dele = sum((ma - mb).values())
                upd = 0
            ch = {"inserted": ins, "deleted": dele, "updated": upd}
            if a.get("schema") != b.get("schema"):
                ch["schema_changed"] = True
        if any(ch.values()):
            out[name] = ch
    return out
