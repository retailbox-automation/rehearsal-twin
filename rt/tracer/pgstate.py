"""Postgres state: per table row hashes (keyed by primary key) and a schema digest.

Only `psql` is needed on the machine. The tracer connects as its own role `rtrace` (peer
authentication from the OS user rtrace, member of pg_read_all_data, BYPASSRLS). A rehearsal
script cannot become that OS user (the sandbox has no CAP_SETUID), so sql[] drops the statements
of that role by user name, never by application_name, which any client sets freely.

Table names never reach the psql lexer. The text sent to psql (SNAPSHOT_SCRIPT) is the same for
every database: one catalog query lists the tables with every name hex-encoded, a second one
builds the per-table SELECTs on the server with format('%I.%I') and `\\gexec` sends each built
statement straight to the server. A table named `orders \\! touch /x` is data, not a psql
meta-command, and rows are attributed to their table by OID, not by a printed name.

Every output line is `tag SEP field ...` where each field is hex, digits or empty, so no name can
add a line or a field. The session pins search_path and the output settings first: the database
owner can change their defaults (ALTER DATABASE ... SET), which would otherwise change the
functions this query calls or the text form of every row.
"""
from __future__ import annotations

import hashlib
import re
import subprocess
from collections import Counter

SEP = "\x1f"
# Names with these characters are traced like any other table and reported as an integrity issue.
UNSAFE_NAME = re.compile(r"[\\\x00-\x1f\x7f]")
_SIMPLE = re.compile(r"^[a-z_][a-z0-9_]*$")

_TABLES_CTE = r"""WITH tbl AS (
  SELECT c.oid, c.relkind, n.nspname, c.relname,
    (SELECT array_agg(a.attname ORDER BY array_position(i.indkey::int2[], a.attnum))
       FROM pg_index i JOIN pg_attribute a ON a.attrelid = i.indrelid AND a.attnum = ANY(i.indkey)
      WHERE i.indrelid = c.oid AND i.indisprimary) AS pk
  FROM pg_class c JOIN pg_namespace n ON n.oid = c.relnamespace
  WHERE c.relkind IN ('r', 'p')
    AND n.nspname NOT IN ('pg_catalog', 'information_schema')
    AND n.nspname NOT LIKE 'pg_toast%'
)"""

SNAPSHOT_SCRIPT = r"""SET search_path = pg_catalog;
SET row_security = off;
SET statement_timeout = 0;
SET TimeZone = 'UTC';
SET DateStyle = 'ISO, MDY';
SET IntervalStyle = 'postgres';
SET extra_float_digits = 1;
SET bytea_output = 'hex';
SET lc_monetary = 'C';
BEGIN ISOLATION LEVEL REPEATABLE READ READ ONLY;
""" + _TABLES_CTE + r"""
SELECT 'T', tbl.oid, tbl.relkind,
  encode(convert_to(tbl.nspname, 'UTF8'), 'hex'),
  encode(convert_to(tbl.relname, 'UTF8'), 'hex'),
  encode(convert_to(coalesce((SELECT string_agg(quote_ident(x), ',' ORDER BY o)
                                FROM unnest(tbl.pk) WITH ORDINALITY u(x, o)), ''), 'UTF8'), 'hex'),
  encode(sha256(convert_to(
    coalesce((SELECT string_agg(a.attname || ':' || format_type(a.atttypid, a.atttypmod), ',' ORDER BY a.attnum)
                FROM pg_attribute a WHERE a.attrelid = tbl.oid AND a.attnum > 0 AND NOT a.attisdropped), '')
    || '|' ||
    coalesce((SELECT string_agg(t.tgname, ',' ORDER BY t.tgname)
                FROM pg_trigger t WHERE t.tgrelid = tbl.oid AND NOT t.tgisinternal), ''), 'UTF8')), 'hex')
FROM tbl ORDER BY tbl.nspname, tbl.relname;
""" + _TABLES_CTE + r"""
SELECT format('SELECT ''R'', %s, %s, encode(sha256(convert_to(ROW(t.*)::text, ''UTF8'')), ''hex'') FROM %s %I.%I t',
  tbl.oid,
  CASE WHEN tbl.pk IS NULL THEN 'NULL'
       ELSE format('encode(sha256(convert_to((%s)::text, ''UTF8'')), ''hex'')',
                   CASE WHEN array_length(tbl.pk, 1) = 1 THEN 't.' || quote_ident(tbl.pk[1])
                        ELSE 'ROW(' || (SELECT string_agg('t.' || quote_ident(x), ', ' ORDER BY o)
                                          FROM unnest(tbl.pk) WITH ORDINALITY u(x, o)) || ')' END) END,
  CASE WHEN tbl.relkind = 'r' THEN 'ONLY' ELSE '' END,
  tbl.nspname, tbl.relname)
FROM tbl ORDER BY tbl.nspname, tbl.relname
\gexec
COMMIT;
"""


class PgError(RuntimeError):
    pass


def psql_argv(cfg: dict) -> list:
    pg = cfg.get("pg") or {}
    conninfo = f"dbname={pg.get('dbname', 'shop')} application_name=rtrace"
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


def _ident(name: str) -> str:
    return name if _SIMPLE.match(name) else '"' + name.replace('"', '""') + '"'


def table_key(schema: str, name: str) -> str:
    """`name` for a plain lower-case table in public, else `schema.name` with each part quoted when needed.

    One key per table: `public."billing.invoices"` and `billing.invoices` stay apart.
    """
    if schema == "public" and _SIMPLE.match(name):
        return name
    return f"{_ident(schema)}.{_ident(name)}"


def _hex(field: str) -> str:
    try:
        return bytes.fromhex(field).decode("utf-8", "replace")
    except ValueError:
        raise PgError(f"bad hex field: {field[:80]!r}") from None


def parse_snapshot(out: str) -> tuple[dict, list]:
    """psql output of SNAPSHOT_SCRIPT -> ({key: table entry}, [keys of tables with unsafe names])."""
    by_oid: dict[str, dict] = {}
    keys: dict[str, str] = {}
    unsafe = []
    for line in out.splitlines():
        if not line:
            continue
        parts = line.split(SEP)
        tag = parts[0]
        if tag == "T":
            if len(parts) != 7 or not parts[1].isdigit():
                raise PgError(f"unexpected table line: {line[:200]!r}")
            _, oid, _kind, schema_h, name_h, pk_h, schema_digest = parts
            schema, name = _hex(schema_h), _hex(name_h)
            key = table_key(schema, name)
            if key in keys.values() or oid in by_oid:
                raise PgError(f"duplicate table key {key!r}")
            pk = _hex(pk_h)
            entry = {"pk": pk, "schema": schema_digest, "count": 0}
            entry["rows" if pk else "multiset"] = {}
            by_oid[oid] = entry
            keys[oid] = key
            if UNSAFE_NAME.search(schema) or UNSAFE_NAME.search(name):
                unsafe.append(key)
        elif tag == "R":
            if len(parts) != 4 or parts[1] not in by_oid:
                raise PgError(f"unexpected row line: {line[:200]!r}")
            entry = by_oid[parts[1]]
            entry["count"] += 1
            if "rows" in entry:
                entry["rows"][parts[2]] = parts[3]
            else:
                entry["multiset"][parts[3]] = entry["multiset"].get(parts[3], 0) + 1
        else:
            raise PgError(f"unexpected line: {line[:200]!r}")
    return {keys[oid]: by_oid[oid] for oid in by_oid}, sorted(unsafe)


def snapshot(cfg: dict, runner=run_psql) -> dict:
    pg = cfg.get("pg") or {}
    if not pg.get("enabled", True):
        return {"ok": False, "error": "disabled", "tables": {}}
    try:
        tables, unsafe = parse_snapshot(runner(SNAPSHOT_SCRIPT, cfg))
    except (PgError, OSError, subprocess.SubprocessError) as exc:
        return {"ok": False, "error": str(exc)[:500], "tables": {}}
    out = {"ok": True, "tables": tables}
    if unsafe:
        out["unsafe_names"] = unsafe
    return out


def _multiset(entry: dict) -> Counter:
    if "multiset" in entry:
        return Counter(entry["multiset"])
    return Counter(entry.get("rows", {}).values())


def op_digest(items) -> str:
    """sha256 hex over the sorted per-row items of one operation, one item per line."""
    return hashlib.sha256("\n".join(sorted(items)).encode()).hexdigest()


def _digests(ins: list, dele: list, upd: list) -> dict:
    out = {}
    for op, items in (("inserted", ins), ("deleted", dele), ("updated", upd)):
        if items:
            out[op] = op_digest(items)
    return out


def _all_items(entry: dict) -> list:
    if "rows" in entry:
        return list(entry["rows"])
    return list(_multiset(entry).elements())


def diff_tables(t0: dict, t1: dict) -> dict:
    """Per table {inserted, deleted, updated} plus dropped/created/schema_changed flags.

    `digests` says which rows: per operation the op_digest of its items. A row is its key (sha256 of
    the primary key text) or, without a primary key, sha256 of the row text; an update is
    "<key>:<sha256 of the new row text>". Both hashes are computed by Postgres in the snapshot.
    """
    out = {}
    for name in sorted(set(t0) | set(t1)):
        a, b = t0.get(name), t1.get(name)
        if a is None:
            items = _all_items(b)
            ch = {"inserted": len(items), "deleted": 0, "updated": 0, "created": True}
            dig = _digests(items, [], [])
        elif b is None:
            items = _all_items(a)
            ch = {"inserted": 0, "deleted": len(items), "updated": 0, "dropped": True}
            dig = _digests([], items, [])
        else:
            if "rows" in a and "rows" in b and a.get("pk") == b.get("pk"):
                ra, rb = a["rows"], b["rows"]
                ins = sorted(rb.keys() - ra.keys())
                dele = sorted(ra.keys() - rb.keys())
                upd = [f"{k}:{rb[k]}" for k in sorted(ra.keys() & rb.keys()) if ra[k] != rb[k]]
            else:
                ma, mb = _multiset(a), _multiset(b)
                ins = list((mb - ma).elements())
                dele = list((ma - mb).elements())
                upd = []
            ch = {"inserted": len(ins), "deleted": len(dele), "updated": len(upd)}
            if a.get("schema") != b.get("schema"):
                ch["schema_changed"] = True
            dig = _digests(ins, dele, upd)
        if any(ch.values()):
            if dig:
                ch["digests"] = dig
            out[name] = ch
    return out
