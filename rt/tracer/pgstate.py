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
add a line or a field. Per row Postgres computes sha256 of the primary key, of the whole row, of
the row without its volatile columns (date/time types, defaults that read the clock, a random
source or a sequence) and a short per-column signature; diff_tables builds the row digests from
these so the same script gives the same digests on a twin and on production. The session pins search_path and the output settings first: the database
owner can change their defaults (ALTER DATABASE ... SET), which would otherwise change the
functions this query calls or the text form of every row.
"""
from __future__ import annotations

import hashlib
import json
import re
import subprocess
from collections import Counter

SEP = "\x1f"
COLSIG_HEX = 16  # hex digits per column in a row's column signature
# Names with these characters are traced like any other table and reported as an integrity issue.
UNSAFE_NAME = re.compile(r"[\\\x00-\x1f\x7f]")
_SIMPLE = re.compile(r"^[a-z_][a-z0-9_]*$")

# A column whose value differs between two machines running the same script: date and time
# types, and defaults that read the clock, a random source or a sequence.
_VOLATILE_COL = r"""(
      (SELECT coalesce(nullif(ty.typbasetype, 0), ty.oid) FROM pg_type ty WHERE ty.oid = a.atttypid)
        IN ('timestamp'::regtype, 'timestamptz'::regtype, 'date'::regtype, 'time'::regtype, 'timetz'::regtype)
      OR coalesce(lower(pg_get_expr(d.adbin, d.adrelid)), '') ~ ('(now|clock_timestamp|statement_timestamp|'
           'transaction_timestamp|timeofday|random|gen_random_uuid|uuid_generate_v[14]|nextval)[(]'
           '|current_(timestamp|date|time)|localtime'))"""

_TABLES_CTE = r"""WITH tbl AS (
  SELECT c.oid, c.relkind, n.nspname, c.relname,
    (SELECT array_agg(a.attname ORDER BY array_position(i.indkey::int2[], a.attnum))
       FROM pg_index i JOIN pg_attribute a ON a.attrelid = i.indrelid AND a.attnum = ANY(i.indkey)
      WHERE i.indrelid = c.oid AND i.indisprimary) AS pk,
    (SELECT array_agg(a.attname ORDER BY a.attnum)
       FROM pg_attribute a WHERE a.attrelid = c.oid AND a.attnum > 0 AND NOT a.attisdropped) AS cols,
    (SELECT array_agg(""" + _VOLATILE_COL + r""" ORDER BY a.attnum)
       FROM pg_attribute a LEFT JOIN pg_attrdef d ON d.adrelid = a.attrelid AND d.adnum = a.attnum
      WHERE a.attrelid = c.oid AND a.attnum > 0 AND NOT a.attisdropped) AS vol
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
    coalesce((SELECT string_agg(a.attname || ':' || format_type(a.atttypid, a.atttypmod) || '='
                                || coalesce(pg_get_expr(d.adbin, d.adrelid), ''), ',' ORDER BY a.attnum)
                FROM pg_attribute a LEFT JOIN pg_attrdef d ON d.adrelid = a.attrelid AND d.adnum = a.attnum
               WHERE a.attrelid = tbl.oid AND a.attnum > 0 AND NOT a.attisdropped), '')
    || '|' ||
    coalesce((SELECT string_agg(t.tgname, ',' ORDER BY t.tgname)
                FROM pg_trigger t WHERE t.tgrelid = tbl.oid AND NOT t.tgisinternal), ''), 'UTF8')), 'hex'),
  coalesce((SELECT string_agg(encode(convert_to(x, 'UTF8'), 'hex'), ',' ORDER BY o)
              FROM unnest(tbl.cols) WITH ORDINALITY u(x, o)), ''),
  coalesce((SELECT string_agg(CASE WHEN v THEN '1' ELSE '0' END, '' ORDER BY o)
              FROM unnest(tbl.vol) WITH ORDINALITY u(v, o)), '')
FROM tbl ORDER BY tbl.nspname, tbl.relname;
""" + _TABLES_CTE + r"""
SELECT format('SELECT ''R'', %s, %s, encode(sha256(convert_to(ROW(t.*)::text, ''UTF8'')), ''hex''), '
              'encode(sha256(convert_to(ROW(%s)::text, ''UTF8'')), ''hex''), %s FROM %s %I.%I t',
  tbl.oid,
  CASE WHEN tbl.pk IS NULL THEN 'NULL'
       ELSE format('encode(sha256(convert_to((%s)::text, ''UTF8'')), ''hex'')',
                   CASE WHEN array_length(tbl.pk, 1) = 1 THEN 't.' || quote_ident(tbl.pk[1])
                        ELSE 'ROW(' || (SELECT string_agg('t.' || quote_ident(x), ', ' ORDER BY o)
                                          FROM unnest(tbl.pk) WITH ORDINALITY u(x, o)) || ')' END) END,
  coalesce((SELECT string_agg('t.' || quote_ident(x), ', ' ORDER BY o)
              FROM unnest(tbl.cols, tbl.vol) WITH ORDINALITY u(x, v, o) WHERE NOT v), ''),
  coalesce((SELECT string_agg(format('left(encode(sha256(convert_to(CASE WHEN t.%1$I IS NULL THEN ''n'' '
                                     'ELSE ''v'' || t.%1$I::text END, ''UTF8'')), ''hex''), 16)', x), ' || ' ORDER BY o)
              FROM unnest(tbl.cols) WITH ORDINALITY u(x, o)), ''''''),
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
            if len(parts) != 9 or not parts[1].isdigit():
                raise PgError(f"unexpected table line: {line[:200]!r}")
            _, oid, _kind, schema_h, name_h, pk_h, schema_digest, cols_h, vol = parts
            schema, name = _hex(schema_h), _hex(name_h)
            key = table_key(schema, name)
            if key in keys.values() or oid in by_oid:
                raise PgError(f"duplicate table key {key!r}")
            pk = _hex(pk_h)
            cols = [_hex(c) for c in cols_h.split(",")] if cols_h else []
            if len(vol) != len(cols) or set(vol) - {"0", "1"}:
                raise PgError(f"unexpected column flags: {line[:200]!r}")
            entry = {"pk": pk, "schema": schema_digest, "count": 0, "columns": cols,
                     "volatile": [c for c, v in zip(cols, vol) if v == "1"]}
            entry["rows" if pk else "multiset"] = {}
            by_oid[oid] = entry
            keys[oid] = key
            if UNSAFE_NAME.search(schema) or UNSAFE_NAME.search(name):
                unsafe.append(key)
        elif tag == "R":
            if len(parts) != 6 or parts[1] not in by_oid:
                raise PgError(f"unexpected row line: {line[:200]!r}")
            entry = by_oid[parts[1]]
            _, _, key, full, stable, sig = parts
            if len(sig) != COLSIG_HEX * len(entry["columns"]):
                raise PgError(f"unexpected column signature: {line[:200]!r}")
            value = f"{full}:{stable}:{sig}"
            entry["count"] += 1
            if "rows" in entry:
                entry["rows"][key] = value
            else:
                entry["multiset"][value] = entry["multiset"].get(value, 0) + 1
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


def split_row(value: str) -> tuple[str, str, str]:
    """A row value is "<sha256 of the row>:<sha256 of its stable columns>:<column signature>".

    Stable columns leave out date/time types and columns whose default reads the clock, a random
    source or a sequence: their values differ between a twin and production running the same
    script. The column signature is COLSIG_HEX hex digits of sha256 per column, in column order.
    A value without ':' (a state written before these fields) is its own stable hash.
    """
    full, sep, rest = value.partition(":")
    if not sep:
        return value, value, ""
    stable, _, sig = rest.partition(":")
    return full, stable, sig


def _col_sigs(entry: dict, sig: str) -> dict:
    cols = entry.get("columns") or []
    if len(sig) != COLSIG_HEX * len(cols):
        return {}
    return {c: sig[i * COLSIG_HEX:(i + 1) * COLSIG_HEX] for i, c in enumerate(cols)}


def changed_columns(a: dict, va: str, b: dict, vb: str) -> list:
    """Names of the columns whose value differs between two versions of a row (added or dropped
    columns count as changed). Empty when the signatures are missing (an older state)."""
    sa, sb = _col_sigs(a, split_row(va)[2]), _col_sigs(b, split_row(vb)[2])
    if not sa or not sb:
        return []
    return sorted(c for c in set(sa) | set(sb) if sa.get(c) != sb.get(c))


def _key_value(key: str, value: str) -> str:
    return f"{key}:{split_row(value)[1]}"


def _digests(ins: list, dele: list, upd: list) -> dict:
    out = {}
    for op, items in (("inserted", ins), ("deleted", dele), ("updated", upd)):
        if items:
            out[op] = op_digest(items)
    return out


def _created_items(entry: dict) -> list:
    if "rows" in entry:
        return [_key_value(k, v) for k, v in entry["rows"].items()]
    return [split_row(v)[1] for v in _multiset(entry).elements()]


def _deleted_items(entry: dict) -> list:
    if "rows" in entry:
        return list(entry["rows"])
    return [split_row(v)[1] for v in _multiset(entry).elements()]


def diff_tables(t0: dict, t1: dict) -> dict:
    """Per table {inserted, deleted, updated} plus dropped/created/schema_changed flags.

    Counts compare whole rows. `digests` says which rows and what they became, built so that
    the same script gives the same digests on a twin and on production even when it writes
    now() or a default fills a timestamp, uuid or sequence value (see split_row):
      inserted  "<key>:<stable hash of the new row>"   (no primary key: the stable hash)
      deleted   "<key>"                                (no primary key: the stable hash)
      updated   "<key>:<changed column names, JSON>:<stable hash of the new row>"
    <key> is sha256 of the primary key text; every hash is computed by Postgres. Each digest is
    op_digest over the items of that operation; an operation with no rows has no digest.
    """
    out = {}
    for name in sorted(set(t0) | set(t1)):
        a, b = t0.get(name), t1.get(name)
        if a is None:
            ch = {"inserted": b.get("count", 0), "deleted": 0, "updated": 0, "created": True}
            dig = _digests(_created_items(b), [], [])
        elif b is None:
            ch = {"inserted": 0, "deleted": a.get("count", 0), "updated": 0, "dropped": True}
            dig = _digests([], _deleted_items(a), [])
        else:
            if "rows" in a and "rows" in b and a.get("pk") == b.get("pk"):
                ra, rb = a["rows"], b["rows"]
                new_keys = sorted(rb.keys() - ra.keys())
                gone = sorted(ra.keys() - rb.keys())
                changed = [k for k in sorted(ra.keys() & rb.keys()) if ra[k] != rb[k]]
                ins = [_key_value(k, rb[k]) for k in new_keys]
                dele = gone
                upd = [f"{k}:{json.dumps(changed_columns(a, ra[k], b, rb[k]), separators=(',', ':'))}:"
                       f"{split_row(rb[k])[1]}" for k in changed]
                n_ins, n_del, n_upd = len(new_keys), len(gone), len(changed)
            else:
                ma, mb = _multiset(a), _multiset(b)
                added, removed = list((mb - ma).elements()), list((ma - mb).elements())
                ins = [split_row(v)[1] for v in added]
                dele = [split_row(v)[1] for v in removed]
                upd = []
                n_ins, n_del, n_upd = len(added), len(removed), 0
            ch = {"inserted": n_ins, "deleted": n_del, "updated": n_upd}
            if a.get("schema") != b.get("schema"):
                ch["schema_changed"] = True
            dig = _digests(ins, dele, upd)
        if any(ch.values()):
            if dig:
                ch["digests"] = dig
            out[name] = ch
    return out
