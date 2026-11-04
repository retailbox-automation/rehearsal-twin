"""Readers for the logs a rehearsal window is cut from: Postgres, auditd, egress recorder.

The window is a byte range [start, end) recorded by `run` and `after`, so no
clock parsing is needed and the tracer's own reads before/after the run are
outside the window.
"""
from __future__ import annotations

import json
import os
import re
import shlex


def size_of(path: str) -> int:
    try:
        return os.stat(path).st_size
    except OSError:
        return 0


def read_window(path: str, start: int, end: int | None = None, limit: int = 64 * 1024 * 1024) -> str:
    """Bytes [start, end) of a log. If the file shrank (rotated), read from 0."""
    try:
        with open(path, "rb") as f:
            f.seek(0, os.SEEK_END)
            size = f.tell()
            if start > size:
                start = 0
            stop = size if end is None or end > size or end < start else end
            f.seek(start)
            data = f.read(min(stop - start, limit))
    except OSError:
        return ""
    return data.decode("utf-8", "replace")


# log_line_prefix = '%m [%p] %u@%d %a: '
PG_LINE = re.compile(
    r"^(?P<ts>\d{4}-\d\d-\d\d \d\d:\d\d:\d\d(?:\.\d+)?(?: \S+)?) \[(?P<pid>\d+)\] "
    r"(?P<user>[^@\s]*)@(?P<db>\S*) (?P<app>.*?): "
    r"(?P<level>LOG|ERROR|FATAL|PANIC|WARNING|NOTICE|DETAIL|HINT|STATEMENT|CONTEXT):\s+(?P<msg>.*)$"
)
PG_STATEMENT = re.compile(r"^(?:statement|execute [^:]*):\s?(?P<sql>.*)$", re.S)


def parse_pg_log(text: str, exclude_users=()) -> list:
    """Statements logged with log_statement='all', in order; errors attached to their statement.

    Lines of the roles in exclude_users (the tracer's own role) are dropped. The user field is the
    session user Postgres authenticated; application_name is set by the client and never used here.
    """
    out = []
    last_by_pid = {}
    current = None
    for raw in text.splitlines():
        if raw.startswith("\t") and current is not None:
            current["statement"] += "\n" + raw[1:]
            continue
        m = PG_LINE.match(raw)
        if not m:
            current = None
            continue
        current = None
        app = m.group("app")
        if m.group("user") in exclude_users:
            continue
        level, msg, pid = m.group("level"), m.group("msg"), m.group("pid")
        if level == "LOG":
            s = PG_STATEMENT.match(msg)
            if not s:
                continue
            entry = {"user": m.group("user"), "db": m.group("db"), "app": app, "statement": s.group("sql")}
            out.append(entry)
            last_by_pid[pid] = entry
            current = entry
        elif level == "ERROR" and pid in last_by_pid:
            last_by_pid[pid]["error"] = msg
    for e in out:
        e["statement"] = e["statement"].rstrip()
    return out


AUDIT_MSG = re.compile(r"msg=audit\((?P<ts>[\d.]+):(?P<serial>\d+)\)")


def _kv(line: str) -> dict:
    out = {}
    try:
        tokens = shlex.split(line, posix=True)
    except ValueError:
        tokens = line.split()
    for tok in tokens:
        k, sep, v = tok.partition("=")
        if sep:
            out[k] = v
    return out


def parse_audit_log(text: str, keys=None) -> list:
    """SYSCALL records carrying one of the given audit keys."""
    out = []
    for line in text.splitlines():
        if not line.startswith("type=SYSCALL"):
            continue
        kv = _kv(line)
        key = kv.get("key")
        if not key or key == "(null)" or (keys and key not in keys):
            continue
        m = AUDIT_MSG.search(line)
        out.append({
            "key": key,
            "syscall": kv.get("syscall") or kv.get("SYSCALL"),
            "success": kv.get("success"),
            "comm": kv.get("comm"),
            "exe": kv.get("exe"),
            "serial": int(m.group("serial")) if m else None,
        })
    return out


def parse_jsonl(text: str) -> tuple[list, int]:
    """Records and the number of unparsable lines (never silently dropped)."""
    out, bad = [], 0
    for line in text.splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            rec = json.loads(line)
        except ValueError:
            bad += 1
            continue
        if isinstance(rec, dict):
            out.append(rec)
        else:
            bad += 1
    return out, bad
