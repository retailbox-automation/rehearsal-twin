"""Goal preserved: a safer variant must still do some of what the task needs.

The original attempt's in-scope effects stand for the task: rows changed per declared table
and operation (inserted, deleted, updated, dropped, created, schema_changed), and files and
directories per operation under the declared paths. Out-of-scope items are left out: they are
what the safer variant is meant to stop doing. A declared table over its max_rows budget still
counts (the task is to change that table, only fewer rows).

A safer attempt that is in scope and exits 0 but shares none of these effects did nothing the
task needs (live run 04.11, preset b: the safer script read a file that did not exist, its guard
skipped the migration and it changed nothing). It is not approvable. When the original had no
in-scope effect at all, there is nothing to compare against and the check does not apply.
"""
from __future__ import annotations

from rt.ledger.scope import DDL_FLAGS, DIR_OPS, FILE_OPS, normalize_scope, norm_table, path_in_scope

ROW_OPS = ("inserted", "deleted", "updated")
_KIND_ORDER = {"table": 0, "dir": 1, "file": 2}
_OP_ORDER: dict[str, int] = {}
for _op in DDL_FLAGS + ROW_OPS + FILE_OPS:
    _OP_ORDER.setdefault(_op, len(_OP_ORDER))


def in_scope_effects(ledger: dict, scope_raw) -> set[tuple[str, str, str]]:
    """{(kind, op, item)}: kind table|file|dir, item a table name or a path."""
    scope = normalize_scope(scope_raw)
    tables, paths = scope["tables"], scope["paths"]
    out: set[tuple[str, str, str]] = set()
    for t_raw, ch in (ledger.get("rows") or {}).items():
        try:
            t = norm_table(t_raw)
        except ValueError:
            continue
        if t not in tables or not isinstance(ch, dict):
            continue
        for flag in DDL_FLAGS:
            if ch.get(flag):
                out.add(("table", flag, t))
        for op in ROW_OPS:
            if int(ch.get(op) or 0) > 0:
                out.add(("table", op, t))
    for group, kind, ops in (("files", "file", FILE_OPS), ("dirs", "dir", DIR_OPS)):
        facts = ledger.get(group) or {}
        for op in ops:
            for p in facts.get(op) or []:
                if path_in_scope(p, paths):
                    out.add((kind, op, p))
    return out


def describe(effect: tuple[str, str, str]) -> str:
    kind, op, item = effect
    if kind == "table":
        return f"{item} {op}" if op in DDL_FLAGS else f"{item} rows {op}"
    return f"{'directory ' if kind == 'dir' else ''}{item} {op}"


def examples(effects, limit: int = 3) -> list[str]:
    """A few effects to name, tables first and DDL before row changes."""
    ordered = sorted(effects, key=lambda e: (_KIND_ORDER.get(e[0], 9), _OP_ORDER.get(e[1], 99), e[2]))
    return [describe(e) for e in ordered[:limit]]


def check(original: set, attempt: set) -> dict | None:
    """None when the rule does not apply or the attempt shares an effect; else the no_effect finding."""
    if not original or original & attempt:
        return None
    named = examples(original)
    more = len(original) - len(named)
    expected = ", ".join(named) + (f" and {more} more" if more > 0 else "")
    return {"expected": named, "expected_total": len(original),
            "reason": f"the safer script did nothing the task needs: expected e.g. {expected}"}
