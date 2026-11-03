"""Run one script under rtrace on a twin or on production, over Machine.exec / Machine.put.

Every file goes to /opt/rt/work/<run>/ on the target: outside every tracked root, so the
script, scope.json and the state/run/ledger files never show up in the ledger itself.
The ledger is read from `rtrace diff` stdout; the run record (script stdout/stderr) stays
on the target.

State version: a hash of what the script can act on — files under the app roots and
the declared paths (content, type, mode, owner; not mtime when content is hashed) and
every Postgres table (row hashes, schema). It is taken from `rtrace before` output, so
the same function versions production at rehearsal, at approval and right before apply.
Paths outside those roots (for example /etc/hostname, which every new instance rewrites)
do not change the version.
"""
from __future__ import annotations

import hashlib
import json
from typing import Any, Callable, Protocol

RT_BIN = "/opt/rt/bin/rtrace"
WORK = "/opt/rt/work"
STATE_ROOTS = ("/srv", "/opt/shop", "/etc/cron.d", "/var/spool/cron")
PHASES = ("before", "run", "after", "diff")


class Machine(Protocol):
    id: str

    def exec(self, argv: list[str], stdin: bytes | str | None = None, timeout: float = 60.0) -> tuple[int, str, str]:
        ...

    def put(self, path: str, data: bytes, mode: int = 0o644, timeout: float = 60.0) -> None:
        ...


class TraceError(Exception):
    def __init__(self, phase: str, message: str):
        super().__init__(f"{phase}: {message}")
        self.phase = phase


class StateShift(Exception):
    """Production is not in the state the approval was given for. Raised before the script runs."""

    def __init__(self, expected: str, found: str, changed: list[str]):
        super().__init__(f"production state is {found[:12]}, approval was for {expected[:12]}")
        self.expected = expected
        self.found = found
        self.changed = changed


def _sha(obj: Any) -> str:
    return hashlib.sha256(json.dumps(obj, sort_keys=True, separators=(",", ":")).encode()).hexdigest()


def _under(path: str, roots) -> bool:
    return any(path == r or path.startswith(r.rstrip("/") + "/") for r in roots)


def state_manifest(state: dict, scope: dict | None = None) -> dict[str, str]:
    """{"f:/path": digest, "t:table": digest} for the parts of an rtrace state a script can act on."""
    roots = tuple(STATE_ROOTS) + tuple((scope or {}).get("paths") or ())
    out: dict[str, str] = {}
    for path, e in (state.get("files") or {}).items():
        if not _under(path, roots):
            continue
        keep = {k: e.get(k) for k in ("t", "size", "mode", "uid", "gid", "sha256", "target", "err")}
        if e.get("t") == "f" and not e.get("sha256"):
            keep["mtime_ns"] = e.get("mtime_ns")
        out["f:" + path] = _sha(keep)[:32]
    pg = state.get("pg") or {}
    if pg.get("ok"):
        for table, entry in (pg.get("tables") or {}).items():
            out["t:" + table] = _sha(entry)[:32]
    else:
        out["pg:unreadable"] = _sha(pg.get("error") or "")[:32]
    return out


def state_version(manifest: dict[str, str]) -> str:
    return _sha(manifest)


def manifest_changes(old: dict[str, str], new: dict[str, str], limit: int = 20) -> list[str]:
    out = []
    for key in sorted(set(old) | set(new)):
        if old.get(key) != new.get(key):
            what = "added" if key not in old else "removed" if key not in new else "changed"
            out.append(f"{key[2:] if key[1] == ':' else key} {what}")
            if len(out) >= limit:
                out.append("...")
                break
    return out


def work_dir(run: str) -> str:
    if not run or not all(c.isalnum() or c == "-" for c in run):
        raise ValueError(f"bad run name {run!r}")
    return f"{WORK}/{run}"


def _check(phase: str, rc: int, err: str) -> None:
    if rc != 0:
        raise TraceError(phase, f"exit {rc}: {err.strip()[:300]}")


def read_state(m: Machine, run: str, scope: dict, *, timeout: float = 300.0) -> dict:
    """Put scope.json in the run dir and return `rtrace before` output (also kept there as state0.json)."""
    w = work_dir(run)
    m.put(f"{w}/scope.json", json.dumps(scope, sort_keys=True).encode(), mode=0o600)
    rc, out, err = m.exec(["sh", "-c", f'cd "$1" && {RT_BIN} before --scope scope.json > state0.json && cat state0.json',
                           "sh", w], timeout=timeout)
    _check("before", rc, err)
    try:
        state = json.loads(out)
    except json.JSONDecodeError:
        raise TraceError("before", "rtrace before did not print JSON") from None
    if not isinstance(state, dict) or state.get("kind") != "rt-state":
        raise TraceError("before", "rtrace before printed something other than a state")
    return state


def drop_run_dir(m: Machine, run: str) -> None:
    w = work_dir(run)
    try:
        m.exec(["sh", "-c", 'rm -rf -- "${1:?}"', "sh", w], timeout=60)
    except Exception:  # best effort: the directory is outside every tracked root
        pass


def trace(m: Machine, run: str, script: bytes, scope: dict, files: dict[str, bytes] | None = None, *,
          wall_s: int = 60, mem: str = "512M", pids: int = 256,
          on_phase: Callable[[str, dict], None] | None = None,
          expect_version: str | None = None, expect_manifest: dict[str, str] | None = None) -> dict:
    """Run the script under rtrace and return {ledger, state_version, manifest}.

    With expect_version, the `before` state must have that version, or StateShift is raised
    before the script runs.
    """
    w = work_dir(run)
    note = on_phase or (lambda phase, info: None)
    for name, data in sorted((files or {}).items()):
        m.put(f"{w}/{name}", data, mode=0o600)
    m.put(f"{w}/script.sh", script, mode=0o700)

    state = read_state(m, run, scope)
    manifest = state_manifest(state, scope)
    version = state_version(manifest)
    note("before", {"state_version": version})
    if expect_version is not None and version != expect_version:
        raise StateShift(expect_version, version, manifest_changes(expect_manifest or {}, manifest))

    rc, _, err = m.exec(["sh", "-c", f'cd "$1" && {RT_BIN} run --script "$1/script.sh" --wall "$2" --mem "$3" '
                         f'--pids "$4" > run.json', "sh", w, str(wall_s), mem, str(pids)],
                        timeout=wall_s + 120)
    _check("run", rc, err)
    note("run", {})

    rc, _, err = m.exec(["sh", "-c", f'cd "$1" && {RT_BIN} after --scope scope.json > state1.json', "sh", w],
                        timeout=300)
    _check("after", rc, err)
    note("after", {})

    rc, out, err = m.exec([RT_BIN, "diff", f"{w}/state0.json", f"{w}/state1.json", f"{w}/run.json",
                           "--scope", f"{w}/scope.json"], timeout=300)
    _check("diff", rc, err)
    try:
        ledger = json.loads(out)
    except json.JSONDecodeError:
        raise TraceError("diff", "rtrace diff did not print JSON") from None
    if not isinstance(ledger, dict):
        raise TraceError("diff", "rtrace diff printed something other than a ledger")
    note("diff", {"ledger_sha256": ledger.get("ledger_sha256")})
    return {"ledger": ledger, "state_version": version, "manifest": manifest}
