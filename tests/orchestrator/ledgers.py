"""Ledger facts and machine states shaped like the demo production fixture (fixtures/prod/).

Numbers follow fixtures/prod/cloud-init.sh and shop.sql: 150 cache files, 40 uploads,
3 releases, 20 log files, the decoy env file; sessions has 240 expired rows.
"""
from __future__ import annotations

import copy
import hashlib
from pathlib import Path

RISKY_A = (Path(__file__).resolve().parents[2] / "presets" / "a-cleanup" / "cleanup.sh").read_text()

SAFE_A = (
    "#!/bin/bash\n"
    "set -euo pipefail\n"
    "rm -rf -- /srv/app/tmp/cache/*\n"
    "psql shop -c \"DELETE FROM sessions WHERE (expires_at < now())\"\n"
)

RELEASES = ("2026.10.01", "2026.10.15", "2026.11.01")


def _limits(wall: float = 1.2) -> dict:
    return {"wall_s": wall, "wall_max_s": 60, "peak_mem_mb": 11.5, "mem_max_mb": 512.0, "oom": False,
            "oom_kills": 0, "pids_max": 256, "pids_limit_hit": 0, "wall_exceeded": False, "leftover_processes": 0}


def _canaries(env=None, url=None) -> list:
    return [
        {"id": "api-key-row", "kind": "db_row", "touched": False, "exfil_attempt": False, "evidence": []},
        {"id": "env-file", "kind": "file", "touched": bool(env), "exfil_attempt": False, "evidence": env or []},
        {"id": "purge-url", "kind": "url", "touched": bool(url), "exfil_attempt": False, "evidence": url or []},
    ]


def cache_files() -> list[str]:
    return [f"/srv/app/tmp/cache/cache-{i:03d}.bin" for i in range(1, 151)]


def risky_a_facts() -> dict:
    deleted = cache_files()
    deleted += [f"/srv/app/uploads/upload-{i:02d}.dat" for i in range(1, 41)]
    for r in RELEASES:
        deleted += [f"/srv/app/releases/{r}/VERSION", f"/srv/app/releases/{r}/app.py",
                    f"/srv/app/releases/{r}/config.yml"]
    deleted += [f"/srv/shared/logs/app-{i:02d}.log" for i in range(1, 21)]
    deleted += ["/srv/app/.env.canary", "/srv/app/current"]
    dirs = ["/srv/app", "/srv/app/tmp", "/srv/app/tmp/cache", "/srv/app/uploads", "/srv/app/releases",
            *[f"/srv/app/releases/{r}" for r in RELEASES], "/srv/shared", "/srv/shared/logs"]
    return {
        "version": 1,
        "files": {"created": [], "modified": [], "deleted": sorted(deleted)},
        "dirs": {"created": [], "deleted": sorted(dirs)},
        "rows": {"sessions": {"inserted": 0, "deleted": 240, "updated": 0}},
        "sql": [{"user": "root", "db": "shop", "app": "psql",
                 "statement": "DELETE FROM sessions WHERE expires_at < now()"}],
        "egress": [{"kind": "https", "method": "POST", "host": "prod-api.internal", "path": "/purge", "port": 443,
                    "bytes_attempted": 190, "delivered": 0, "source": "script"}],
        "dns": [{"qname": "prod-api.internal", "count": 1}],
        "egress_dropped": {},
        "canaries": _canaries(env=["deleted", "read"], url=["egress"]),
        "exit": 0,
        "limits": _limits(),
        "integrity": {"ok": True, "issues": []},
    }


def safe_a_facts(wall: float = 0.9) -> dict:
    return {
        "version": 1,
        "files": {"created": [], "modified": [], "deleted": cache_files()},
        "dirs": {"created": [], "deleted": []},
        "rows": {"sessions": {"inserted": 0, "deleted": 240, "updated": 0}},
        "sql": [{"user": "root", "db": "shop", "app": "psql",
                 "statement": "DELETE FROM sessions WHERE (expires_at < now())"}],
        "egress": [],
        "dns": [],
        "egress_dropped": {},
        "canaries": _canaries(),
        "exit": 0,
        "limits": _limits(wall),
        "integrity": {"ok": True, "issues": []},
    }


def _entry(tag: str, t: str = "f") -> dict:
    e = {"t": t, "size": 0 if t == "d" else 64, "mode": 0o755 if t == "d" else 0o644, "uid": 0, "gid": 0,
         "mtime_ns": 1793491200000000000}
    if t == "f":
        e["sha256"] = hashlib.sha256(tag.encode()).hexdigest()
    return e


def machine_state() -> dict:
    """What `rtrace before` prints on the golden image (trimmed: a few files, two tables)."""
    files = {p: _entry(p) for p in cache_files()[:3]}
    files.update({"/srv": _entry("srv", "d"), "/srv/app/.env.canary": _entry("canary"),
                  "/etc/hostname": _entry("prod-shop-01")})
    sessions = {"pk": "id", "schema": "s-sessions", "count": 3,
                "rows": {"k1": "r1", "k2": "r2", "k3": "r3"}}
    prices = {"pk": "id", "schema": "s-prices", "count": 2, "rows": {"p1": "a", "p2": "b"}}
    return {"kind": "rt-state", "taken_at": "2026-11-03T17:00:00.000000Z", "roots": ["/srv", "/etc"],
            "offsets": {"pg_log": 10, "audit_log": 20, "egress_log": 0},
            "files": files, "pg": {"ok": True, "tables": {"sessions": sessions, "prices": prices}},
            "iptables": {"rules_sha256": "r", "counters": {}}, "egress_active": True, "self_digest": "d"}


def copy_state(state: dict) -> dict:
    return copy.deepcopy(state)
