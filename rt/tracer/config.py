"""Tracer configuration. Installed copy lives in /opt/rt/config.json (outside every tracked root)."""
from __future__ import annotations

import json
import os

RT_HOME = "/opt/rt"

DEFAULTS = {
    "track_roots": ["/srv", "/etc", "/home", "/root", "/usr/local", "/var/spool/cron", "/var/www", "/opt/shop"],
    "exclude": [RT_HOME, "/proc", "/sys", "/dev", "/run"],
    "self_root": RT_HOME,
    "hash_limit": 4 * 1024 * 1024,
    "pg": {
        "enabled": True,
        "dbname": "shop",
        "run_as": "postgres",
        "log_path": "/var/log/postgresql/postgresql-16-main.log",
        "exclude_apps": ["rtrace", "shop-webhooks"],
    },
    "audit_log": "/var/log/audit/audit.log",
    "egress_log": "/var/log/rt-egress/egress.jsonl",
    "egress_ignore_units": [
        "systemd-timesyncd.service",
        "snapd.service",
        "unattended-upgrades.service",
        "apt-daily.service",
        "apt-daily-upgrade.service",
        "motd-news.service",
        "fwupd-refresh.service",
        "ua-timer.service",
    ],
    "canaries_path": RT_HOME + "/canaries.json",
    "run_slice": "rt.slice",
    # Extra addresses the sandboxed script may reach besides localhost and the recorder's
    # fake range. Empty on purpose: the script must not reach the control machine.
    "sandbox_allow": [],
}


def _merge(base: dict, over: dict) -> dict:
    out = dict(base)
    for k, v in over.items():
        if isinstance(v, dict) and isinstance(out.get(k), dict):
            out[k] = _merge(out[k], v)
        else:
            out[k] = v
    return out


def load(path: str | None = None) -> dict:
    path = path or os.environ.get("RT_CONFIG") or (RT_HOME + "/config.json")
    try:
        with open(path, encoding="utf-8") as f:
            return _merge(DEFAULTS, json.load(f))
    except FileNotFoundError:
        return _merge(DEFAULTS, {})


def load_canaries(path: str) -> list:
    """Canary definitions with tokens. Tokens never go into a ledger."""
    try:
        with open(path, encoding="utf-8") as f:
            return list(json.load(f).get("canaries") or [])
    except FileNotFoundError:
        return []
