"""Settings of the control machine, read from the environment (systemd EnvironmentFile /etc/rt/env).

Names only here; values are never logged. Secrets (VULTR_API_KEY, VULTR_INFERENCE_API_KEY,
RT_RECEIPT_SIGNING_KEY, the SSH key file) are read by the modules that use them.
"""
from __future__ import annotations

import os
from dataclasses import dataclass, field
from pathlib import Path
from typing import Mapping

REPO_ROOT = Path(__file__).resolve().parents[2]

DEFAULT_TARGET_DESC = (
    "Ubuntu 24.04 demo server, run as root. Postgres database shop (tables customers, products, prices, "
    "orders, legacy_orders, sessions, audit_log, webhooks, api_keys; psql connects as root). "
    "App tree under /srv (/srv/app/tmp/cache, /srv/app/uploads, /srv/app/releases, /srv/shared/logs). "
    "Internal live API at https://prod-api.internal."
)

# Required in live mode. Secrets are checked for presence only.
LIVE_REQUIRED = ("VULTR_API_KEY", "VULTR_INFERENCE_API_KEY", "RT_RECEIPT_SIGNING_KEY", "RT_SSH_KEY_FILE",
                 "RT_GOLDEN_SNAPSHOT_ID", "RT_VPC_ID", "RT_PROD_INSTANCE_ID")


def _int(env: Mapping[str, str], name: str, default: int) -> int:
    try:
        return int(env.get(name) or default)
    except ValueError:
        return default


def _float(env: Mapping[str, str], name: str, default: float) -> float:
    try:
        return float(env.get(name) or default)
    except ValueError:
        return default


@dataclass
class Settings:
    data_dir: Path
    presets_dir: Path = REPO_ROOT / "presets"
    snapshot_id: str = ""
    vpc_id: str = ""
    prod_instance_id: str = ""
    prod_label: str = "prod-shop-01"
    twin_plan: str = "vc2-1c-2gb"
    region: str = "ewr"
    ssh_key_file: str = ""
    jump_host: str | None = None
    target_desc: str = DEFAULT_TARGET_DESC
    max_safer_attempts: int = 3
    max_twins_alive: int = 3
    ready_timeout_s: float = 900.0
    poll_s: float = 5.0
    wall_s: int = 60
    mem: str = "512M"
    pids: int = 256
    api_token: str = ""
    sse_max_s: float = 1800.0
    twin_slot_wait_s: float = 600.0
    reaper_ttl_s: float = 900.0
    lease_stale_s: float = 300.0
    restore_timeout_s: float = 1800.0
    restore_poll_s: float = 10.0
    restore_settle_s: float = 30.0
    approval_window_s: float = 1800.0
    judge_mode: bool = False
    judge_runs_per_ip_hour: int = 3
    daily_run_budget: int = 30
    max_queue: int = 10
    missing: list[str] = field(default_factory=list)

    @classmethod
    def from_env(cls, env: Mapping[str, str] | None = None) -> "Settings":
        env = os.environ if env is None else env
        return cls(
            data_dir=Path(env.get("RT_DATA_DIR") or "/var/lib/rt"),
            presets_dir=Path(env.get("RT_PRESETS_DIR") or REPO_ROOT / "presets"),
            snapshot_id=env.get("RT_GOLDEN_SNAPSHOT_ID", ""),
            vpc_id=env.get("RT_VPC_ID", ""),
            prod_instance_id=env.get("RT_PROD_INSTANCE_ID", ""),
            prod_label=env.get("RT_PROD_LABEL") or "prod-shop-01",
            twin_plan=env.get("RT_TWIN_PLAN") or "vc2-1c-2gb",
            region=env.get("RT_REGION") or "ewr",
            ssh_key_file=env.get("RT_SSH_KEY_FILE", ""),
            jump_host=env.get("RT_JUMP_HOST") or None,
            target_desc=env.get("RT_TARGET_DESC") or DEFAULT_TARGET_DESC,
            max_safer_attempts=max(0, min(3, _int(env, "RT_MAX_SAFER_ATTEMPTS", 3))),
            max_twins_alive=max(1, min(3, _int(env, "RT_MAX_TWINS_ALIVE", 3))),
            ready_timeout_s=_float(env, "RT_TWIN_READY_TIMEOUT_S", 900.0),
            poll_s=_float(env, "RT_POLL_S", 5.0),
            wall_s=_int(env, "RT_RUN_WALL_S", 60),
            mem=env.get("RT_RUN_MEM") or "512M",
            pids=_int(env, "RT_RUN_PIDS", 256),
            api_token=env.get("RT_API_TOKEN", ""),
            sse_max_s=_float(env, "RT_SSE_MAX_S", 1800.0),
            twin_slot_wait_s=_float(env, "RT_TWIN_SLOT_WAIT_S", 600.0),
            reaper_ttl_s=_float(env, "RT_REAPER_TTL_S", 900.0),
            lease_stale_s=_float(env, "RT_LEASE_STALE_S", 300.0),
            restore_timeout_s=_float(env, "RT_RESTORE_TIMEOUT_S", 1800.0),
            restore_settle_s=_float(env, "RT_RESTORE_SETTLE_S", 30.0),
            approval_window_s=_float(env, "RT_APPROVAL_WINDOW_S", 1800.0),
            judge_mode=(env.get("RT_JUDGE_MODE") or "off").strip().lower() in ("on", "1", "true", "yes"),
            judge_runs_per_ip_hour=max(0, _int(env, "RT_JUDGE_RUNS_PER_IP_HOUR", 3)),
            daily_run_budget=max(0, _int(env, "RT_DAILY_RUN_BUDGET", 30)),
            max_queue=max(0, _int(env, "RT_MAX_QUEUE", 10)),
            missing=[n for n in LIVE_REQUIRED if not env.get(n)],
        )
