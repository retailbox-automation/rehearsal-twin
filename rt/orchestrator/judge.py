"""Judge mode: anyone without the token may start a preset, within limits, and approve their own run.

Limits, kept on disk so a restart does not reset them (<data_dir>/judge-runs.json):
  runs per client address per hour (RT_JUDGE_RUNS_PER_IP_HOUR), runs per UTC day for all
  judges together (RT_DAILY_RUN_BUDGET). Addresses are stored only as a salted hash.
Client address: the peer, unless the peer is the local reverse proxy (127.0.0.1 / ::1);
then the rightmost X-Forwarded-For entry, the one Caddy itself appended.
Ownership: a judge run returns an owner key once; the record keeps only its sha256.
"""
from __future__ import annotations

import hashlib
import hmac
import json
import secrets
import threading
import time
from datetime import datetime, timezone
from pathlib import Path

from rt.orchestrator.store import _atomic_write

TRUSTED_PROXIES = frozenset({"127.0.0.1", "::1"})
RUNS_FILE = "judge-runs.json"
SALT_FILE = "judge-salt"


class Limited(Exception):
    def __init__(self, reason: str, retry_after_s: int):
        super().__init__(reason)
        self.reason = reason
        self.retry_after_s = max(1, int(retry_after_s))


def client_address(peer: str | None, forwarded_for: str | None) -> str:
    peer = (peer or "").strip()
    if peer in TRUSTED_PROXIES and forwarded_for:
        last = forwarded_for.split(",")[-1].strip()
        if last:
            return last
    return peer or "unknown"


def new_owner_key() -> tuple[str, str]:
    key = secrets.token_urlsafe(24)
    return key, hashlib.sha256(key.encode()).hexdigest()


def owner_matches(key: str | None, digest: str | None) -> bool:
    if not key or not digest:
        return False
    return hmac.compare_digest(hashlib.sha256(key.encode()).hexdigest(), digest)


def _day_start(ts: float) -> float:
    d = datetime.fromtimestamp(ts, timezone.utc)
    return datetime(d.year, d.month, d.day, tzinfo=timezone.utc).timestamp()


class JudgeGate:
    def __init__(self, data_dir: Path | str, *, per_ip_hour: int, daily_budget: int, clock=time.time):
        self.dir = Path(data_dir)
        self.per_ip_hour = per_ip_hour
        self.daily_budget = daily_budget
        self.clock = clock
        self._lock = threading.Lock()
        self._salt = self._load_salt()

    def _load_salt(self) -> bytes:
        p = self.dir / SALT_FILE
        try:
            return p.read_bytes()
        except FileNotFoundError:
            salt = secrets.token_bytes(16)
            _atomic_write(p, salt)
            return salt

    def address_tag(self, address: str) -> str:
        return hashlib.sha256(self._salt + address.encode()).hexdigest()[:16]

    def _runs(self) -> list[list]:
        try:
            data = json.loads((self.dir / RUNS_FILE).read_text(encoding="utf-8"))
            return [r for r in data.get("runs", []) if isinstance(r, list) and len(r) == 2]
        except (FileNotFoundError, json.JSONDecodeError, AttributeError):
            return []

    def admit(self, address: str) -> None:
        """Count one judge run for this address, or raise Limited without counting it."""
        with self._lock:
            now = self.clock()
            runs = [r for r in self._runs() if now - float(r[0]) < 86400 + 3600]
            tag = self.address_tag(address)
            mine = sorted(float(t) for t, a in runs if a == tag and now - float(t) < 3600)
            if len(mine) >= self.per_ip_hour:
                raise Limited(f"{self.per_ip_hour} runs per hour from one address", mine[0] + 3600 - now)
            today = [r for r in runs if float(r[0]) >= _day_start(now)]
            if len(today) >= self.daily_budget:
                raise Limited(f"daily budget of {self.daily_budget} runs is used up", _day_start(now) + 86400 - now)
            runs.append([round(now, 3), tag])
            _atomic_write(self.dir / RUNS_FILE, json.dumps({"runs": runs}).encode())

    def status(self) -> dict:
        now = self.clock()
        today = [r for r in self._runs() if float(r[0]) >= _day_start(now)]
        return {"runs_today": len(today), "daily_budget": self.daily_budget, "per_ip_hour": self.per_ip_hour}
