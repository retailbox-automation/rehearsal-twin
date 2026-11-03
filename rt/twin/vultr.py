"""Minimal Vultr API v2 client: only the calls the twin needs.

Standard library only. Every HTTP attempt writes one JSON timing line
(ts, method, path, status, ms, attempt) to the timing sink: the file in
RT_VULTR_TIMING_LOG if set, otherwise stderr. The API key never appears
in timing lines or error messages.

Retries: 429 is retried for every method (the request was rejected).
5xx and network errors are retried only for idempotent methods; a failed
POST may still have created something, so it is raised instead of repeated.
"""
from __future__ import annotations

import json
import os
import re
import sys
import time
import urllib.error
import urllib.parse
import urllib.request
from datetime import datetime, timezone
from typing import Any, Callable

DEFAULT_BASE_URL = "https://api.vultr.com/v2"
IDEMPOTENT = {"GET", "DELETE", "PUT", "HEAD"}
RETRY_5XX = {500, 502, 503, 504}
# Account-level refusals (money, credit, quota). These stop the run: a human decides.
ACCOUNT_WORDS = re.compile(r"balance|billing|payment|credit|insufficient|limit|suspend|verify your account", re.I)


class VultrError(Exception):
    def __init__(self, message: str, status: int | None = None, method: str = "", path: str = ""):
        super().__init__(message)
        self.status = status
        self.method = method
        self.path = path


class NotFound(VultrError):
    pass


class AccountBlocked(VultrError):
    """The API refused for an account reason (balance, credit, quota). Needs a human."""


def utc_now() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.%fZ")


def _default_timing() -> Callable[[str], None]:
    path = os.environ.get("RT_VULTR_TIMING_LOG")
    if path:
        def write_file(line: str) -> None:
            with open(path, "a", encoding="utf-8") as fh:
                fh.write(line + "\n")
        return write_file

    def write_stderr(line: str) -> None:
        print(line, file=sys.stderr, flush=True)
    return write_stderr


class Vultr:
    def __init__(self, api_key: str | None = None, base_url: str = DEFAULT_BASE_URL, *,
                 timeout_s: float = 30.0, max_attempts: int = 6, backoff_s: float = 1.0,
                 max_backoff_s: float = 30.0, sleep: Callable[[float], Any] = time.sleep,
                 timing: Callable[[str], None] | None = None):
        key = api_key or os.environ.get("VULTR_API_KEY", "")
        if not key:
            raise VultrError("VULTR_API_KEY is not set")
        self._key = key
        self.base_url = base_url.rstrip("/")
        self.timeout_s = timeout_s
        self.max_attempts = max(1, max_attempts)
        self.backoff_s = backoff_s
        self.max_backoff_s = max_backoff_s
        self.sleep = sleep
        self.timing = timing or _default_timing()

    def __repr__(self) -> str:  # keep the key out of any accidental repr
        return f"Vultr(base_url={self.base_url!r})"

    # -- transport ---------------------------------------------------------
    def request(self, method: str, path: str, body: dict | None = None,
                query: dict[str, Any] | None = None) -> tuple[int, dict]:
        method = method.upper()
        url = self.base_url + path
        if query:
            url += "?" + urllib.parse.urlencode({k: v for k, v in query.items() if v not in (None, "")})
        data = json.dumps(body).encode() if body is not None else None
        headers = {"Authorization": "Bearer " + self._key, "Accept": "application/json",
                   "User-Agent": "rehearsal-twin/0.1"}
        if data is not None:
            headers["Content-Type"] = "application/json"

        for attempt in range(1, self.max_attempts + 1):
            req = urllib.request.Request(url, data=data, method=method, headers=headers)
            t0 = time.monotonic()
            status: int | None = None
            retry_after: float | None = None
            try:
                with urllib.request.urlopen(req, timeout=self.timeout_s) as resp:
                    status = resp.status
                    text = resp.read().decode("utf-8", "replace")
                self._log(method, path, status, t0, attempt)
                return status, _parse(text)
            except urllib.error.HTTPError as e:
                status = e.code
                text = e.read().decode("utf-8", "replace")
                retry_after = _retry_after(e.headers.get("Retry-After") if e.headers else None)
                self._log(method, path, status, t0, attempt)
                payload = _parse(text)
                msg = str(payload.get("error") or text[:300] or e.reason)
                retryable = status == 429 or (status in RETRY_5XX and method in IDEMPOTENT)
                if not retryable or attempt == self.max_attempts:
                    raise _error_for(status, f"HTTP {status} {method} {path}: {msg}", method, path) from None
            except (urllib.error.URLError, TimeoutError, ConnectionError, OSError) as e:
                self._log(method, path, None, t0, attempt, error=type(e).__name__)
                if method not in IDEMPOTENT or attempt == self.max_attempts:
                    raise VultrError(f"{method} {path}: network error {type(e).__name__}", None, method, path) from None
            delay = min(self.max_backoff_s, self.backoff_s * 2 ** (attempt - 1))
            if retry_after is not None:
                delay = max(delay, min(retry_after, 60.0))
            self.sleep(delay)
        raise VultrError(f"{method} {path}: retries exhausted", status, method, path)  # pragma: no cover

    def _log(self, method: str, path: str, status: int | None, t0: float, attempt: int, error: str = "") -> None:
        row = {"ts": utc_now(), "api": "vultr", "method": method, "path": path, "status": status,
               "ms": round((time.monotonic() - t0) * 1000, 1), "attempt": attempt}
        if error:
            row["error"] = error
        try:
            self.timing(json.dumps(row))
        except Exception as e:  # a broken log sink must not break the call, but say so
            print(f"rt.twin.vultr: timing sink failed: {type(e).__name__}", file=sys.stderr)

    def _list(self, path: str, key: str, query: dict[str, Any] | None = None, per_page: int = 100) -> list[dict]:
        out: list[dict] = []
        q = dict(query or {}, per_page=per_page)
        while True:
            _, d = self.request("GET", path, query=q)
            out.extend(d.get(key, []))
            nxt = ((d.get("meta") or {}).get("links") or {}).get("next") or ""
            if not nxt:
                return out
            q["cursor"] = nxt

    # -- instances -----------------------------------------------------------
    def create_instance(self, body: dict) -> dict:
        return self.request("POST", "/instances", body)[1]["instance"]

    def get_instance(self, instance_id: str) -> dict:
        return self.request("GET", f"/instances/{_seg(instance_id)}")[1]["instance"]

    def list_instances(self, tag: str | None = None, per_page: int = 100) -> list[dict]:
        return self._list("/instances", "instances", {"tag": tag}, per_page)

    def delete_instance(self, instance_id: str) -> None:
        self.request("DELETE", f"/instances/{_seg(instance_id)}")

    def restore_instance(self, instance_id: str, snapshot_id: str) -> dict:
        return self.request("POST", f"/instances/{_seg(instance_id)}/restore", {"snapshot_id": snapshot_id})[1]

    def instance_vpcs(self, instance_id: str) -> list[dict]:
        return self._list(f"/instances/{_seg(instance_id)}/vpcs", "vpcs")

    # -- snapshots -----------------------------------------------------------
    def create_snapshot(self, instance_id: str, description: str = "") -> dict:
        return self.request("POST", "/snapshots", {"instance_id": instance_id, "description": description})[1]["snapshot"]

    def get_snapshot(self, snapshot_id: str) -> dict:
        return self.request("GET", f"/snapshots/{_seg(snapshot_id)}")[1]["snapshot"]

    def delete_snapshot(self, snapshot_id: str) -> None:
        self.request("DELETE", f"/snapshots/{_seg(snapshot_id)}")

    # -- vpcs, ssh keys ----------------------------------------------------
    def list_vpcs(self) -> list[dict]:
        return self._list("/vpcs", "vpcs")

    def create_vpc(self, region: str, description: str, v4_subnet: str, v4_subnet_mask: int) -> dict:
        body = {"region": region, "description": description, "v4_subnet": v4_subnet, "v4_subnet_mask": v4_subnet_mask}
        return self.request("POST", "/vpcs", body)[1]["vpc"]

    def list_ssh_keys(self) -> list[dict]:
        return self._list("/ssh-keys", "ssh_keys")


def _seg(value: str) -> str:
    return urllib.parse.quote(str(value), safe="")


def _parse(text: str) -> dict:
    if not text.strip():
        return {}
    try:
        v = json.loads(text)
    except json.JSONDecodeError:
        return {"raw": text[:500]}
    return v if isinstance(v, dict) else {"data": v}


def _retry_after(value: str | None) -> float | None:
    try:
        return float(value) if value else None
    except ValueError:
        return None


def _error_for(status: int, msg: str, method: str, path: str) -> VultrError:
    if status == 404:
        return NotFound(msg, status, method, path)
    if status == 402 or (400 <= status < 500 and status != 429 and ACCOUNT_WORDS.search(msg)):
        return AccountBlocked(msg, status, method, path)
    return VultrError(msg, status, method, path)
