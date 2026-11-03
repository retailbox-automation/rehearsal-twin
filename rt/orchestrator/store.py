"""Rehearsal records as files under RT_DATA_DIR (no database).

    <data_dir>/rehearsals/<id>/record.json     the record (rewritten atomically)
    <data_dir>/rehearsals/<id>/events.jsonl    append-only event feed (SSE replays and tails it)
    <data_dir>/rehearsals/<id>/<name>          scripts, scope, ledgers, compare, receipt

Ids are 12 lowercase hex characters; anything else is refused before touching the disk.
"""
from __future__ import annotations

import json
import os
import re
import secrets
import threading
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

ID_RE = re.compile(r"^[0-9a-f]{12}$")
NAME_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,80}$")


class UnknownRehearsal(KeyError):
    pass


def utc_now() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.%fZ")


def new_id() -> str:
    return secrets.token_hex(6)


def _atomic_write(path: Path, data: bytes, mode: int = 0o600) -> None:
    tmp = path.with_name(f".{path.name}.{secrets.token_hex(4)}.tmp")
    fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_EXCL, mode)
    try:
        with os.fdopen(fd, "wb") as f:
            f.write(data)
            f.flush()
            os.fsync(f.fileno())
        os.replace(tmp, path)
    except BaseException:
        tmp.unlink(missing_ok=True)
        raise


class Store:
    def __init__(self, data_dir: Path | str):
        self.root = Path(data_dir) / "rehearsals"
        self.root.mkdir(parents=True, exist_ok=True)
        os.chmod(self.root.parent, 0o700)
        self._lock = threading.RLock()
        self._seq: dict[str, int] = {}

    # -- paths ---------------------------------------------------------------
    def dir(self, rid: str) -> Path:
        if not isinstance(rid, str) or not ID_RE.match(rid):
            raise UnknownRehearsal(rid)
        return self.root / rid

    def path(self, rid: str, name: str) -> Path:
        if not NAME_RE.match(name):
            raise ValueError(f"bad file name {name!r}")
        return self.dir(rid) / name

    def exists(self, rid: str) -> bool:
        try:
            return (self.dir(rid) / "record.json").is_file()
        except UnknownRehearsal:
            return False

    # -- records -------------------------------------------------------------
    def create(self, record: dict) -> dict:
        with self._lock:
            d = self.dir(record["id"])
            d.mkdir(mode=0o700)
            (d / "events.jsonl").touch(mode=0o600)
            self.save(record)
        return record

    def save(self, record: dict) -> None:
        with self._lock:
            record["updated_at"] = utc_now()
            _atomic_write(self.dir(record["id"]) / "record.json",
                          json.dumps(record, sort_keys=True, indent=1).encode())

    def load(self, rid: str) -> dict:
        p = self.dir(rid) / "record.json"
        try:
            return json.loads(p.read_text(encoding="utf-8"))
        except FileNotFoundError:
            raise UnknownRehearsal(rid) from None

    def ids(self) -> list[str]:
        """Record ids, oldest first."""
        out = [d.name for d in self.root.iterdir() if ID_RE.match(d.name) and (d / "record.json").is_file()]
        return sorted(out, key=lambda r: (self.load(r).get("created_at", ""), r))

    def latest(self) -> str | None:
        ids = self.ids()
        return ids[-1] if ids else None

    # -- files ---------------------------------------------------------------
    def write_file(self, rid: str, name: str, data: bytes | str, mode: int = 0o600) -> Path:
        p = self.path(rid, name)
        _atomic_write(p, data.encode() if isinstance(data, str) else data, mode)
        return p

    def write_json(self, rid: str, name: str, obj: Any) -> Path:
        return self.write_file(rid, name, json.dumps(obj, sort_keys=True, indent=1, ensure_ascii=False))

    def read_file(self, rid: str, name: str) -> bytes:
        try:
            return self.path(rid, name).read_bytes()
        except FileNotFoundError:
            raise UnknownRehearsal(f"{rid}/{name}") from None

    def read_json(self, rid: str, name: str) -> Any:
        return json.loads(self.read_file(rid, name))

    def has_file(self, rid: str, name: str) -> bool:
        return self.path(rid, name).is_file()

    # -- events --------------------------------------------------------------
    def append_event(self, rid: str, type_: str, data: dict) -> dict:
        with self._lock:
            p = self.dir(rid) / "events.jsonl"
            seq = self._next_seq(rid, p)
            ev = {"seq": seq, "ts": utc_now(), "type": type_, "data": data}
            with open(p, "a", encoding="utf-8") as f:
                f.write(json.dumps(ev, sort_keys=True, ensure_ascii=False) + "\n")
            return ev

    def _next_seq(self, rid: str, p: Path) -> int:
        cache = self._seq
        if rid not in cache:
            n = 0
            if p.exists():
                with open(p, encoding="utf-8") as f:
                    n = sum(1 for line in f if line.strip())
            cache[rid] = n
        cache[rid] += 1
        return cache[rid]

    def read_events(self, rid: str, offset: int = 0) -> tuple[list[dict], int]:
        """Complete event lines from a byte offset; returns (events, new offset)."""
        p = self.dir(rid) / "events.jsonl"
        try:
            with open(p, "rb") as f:
                f.seek(offset)
                chunk = f.read()
        except FileNotFoundError:
            raise UnknownRehearsal(rid) from None
        end = chunk.rfind(b"\n")
        if end < 0:
            return [], offset
        events = [json.loads(line) for line in chunk[:end].split(b"\n") if line.strip()]
        return events, offset + end + 1

    def events(self, rid: str) -> list[dict]:
        return self.read_events(rid, 0)[0]
