"""Fake machines behind rt.twin.lifecycle.SSH, and a model router for the fake Inference server.

FakeFleet replaces subprocess.run inside SSH. It finds the machine by the per-instance
known_hosts file name SSH passes, so every twin gets its own fresh FakeTarget (its own disk),
and production is one FakeTarget whose state the test can change.
A FakeTarget answers what rt.orchestrator.remote sends: put, rtrace before/run/after/diff,
rm of the run directory, cat /proc/uptime. `rtrace diff` returns the canned facts for the
script that was put there, finalized with the scope.json that was put there.
"""
from __future__ import annotations

import hashlib
import json
import posixpath
import re
import shlex
import subprocess
from typing import Callable

from rt.ledger import finalize
from rt.orchestrator.remote import RT_BIN

KNOWN_HOSTS = re.compile(r"known_hosts-([A-Za-z0-9_.-]+)")


def sha(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


class FakeTarget:
    def __init__(self, name: str, state: dict, ledgers: dict[str, dict]):
        self.name = name
        self.state = state
        self.ledgers = ledgers
        self.files: dict[str, bytes] = {}
        self.phases: list[str] = []
        self.fail: dict[str, object] = {}
        self.tamper: Callable[[dict], dict] | None = None

    def _fail(self, phase: str):
        what = self.fail.get(phase)
        if what is None:
            return None
        if isinstance(what, BaseException):
            raise what
        return what

    def handle(self, remote: list[str], data: bytes | None) -> tuple[int, str, str]:
        if remote == ["true"]:
            return 0, "", ""
        if remote == ["cat", "/proc/uptime"]:
            return 0, "3564720.50 7000000.00\n", ""
        if remote[:2] == ["sh", "-c"]:
            body, args = remote[2], remote[4:]
            if 'cat > "$2"' in body:
                self.files[args[1]] = data or b""
                return 0, "", ""
            for phase in ("before", "run", "after"):
                if f"{RT_BIN} {phase} " in body:
                    self.phases.append(phase)
                    failed = self._fail(phase)
                    if failed:
                        return failed
                    if phase == "before":
                        return 0, json.dumps(self.state), ""
                    return 0, "", ""
            if body.startswith("rm -rf --"):
                w = args[0].rstrip("/") + "/"
                self.files = {p: v for p, v in self.files.items() if not p.startswith(w)}
                self.phases.append("rm")
                return 0, "", ""
        if remote[:2] == [RT_BIN, "diff"]:
            self.phases.append("diff")
            failed = self._fail("diff")
            if failed:
                return failed
            w = posixpath.dirname(remote[2])
            script = self.files.get(f"{w}/script.sh")
            facts = self.ledgers.get(sha(script or b""))
            if facts is None:
                return 1, "", "no canned ledger for this script"
            ledger = finalize(facts, json.loads(self.files[f"{w}/scope.json"]))
            if self.tamper:
                ledger = self.tamper(ledger)
            return 0, json.dumps(ledger), ""
        return 127, "", f"unknown command {remote[:3]}"


class FakeFleet:
    def __init__(self, twin_state: Callable[[], dict], twin_ledgers: dict[str, dict]):
        self.twin_state = twin_state
        self.twin_ledgers = twin_ledgers
        self.targets: dict[str, FakeTarget] = {}
        self.twin_setup: Callable[[FakeTarget], None] | None = None
        self.calls: list[tuple[str, list[str]]] = []

    def add(self, name: str, state: dict, ledgers: dict[str, dict]) -> FakeTarget:
        self.targets[name] = FakeTarget(name, state, ledgers)
        return self.targets[name]

    def target(self, name: str) -> FakeTarget:
        if name not in self.targets:
            t = self.add(name, self.twin_state(), self.twin_ledgers)
            if self.twin_setup:
                self.twin_setup(t)
        return self.targets[name]

    def __call__(self, argv, input=None, stdin=None, capture_output=False, timeout=None, check=False):
        m = KNOWN_HOSTS.search(" ".join(argv))
        assert m, "ssh call without a per-machine known_hosts file"
        remote = shlex.split(argv[-1])
        self.calls.append((m.group(1), remote))
        rc, out, err = self.target(m.group(1)).handle(remote, input)
        return subprocess.CompletedProcess(argv, rc, out.encode(), err.encode())


class ModelRouter(list):
    """Stand-in for FakeInference.queue: picks the reply by the request's model and schema name."""

    def __init__(self, fake, route: Callable[[dict], dict]):
        super().__init__()
        self.fake = fake
        self.route = route

    def __bool__(self) -> bool:
        return True

    def pop(self, index: int = -1):
        body = self.fake.requests[-1]["body"]
        out = self.route(body)
        return {"kind": "reply", "model": None, "finish_reason": "stop", **out}


def reply_safe_unless(words: tuple[str, ...] = ()) -> Callable[[dict], str]:
    def label(body: dict) -> str:
        text = body["messages"][-1]["content"].lower()
        if any(w in text for w in words):
            return "User Safety: unsafe\nSafety Categories: Manipulation"
        return "User Safety: safe"
    return label
