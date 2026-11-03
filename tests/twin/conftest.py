from __future__ import annotations

import subprocess

import pytest

from tests.twin.fake_vultr import FakeVultr

FAKE_KEY = "unit-test-placeholder"


class FakeRunner:
    """Stands in for subprocess.run when the code shells out to ssh."""

    def __init__(self, results=None):
        self.calls: list[dict] = []
        self.results = list(results or [])

    def __call__(self, argv, input=None, stdin=None, capture_output=False, timeout=None, check=False):
        self.calls.append({"argv": list(argv), "input": input, "timeout": timeout})
        if self.results:
            r = self.results.pop(0)
            if isinstance(r, BaseException):
                raise r
            rc, out, err = r
        else:
            rc, out, err = 0, b"ok\n", b""
        return subprocess.CompletedProcess(argv, rc, out, err)


@pytest.fixture
def fake():
    f = FakeVultr().start()
    yield f
    f.stop()


@pytest.fixture
def timing_lines():
    return []


@pytest.fixture
def sleeps():
    return []


@pytest.fixture
def client(fake, timing_lines, sleeps):
    from rt.twin.vultr import Vultr

    return Vultr(api_key=FAKE_KEY, base_url=fake.url, sleep=sleeps.append, timing=timing_lines.append)


@pytest.fixture
def runner():
    return FakeRunner()


@pytest.fixture
def ssh(runner, tmp_path):
    from rt.twin.lifecycle import SSH

    key = tmp_path / "key"
    key.write_text("placeholder")
    return SSH(key_file=str(key), jump="198.51.100.10", runner=runner, state_dir=str(tmp_path / "kh"))
