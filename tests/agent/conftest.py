from __future__ import annotations

import pytest

from tests.agent.fake_inference import FakeInference

FAKE_KEY = "unit-test-placeholder"


@pytest.fixture
def fake():
    f = FakeInference().start()
    yield f
    f.stop()


@pytest.fixture
def sleeps():
    return []


@pytest.fixture
def client(fake, sleeps):
    from rt.agent.inference import InferenceClient

    return InferenceClient(api_key=FAKE_KEY, base_url=fake.url, sleep=sleeps.append)
