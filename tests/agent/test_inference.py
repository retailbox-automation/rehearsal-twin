from __future__ import annotations

import json
import secrets

import pytest

from rt.agent.inference import (ALLOWED_MODELS, InferenceClient, InferenceError, Masker,
                                ModelNotAllowed, ModelSubstitutionError, SecretInPromptError)
from tests.agent.conftest import FAKE_KEY

MSG = [{"role": "user", "content": "say ok"}]
RECORD_KEYS = {"ts", "purpose", "model_requested", "model_returned", "tokens_in", "tokens_out",
               "ms", "attempts", "outcome"}


def test_allowlist_is_exact_and_has_no_fallback_family():
    assert set(ALLOWED_MODELS) == {"muse-glimmer-30b", "nemotron-3-nano-omni-30b-a3b-reasoning",
                                   "nemotron-3.5-content-safety", "raon-1-mini-preview"}
    banned = ("qwen", "deepseek", "glm", "mimo", "minimax", "clef", "pplx", "d3")
    assert not [m for m in ALLOWED_MODELS for b in banned if b in m.lower()]


def test_happy_path_sends_explicit_max_tokens_and_records_call(fake, client):
    res = client.chat("muse-glimmer-30b", MSG, max_tokens=256, purpose="probe")
    assert res.content == "ok" and res.model == "muse-glimmer-30b"
    (req,) = fake.requests
    assert req["path"] == "/v1/chat/completions"
    assert req["auth"] == "Bearer " + FAKE_KEY
    assert req["body"]["model"] == "muse-glimmer-30b"
    assert req["body"]["max_tokens"] == 256
    (rec,) = client.llm_calls
    assert set(rec) == RECORD_KEYS
    assert rec["outcome"] == "ok" and rec["attempts"] == 1
    assert (rec["model_requested"], rec["model_returned"]) == ("muse-glimmer-30b", "muse-glimmer-30b")
    assert (rec["tokens_in"], rec["tokens_out"]) == (123, 45)


def test_model_substitution_rejected(fake, client):
    fake.reply("I am a different model", model="deepseek-v4.1-flash-1017")
    with pytest.raises(ModelSubstitutionError) as e:
        client.chat("muse-glimmer-30b", MSG, max_tokens=256)
    assert e.value.requested == "muse-glimmer-30b"
    assert e.value.returned == "deepseek-v4.1-flash-1017"
    assert "different model" not in str(e.value)  # the answer is dropped, not carried in the error
    assert len(fake.requests) == 1  # not retried either
    (rec,) = client.llm_calls
    assert rec["outcome"] == "model_substitution"
    assert rec["model_returned"] == "deepseek-v4.1-flash-1017"
    assert "different model" not in json.dumps(rec)


def test_substitution_to_another_allowed_model_rejected(fake, client):
    fake.reply("ok", model="raon-1-mini-preview")
    with pytest.raises(ModelSubstitutionError):
        client.chat("muse-glimmer-30b", MSG, max_tokens=256)


def test_response_without_model_field_rejected(fake, client):
    fake.reply("ok", omit_model=True)
    with pytest.raises(ModelSubstitutionError):
        client.chat("muse-glimmer-30b", MSG, max_tokens=256)


@pytest.mark.parametrize("model", ["muse-glimmer-30B", "muse-glimmer", "deepseek-v4.1-flash-1017",
                                   "clef", "qwen3.8-27b", "", "nemotron-3.5-content-safety "])
def test_unknown_model_rejected_before_network(fake, client, model):
    with pytest.raises(ModelNotAllowed):
        client.chat(model, MSG, max_tokens=256)
    assert fake.requests == []


@pytest.mark.parametrize("max_tokens", [0, -1, 131072, 200000, 1.5, True, None])
def test_max_tokens_must_be_explicit_and_below_window(fake, client, max_tokens):
    with pytest.raises(ValueError):
        client.chat("muse-glimmer-30b", MSG, max_tokens=max_tokens)
    assert fake.requests == []


def test_max_tokens_has_no_default(client):
    with pytest.raises(TypeError):
        client.chat("muse-glimmer-30b", MSG)  # type: ignore[call-arg]


def test_retry_on_429(fake, client, sleeps):
    fake.fail(429, {"Retry-After": "2"}, "Rate limit exceeded. Please retry later.")
    fake.fail(429, {}, "Rate limit exceeded. Please retry later.")
    res = client.chat("muse-glimmer-30b", MSG, max_tokens=64)
    assert res.content == "ok"
    assert len(fake.requests) == 3
    assert len(sleeps) == 2 and sleeps[0] >= 2  # Retry-After honoured
    assert client.llm_calls[-1]["attempts"] == 3
    assert client.llm_calls[-1]["outcome"] == "ok"


def test_retry_on_429_gives_up(fake, sleeps):
    c = InferenceClient(api_key=FAKE_KEY, base_url=fake.url, sleep=sleeps.append, max_attempts=3)
    for _ in range(3):
        fake.fail(429, {"Retry-After": "5"}, "Rate limit exceeded. Please retry later.")
    with pytest.raises(InferenceError) as e:
        c.chat("muse-glimmer-30b", MSG, max_tokens=64)
    assert e.value.status == 429
    assert len(fake.requests) == 3
    assert c.llm_calls[-1]["outcome"] == "http_429"


def test_retry_after_is_capped(fake, client, sleeps):
    fake.fail(429, {"Retry-After": "3600"}, "slow down")
    client.chat("muse-glimmer-30b", MSG, max_tokens=64)
    assert sleeps == [60.0]


def test_503_retried_400_not(fake, client):
    fake.fail(503, {}, "busy")
    assert client.chat("muse-glimmer-30b", MSG, max_tokens=64).content == "ok"
    assert len(fake.requests) == 2
    fake.fail(400, {}, "Input for property `seed` must be a valid integer value")
    with pytest.raises(InferenceError) as e:
        client.chat("muse-glimmer-30b", MSG, max_tokens=64)
    assert e.value.status == 400 and "seed" in str(e.value)
    assert len(fake.requests) == 3


def test_500_retried_once(fake, client):
    fake.fail(500, {}, "oops")
    fake.fail(500, {}, "oops")
    with pytest.raises(InferenceError) as e:
        client.chat("muse-glimmer-30b", MSG, max_tokens=64)
    assert e.value.status == 500
    assert len(fake.requests) == 2


def test_extra_cannot_override_guarded_fields(fake, client):
    for key in ("model", "max_tokens", "max_completion_tokens", "messages"):
        with pytest.raises(ValueError):
            client.chat("muse-glimmer-30b", MSG, max_tokens=64, extra={key: "x"})
    assert fake.requests == []


def test_secret_in_request_refused_before_network(fake, sleeps, monkeypatch):
    value = secrets.token_hex(16)
    monkeypatch.setenv("RT_UNIT_DB_PASSWORD", value)
    c = InferenceClient(api_key=FAKE_KEY, base_url=fake.url, sleep=sleeps.append)
    for text in (f"connect with {value}", "token rt-canary-" + secrets.token_hex(6)):
        with pytest.raises(SecretInPromptError) as e:
            c.chat("muse-glimmer-30b", [{"role": "user", "content": text}], max_tokens=64)
        assert value not in str(e.value)
    assert fake.requests == []
    assert [r["outcome"] for r in c.llm_calls] == ["refused_secret", "refused_secret"]


def test_masker_replaces_values_and_canaries():
    value = secrets.token_hex(12)
    other = secrets.token_hex(12)
    m = Masker(secrets={"prod.db_password": other}, env={"RT_API_TOKEN": value, "HOME": "/home/someone-long"})
    c1, c2 = "rt-canary-" + secrets.token_hex(4), "rt-canary-" + secrets.token_hex(4)
    out = m.mask(f"a={value} b={other} c={c1} d={c2} e={c1} home=/home/someone-long")
    assert value not in out and other not in out and "rt-canary-" not in out
    assert "<secret:env.RT_API_TOKEN>" in out and "<secret:prod.db_password>" in out
    assert out.count("<secret:canary-1>") == 2 and "<secret:canary-2>" in out
    assert "/home/someone-long" in out  # only secret-like names are masked
    assert m.leaks(out) == []


def test_masker_refuses_short_explicit_secret():
    with pytest.raises(ValueError):
        Masker(secrets={"pin": "1234"}, env={})


def test_key_not_in_repr_or_errors(fake, sleeps):
    c = InferenceClient(api_key=FAKE_KEY, base_url=fake.url, sleep=sleeps.append, max_attempts=1)
    fake.fail(401, {}, "The API key is missing, unknown or not active.")
    with pytest.raises(InferenceError) as e:
        c.chat("muse-glimmer-30b", MSG, max_tokens=64)
    assert FAKE_KEY not in str(e.value) and FAKE_KEY not in repr(c)
    assert FAKE_KEY not in json.dumps(c.llm_calls)


def test_missing_key_is_an_error(monkeypatch):
    monkeypatch.delenv("VULTR_INFERENCE_API_KEY", raising=False)
    with pytest.raises(InferenceError):
        InferenceClient()


def test_on_call_sink_gets_records_without_content(fake, sleeps):
    seen = []
    c = InferenceClient(api_key=FAKE_KEY, base_url=fake.url, sleep=sleeps.append, on_call=seen.append)
    fake.reply("the answer text")
    c.chat("nemotron-3-nano-omni-30b-a3b-reasoning", [{"role": "user", "content": "the prompt text"}], max_tokens=64)
    (rec,) = seen
    assert set(rec) == RECORD_KEYS
    dumped = json.dumps(rec)
    assert "answer text" not in dumped and "prompt text" not in dumped
