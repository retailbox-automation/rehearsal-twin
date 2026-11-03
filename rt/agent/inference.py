"""Client for Vultr Serverless Inference, route /v1/chat/completions.

Standard library only. Guards enforced here, for every call:
- Model allowlist. A request for any other id fails before the network.
  Vultr routes an unknown or misspelled model name to another model without
  an error, so the `model` field of every response is checked too: a response
  from any model other than the one requested raises ModelSubstitutionError
  and its content is dropped.
- max_tokens is always sent and must be below the model's context window.
- No secret values in a request: every string in the body is checked against
  secret-like environment values, explicitly registered secrets and canary
  tokens (rt-canary-...) before anything is sent. Callers mask text with
  `client.masker` first; the check is the backstop.
- Retries follow the Vultr Inference docs (concepts/errors, concepts/limits):
  429 after Retry-After, 502/503/504 and network errors with a growing wait,
  500 once. Other statuses fail at once.

Each chat() call appends one record to `llm_calls`: model ids, token counts,
wall time, attempts, outcome. Never prompt or answer text.
"""
from __future__ import annotations

import json
import os
import re
import sys
import time
import urllib.error
import urllib.request
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Any, Callable, Iterator, Mapping

DEFAULT_BASE_URL = "https://api.vultrinference.com/v1"

# Exact ids and context windows (tokens), from GET /v1/models on 2026-11-03.
ALLOWED_MODELS: dict[str, int] = {
    "muse-glimmer-30b": 131072,
    "nemotron-3-nano-omni-30b-a3b-reasoning": 262144,
    "nemotron-3.5-content-safety": 131072,
    "raon-1-mini-preview": 262144,
}

RETRY_BACKOFF = {502, 503, 504}
RESERVED_KEYS = {"model", "messages", "max_tokens", "max_completion_tokens", "stream", "n"}

SECRET_NAME = re.compile(r"KEY|TOKEN|SECRET|PASS|PWD|CREDENTIAL|AUTH|PRIVATE|DSN|DATABASE_URL", re.I)
MIN_SECRET_LEN = 8
CANARY_PREFIX = "rt-canary-"
CANARY = re.compile(r"rt-canary-[^\s\"'`<>,;()\[\]{}]*", re.I)
PEM_BLOCK = re.compile(r"-----BEGIN [A-Z0-9 ]*PRIVATE KEY-----.*?(?:-----END [A-Z0-9 ]*PRIVATE KEY-----|\Z)", re.S)
PEM_MARK = re.compile(r"-----BEGIN [A-Z0-9 ]*PRIVATE KEY-----")


class InferenceError(Exception):
    def __init__(self, message: str, status: int | None = None):
        super().__init__(message)
        self.status = status


class ModelNotAllowed(InferenceError):
    """The requested model id is not in the allowlist. Raised before any network call."""


class ModelSubstitutionError(InferenceError):
    """The response came from a model other than the one requested. The response is dropped."""

    def __init__(self, requested: str, returned: Any):
        shown = returned[:100] if isinstance(returned, str) else returned
        super().__init__(f"asked for {requested!r}, response came from {shown!r}; response dropped")
        self.requested = requested
        self.returned = shown


class SecretInPromptError(InferenceError):
    """A request body still held a secret value or canary token. Raised before any network call."""

    def __init__(self, names: list[str]):
        super().__init__("request refused, secret values present: " + ", ".join(names))
        self.names = names


def utc_now() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.%fZ")


def check_model(model: str) -> int:
    """Return the context window of an allowed model id, or raise ModelNotAllowed."""
    if not isinstance(model, str) or model not in ALLOWED_MODELS:
        raise ModelNotAllowed(f"model {model!r} is not in the allowlist {sorted(ALLOWED_MODELS)}")
    return ALLOWED_MODELS[model]


class Masker:
    """Replaces secret values with <secret:NAME> placeholders before text reaches a model.

    Sources: environment variables whose name looks secret (KEY, TOKEN, PASSWORD, ...)
    and whose value has at least 8 characters, plus secrets passed in by name
    (for example {"prod.db_password": value}). Canary tokens become
    <secret:canary-N>, numbered per distinct token; private key blocks become
    <secret:pem-private-key>.
    """

    def __init__(self, secrets: Mapping[str, str] | None = None, env: Mapping[str, str] | None = None):
        env = os.environ if env is None else env
        by_value: dict[str, str] = {}
        for name, value in env.items():
            if value and len(value) >= MIN_SECRET_LEN and SECRET_NAME.search(name):
                by_value[value] = f"env.{name}"
        for name, value in (secrets or {}).items():
            if not value or len(value) < MIN_SECRET_LEN:
                raise ValueError(f"secret {name!r} is shorter than {MIN_SECRET_LEN} characters; it cannot be masked reliably")
            by_value[value] = name
        self._values = sorted(by_value.items(), key=lambda kv: -len(kv[0]))
        self._canaries: dict[str, int] = {}

    def mask(self, text: str) -> str:
        for value, name in self._values:
            if value in text:
                text = text.replace(value, f"<secret:{name}>")
        text = PEM_BLOCK.sub("<secret:pem-private-key>", text)
        return CANARY.sub(self._canary_slot, text)

    def mask_obj(self, obj: Any) -> Any:
        if isinstance(obj, str):
            return self.mask(obj)
        if isinstance(obj, dict):
            return {self.mask(k) if isinstance(k, str) else k: self.mask_obj(v) for k, v in obj.items()}
        if isinstance(obj, (list, tuple)):
            return [self.mask_obj(v) for v in obj]
        return obj

    def leaks(self, text: str) -> list[str]:
        """Names (never values) of the secrets present in text."""
        found = [name for value, name in self._values if value in text]
        if CANARY_PREFIX in text.lower():
            found.append("canary")
        if PEM_MARK.search(text):
            found.append("pem-private-key")
        return found

    def _canary_slot(self, m: re.Match) -> str:
        n = self._canaries.setdefault(m.group(0), len(self._canaries) + 1)
        return f"<secret:canary-{n}>"


@dataclass(frozen=True)
class ChatResult:
    content: str
    model: str
    finish_reason: str
    tokens_in: int | None
    tokens_out: int | None


class InferenceClient:
    def __init__(self, api_key: str | None = None, base_url: str = DEFAULT_BASE_URL, *,
                 timeout_s: float = 600.0, max_attempts: int = 5, backoff_s: float = 1.0,
                 max_backoff_s: float = 30.0, max_retry_after_s: float = 60.0,
                 sleep: Callable[[float], Any] = time.sleep, masker: Masker | None = None,
                 on_call: Callable[[dict], None] | None = None):
        key = api_key or os.environ.get("VULTR_INFERENCE_API_KEY", "")
        if not key:
            raise InferenceError("VULTR_INFERENCE_API_KEY is not set")
        self._key = key
        self.base_url = base_url.rstrip("/")
        self.timeout_s = timeout_s
        self.max_attempts = max(1, max_attempts)
        self.backoff_s = backoff_s
        self.max_backoff_s = max_backoff_s
        self.max_retry_after_s = max_retry_after_s
        self.sleep = sleep
        self.masker = masker or Masker()
        self.on_call = on_call
        self.llm_calls: list[dict] = []

    def __repr__(self) -> str:  # keep the key out of any accidental repr
        return f"InferenceClient(base_url={self.base_url!r})"

    def chat(self, model: str, messages: list[dict], *, max_tokens: int,
             response_format: dict | None = None, temperature: float | None = None,
             top_p: float | None = None, extra: dict | None = None, purpose: str = "") -> ChatResult:
        window = check_model(model)
        if isinstance(max_tokens, bool) or not isinstance(max_tokens, int) or not 0 < max_tokens < window:
            raise ValueError(f"max_tokens must be an int in 1..{window - 1} for {model}, got {max_tokens!r}")
        body: dict[str, Any] = {"model": model, "messages": messages, "max_tokens": max_tokens}
        if response_format is not None:
            body["response_format"] = response_format
        if temperature is not None:
            body["temperature"] = temperature
        if top_p is not None:
            body["top_p"] = top_p
        if extra:
            clash = RESERVED_KEYS & set(extra)
            if clash:
                raise ValueError(f"extra may not set {sorted(clash)}")
            body.update(extra)

        rec: dict[str, Any] = {"ts": utc_now(), "purpose": purpose, "model_requested": model,
                               "model_returned": None, "tokens_in": None, "tokens_out": None,
                               "ms": 0.0, "attempts": 0, "outcome": ""}
        t0 = time.monotonic()
        try:
            leaked = sorted({n for s in _strings(body) for n in self.masker.leaks(s)})
            if leaked:
                rec["outcome"] = "refused_secret"
                raise SecretInPromptError(leaked)
            data = self._post(body, rec)
            returned = data.get("model")
            rec["model_returned"] = returned[:100] if isinstance(returned, str) else None
            usage = data.get("usage") if isinstance(data.get("usage"), dict) else {}
            rec["tokens_in"] = _int_or_none(usage.get("prompt_tokens"))
            rec["tokens_out"] = _int_or_none(usage.get("completion_tokens"))
            if returned != model:
                rec["outcome"] = "model_substitution"
                raise ModelSubstitutionError(model, returned)
            content, finish = _first_choice(data)
            rec["outcome"] = "ok"
            return ChatResult(content, returned, finish, rec["tokens_in"], rec["tokens_out"])
        except InferenceError:
            rec["outcome"] = rec["outcome"] or "bad_response"
            raise
        finally:
            rec["ms"] = round((time.monotonic() - t0) * 1000, 1)
            self._record(rec)

    # -- transport ---------------------------------------------------------
    def _post(self, body: dict, rec: dict) -> dict:
        data = json.dumps(body).encode()
        headers = {"Authorization": "Bearer " + self._key, "Content-Type": "application/json",
                   "Accept": "application/json", "User-Agent": "rehearsal-twin/0.1"}
        url = self.base_url + "/chat/completions"
        for attempt in range(1, self.max_attempts + 1):
            rec["attempts"] = attempt
            retry_after: float | None = None
            req = urllib.request.Request(url, data=data, method="POST", headers=headers)
            try:
                with urllib.request.urlopen(req, timeout=self.timeout_s) as resp:
                    text = resp.read().decode("utf-8", "replace")
                    status = resp.status
                try:
                    payload = json.loads(text)
                except json.JSONDecodeError:
                    raise InferenceError("response body is not JSON", status) from None
                if not isinstance(payload, dict):
                    raise InferenceError("response body is not a JSON object", status)
                return payload
            except urllib.error.HTTPError as e:
                status = e.code
                text = e.read().decode("utf-8", "replace")
                retry_after = _retry_after(e.headers.get("Retry-After") if e.headers else None)
                retryable = status == 429 or status in RETRY_BACKOFF or (status == 500 and attempt == 1)
                if not retryable or attempt == self.max_attempts:
                    rec["outcome"] = f"http_{status}"
                    raise InferenceError(f"HTTP {status} from chat/completions: {_error_message(text)}", status) from None
            except (urllib.error.URLError, TimeoutError, ConnectionError, OSError) as e:
                if attempt == self.max_attempts:
                    rec["outcome"] = "network"
                    raise InferenceError(f"chat/completions: network error {type(e).__name__}") from None
            delay = min(self.max_backoff_s, self.backoff_s * 2 ** (attempt - 1))
            if retry_after is not None:
                delay = max(delay, min(retry_after, self.max_retry_after_s))
            self.sleep(delay)
        raise InferenceError("chat/completions: retries exhausted")  # pragma: no cover

    def _record(self, rec: dict) -> None:
        self.llm_calls.append(dict(rec))
        if self.on_call is None:
            return
        try:
            self.on_call(dict(rec))
        except Exception as e:  # a broken feed must not break the call, but say so
            print(f"rt.agent.inference: on_call sink failed: {type(e).__name__}", file=sys.stderr)


def _strings(obj: Any) -> Iterator[str]:
    if isinstance(obj, str):
        yield obj
    elif isinstance(obj, dict):
        for k, v in obj.items():
            if isinstance(k, str):
                yield k
            yield from _strings(v)
    elif isinstance(obj, (list, tuple)):
        for v in obj:
            yield from _strings(v)


def _first_choice(data: dict) -> tuple[str, str]:
    choices = data.get("choices")
    if not isinstance(choices, list) or not choices or not isinstance(choices[0], dict):
        raise InferenceError("response has no choices")
    msg = choices[0].get("message") if isinstance(choices[0].get("message"), dict) else {}
    content = msg.get("content")
    if not isinstance(content, str):
        raise InferenceError("response has no text content")
    finish = choices[0].get("finish_reason")
    return content, finish if isinstance(finish, str) else ""


def _int_or_none(v: Any) -> int | None:
    return v if isinstance(v, int) and not isinstance(v, bool) else None


def _retry_after(value: str | None) -> float | None:
    try:
        return float(value) if value else None
    except ValueError:
        return None


def _error_message(text: str) -> str:
    try:
        payload = json.loads(text)
    except json.JSONDecodeError:
        return text[:300]
    err = payload.get("error") if isinstance(payload, dict) else None
    if isinstance(err, dict):
        return str(err.get("message") or err.get("type") or "")[:300]
    return str(err or text)[:300]
