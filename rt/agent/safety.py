"""Input filter on nemotron-3.5-content-safety: goal text and data fragments -> {unsafe, categories, excerpt}.

Prompt format, from the model card https://huggingface.co/nvidia/Nemotron-3.5-Content-Safety
(README sections "Output" and "Use it with vLLM", and chat_template.jinja; revision 35645ed, read 2026-11-03):
- The text to classify is the single user message. The served chat template wraps it in the
  classifier instructions itself and drops any system message, so none is sent.
- chat_template_kwargs: request_categories="/categories" asks for the violated categories,
  enable_thinking=False skips the reasoning trace, custom_policy=<text> replaces the built-in
  taxonomy (Aegis 2.0, S1..S24) with our own policy.
- Output lines: "User Safety: safe|unsafe", optional "Response Safety: ...", optional
  "Safety Categories: a, b". In thinking mode a <think>...</think> block comes first.
The Vultr Inference docs (api.vultrinference.com/docs, 2026-11-03) do not mention
chat_template_kwargs; whether the gateway forwards them is checked on the first live call
(template_kwargs=False turns them off). Without them the model uses its built-in taxonomy and
lists no categories, and data verdicts carry policy_applied=False.

Goal text is checked against the built-in taxonomy. Data fragments from the ledger are checked
against prompts/safety_policy.md (instructions to an agent or reviewer hidden in data). The flag
is informational: the in/out-of-scope verdict comes from rt.ledger and this module never changes it.
Every text is masked (client.masker) before it is sent.
"""
from __future__ import annotations

import re
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Iterable, Iterator

from rt.agent.inference import InferenceClient

MODEL = "nemotron-3.5-content-safety"
MAX_TOKENS = 128
MAX_FRAGMENT_CHARS = 4000
MIN_LEAF_CHARS = 8
EXCERPT_CHARS = 240
POLICY_FILE = Path(__file__).with_name("prompts") / "safety_policy.md"

_THINK = re.compile(r"<think>.*?</think>", re.S | re.I)
_USER_SAFETY = re.compile(r"User Safety:\s*(unsafe|safe)\b", re.I)
_CATEGORIES = re.compile(r"Safety Categories:\s*(.*)", re.I)


class SafetyParseError(Exception):
    """The filter answered without a 'User Safety' label. Treat as a failed check, not as safe."""


@dataclass(frozen=True)
class SafetyVerdict:
    unsafe: bool
    categories: tuple[str, ...]
    excerpt: str
    source: str  # "goal" or "data"
    policy_applied: bool

    def as_dict(self) -> dict:
        return {"unsafe": self.unsafe, "categories": list(self.categories), "excerpt": self.excerpt,
                "source": self.source, "policy_applied": self.policy_applied}


def parse_output(text: str) -> tuple[bool, list[str]]:
    body = _THINK.sub("", text)
    m = _USER_SAFETY.search(body)
    if not m:
        raise SafetyParseError("filter output has no 'User Safety' label")
    cats: list[str] = []
    c = _CATEGORIES.search(body)
    if c:
        cats = [x.strip() for x in c.group(1).split(",") if x.strip() and x.strip().lower() != "none"]
    return m.group(1).lower() == "unsafe", cats


class SafetyFilter:
    def __init__(self, client: InferenceClient, *, template_kwargs: bool = True,
                 policy: str | None = None, max_tokens: int = MAX_TOKENS):
        self.client = client
        self.template_kwargs = template_kwargs
        self.policy = policy if policy is not None else POLICY_FILE.read_text(encoding="utf-8")
        self.max_tokens = max_tokens

    def check_goal(self, goal: str) -> SafetyVerdict:
        """One verdict for the whole goal; a long goal is checked in chunks, unsafe if any chunk is."""
        masked = self.client.masker.mask(goal)  # mask before chunking: a value must not be split
        verdicts = [self._classify(chunk, "goal", None) for chunk in _chunks(masked)]
        bad = [v for v in verdicts if v.unsafe]
        cats = tuple(dict.fromkeys(c for v in verdicts for c in v.categories))
        first = bad[0] if bad else verdicts[0]
        return SafetyVerdict(bool(bad), cats, first.excerpt, "goal", False)

    def check_data(self, fragments: Iterable[str]) -> list[SafetyVerdict]:
        """One verdict per batch of fragments (lines joined up to MAX_FRAGMENT_CHARS)."""
        masked = [self.client.masker.mask(f) for f in fragments]
        return [self._classify(batch, "data", self.policy) for batch in batches(masked)]

    def _classify(self, masked: str, source: str, policy: str | None) -> SafetyVerdict:
        extra = None
        if self.template_kwargs:
            kwargs: dict[str, Any] = {"request_categories": "/categories", "enable_thinking": False}
            if policy:
                kwargs["custom_policy"] = policy
            extra = {"chat_template_kwargs": kwargs}
        res = self.client.chat(MODEL, [{"role": "user", "content": masked}], max_tokens=self.max_tokens,
                               temperature=0.01, top_p=0.95, extra=extra, purpose=f"safety.{source}")
        unsafe, cats = parse_output(res.content)
        return SafetyVerdict(unsafe, tuple(cats), _excerpt(masked), source,
                             bool(policy) and self.template_kwargs)


def ledger_fragments(ledger: Any) -> list[str]:
    """String values from a ledger (SQL, paths, egress, canary rows), deduplicated, in order."""
    out: dict[str, None] = {}

    def walk(obj: Any, key: str = "") -> None:
        if isinstance(obj, str):
            if key != "ledger_sha256" and len(obj.strip()) >= MIN_LEAF_CHARS:
                out.setdefault(obj.strip(), None)
        elif isinstance(obj, dict):
            for k, v in obj.items():
                walk(v, str(k))
        elif isinstance(obj, (list, tuple)):
            for v in obj:
                walk(v, key)

    walk(ledger)
    return list(out)


def batches(fragments: Iterable[str], limit: int = MAX_FRAGMENT_CHARS) -> Iterator[str]:
    buf: list[str] = []
    size = 0
    for frag in fragments:
        for piece in _chunks(frag, limit):
            if buf and size + len(piece) + 1 > limit:
                yield "\n".join(buf)
                buf, size = [], 0
            buf.append(piece)
            size += len(piece) + 1
    if buf:
        yield "\n".join(buf)


def _chunks(text: str, limit: int = MAX_FRAGMENT_CHARS) -> list[str]:
    text = text if text.strip() else "(empty)"
    return [text[i:i + limit] for i in range(0, len(text), limit)]


def _excerpt(text: str) -> str:
    flat = " ".join(text.split())
    return flat if len(flat) <= EXCERPT_CHARS else flat[:EXCERPT_CHARS - 1] + "…"
