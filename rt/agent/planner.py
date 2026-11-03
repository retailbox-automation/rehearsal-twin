"""Planner on muse-glimmer-30b with structured output (response_format json_schema).

plan(goal, scope, target_desc) -> {script, rationale, expected{paths[], tables{}, hosts[]}}
explain(ledger, scope, script=None) -> {summary, out_of_scope[], safer_script, why_safer}

The model never decides what is in or out of scope: out_of_scope[] is copied from the
ledger (the deterministic check in rt.ledger); the model may only attach a note to a row by
its index, and cannot add, drop or reorder rows. Everything sent to the model is masked by
the client's Masker first, so it sees <secret:NAME> placeholders, never values. A script that
contains such a placeholder is rejected: scripts name secrets by environment variable and the
executor supplies the values. An answer that is not valid JSON for the schema, was cut at
max_tokens or breaks those rules is retried; at most 3 attempts per call.
"""
from __future__ import annotations

import json
from pathlib import Path
from typing import Any, Callable

from rt.agent.inference import InferenceClient, check_model

MODEL = "muse-glimmer-30b"
MAX_ATTEMPTS = 3
MAX_TOKENS = 16384
LIST_CAP = 40
OUT_OF_SCOPE_CAP = 100
STRING_CAP = 2000
SCRIPT_MAX_CHARS = 20000
TEXT_MAX_CHARS = 4000
PROMPTS = Path(__file__).with_name("prompts")

_COUNT = {"type": ["integer", "null"]}
PLAN_SCHEMA: dict = {
    "type": "object",
    "additionalProperties": False,
    "required": ["script", "rationale", "expected"],
    "properties": {
        "script": {"type": "string"},
        "rationale": {"type": "string"},
        "expected": {
            "type": "object",
            "additionalProperties": False,
            "required": ["paths", "tables", "hosts"],
            "properties": {
                "paths": {"type": "array", "items": {"type": "string"}},
                "tables": {
                    "type": "array",
                    "items": {
                        "type": "object",
                        "additionalProperties": False,
                        "required": ["table", "inserted", "deleted", "updated"],
                        "properties": {"table": {"type": "string"}, "inserted": _COUNT,
                                       "deleted": _COUNT, "updated": _COUNT},
                    },
                },
                "hosts": {"type": "array", "items": {"type": "string"}},
            },
        },
    },
}

EXPLAIN_SCHEMA: dict = {
    "type": "object",
    "additionalProperties": False,
    "required": ["summary", "notes", "safer_script", "why_safer"],
    "properties": {
        "summary": {"type": "string"},
        "notes": {
            "type": "array",
            "items": {
                "type": "object",
                "additionalProperties": False,
                "required": ["index", "note"],
                "properties": {"index": {"type": "integer"}, "note": {"type": "string"}},
            },
        },
        "safer_script": {"type": "string"},
        "why_safer": {"type": "string"},
    },
}


class OutputRejected(Exception):
    """The model's answer broke the schema or a rule. The reason is ours, never model text."""


class PlannerError(Exception):
    def __init__(self, message: str, attempts: int, reasons: list[str]):
        super().__init__(message)
        self.attempts = attempts
        self.reasons = reasons


def load_prompt(name: str) -> str:
    return (PROMPTS / name).read_text(encoding="utf-8")


class Planner:
    def __init__(self, client: InferenceClient, *, model: str = MODEL, max_tokens: int = MAX_TOKENS,
                 temperature: float = 0.2, max_attempts: int = MAX_ATTEMPTS,
                 reasoning_effort: str | None = None):
        check_model(model)
        self.client = client
        self.model = model
        self.max_tokens = max_tokens
        self.temperature = temperature
        self.max_attempts = max(1, min(max_attempts, MAX_ATTEMPTS))
        self.reasoning_effort = reasoning_effort

    # -- public --------------------------------------------------------------
    def plan(self, goal: str, scope: dict, target_desc: str) -> dict:
        m = self.client.masker
        user = (
            f"<goal>\n{m.mask(goal)}\n</goal>\n\n"
            f"<scope>\n{_dump(m.mask_obj(scope))}\n</scope>\n\n"
            f"<target>\n{m.mask(target_desc)}\n</target>"
        )
        obj = self._ask(load_prompt("planner_system.md"), user, "rehearsal_plan", PLAN_SCHEMA,
                        self._check_plan, "plan")
        exp = obj["expected"]
        tables = {t["table"]: {"inserted": t["inserted"], "deleted": t["deleted"], "updated": t["updated"]}
                  for t in exp["tables"]}
        return {"script": obj["script"], "rationale": obj["rationale"],
                "expected": {"paths": list(exp["paths"]), "tables": tables, "hosts": list(exp["hosts"])}}

    def explain(self, ledger: dict, scope: dict, script: str | None = None) -> dict:
        m = self.client.masker
        rows = list(ledger.get("out_of_scope") or [])
        shown = rows[:OUT_OF_SCOPE_CAP]
        numbered = "\n".join(f"{i}: {_dump(m.mask_obj(r))}" for i, r in enumerate(shown))
        if len(rows) > len(shown):
            numbered += f"\n... {len(rows) - len(shown)} more rows not shown"
        body = {k: v for k, v in ledger.items() if k != "out_of_scope"}
        parts = [f"<scope>\n{_dump(m.mask_obj(scope))}\n</scope>"]
        if script is not None:
            parts.append(f"<script>\n{m.mask(script)}\n</script>")
        parts.append(f"<ledger>\n{_dump(_compact(m.mask_obj(body)))}\n</ledger>")
        parts.append(f"<out_of_scope>\n{numbered or '(none)'}\n</out_of_scope>")
        obj = self._ask(load_prompt("explain_system.md"), "\n\n".join(parts), "rehearsal_explain",
                        EXPLAIN_SCHEMA, self._check_explain, "explain")
        notes: dict[int, str] = {}
        for n in obj["notes"]:
            if 0 <= n["index"] < len(shown):
                notes.setdefault(n["index"], n["note"][:TEXT_MAX_CHARS])
        out = []
        for i, row in enumerate(rows):
            item = dict(row) if isinstance(row, dict) else {"row": row}
            item["note"] = notes.get(i)
            out.append(item)
        return {"summary": obj["summary"], "out_of_scope": out,
                "safer_script": obj["safer_script"], "why_safer": obj["why_safer"]}

    # -- internals -----------------------------------------------------------
    def _ask(self, system: str, user: str, name: str, schema: dict,
             check: Callable[[dict], None], purpose: str) -> dict:
        fmt = {"type": "json_schema", "json_schema": {"name": name, "strict": True, "schema": schema}}
        extra = {"reasoning_effort": self.reasoning_effort} if self.reasoning_effort else None
        reasons: list[str] = []
        for attempt in range(1, self.max_attempts + 1):
            content = user
            if reasons:
                content += ("\n\nYour previous answer was rejected: " + reasons[-1]
                            + ". Answer again with JSON only, matching the schema.")
            res = self.client.chat(self.model, [{"role": "system", "content": system},
                                                {"role": "user", "content": content}],
                                   max_tokens=self.max_tokens, response_format=fmt,
                                   temperature=self.temperature, extra=extra,
                                   purpose=f"{purpose}#{attempt}")
            try:
                if res.finish_reason == "length":
                    raise OutputRejected("the answer was cut at max_tokens")
                try:
                    obj = json.loads(_strip_fence(res.content))
                except json.JSONDecodeError as e:
                    raise OutputRejected(f"not valid JSON ({e.msg} at char {e.pos})") from None
                validate(obj, schema)
                check(obj)
                return obj
            except OutputRejected as e:
                reasons.append(str(e))
        raise PlannerError(f"{purpose}: no valid answer in {self.max_attempts} attempts", self.max_attempts, reasons)

    def _check_plan(self, obj: dict) -> None:
        _check_script(obj["script"], "script")
        _check_len(obj["rationale"], "rationale")
        self._check_no_leak(obj)

    def _check_explain(self, obj: dict) -> None:
        _check_script(obj["safer_script"], "safer_script")
        _check_len(obj["summary"], "summary")
        _check_len(obj["why_safer"], "why_safer")
        self._check_no_leak(obj)

    def _check_no_leak(self, obj: dict) -> None:
        if self.client.masker.leaks(json.dumps(obj, ensure_ascii=False)):
            raise OutputRejected("the answer contains a secret value or canary token")


def validate(obj: Any, schema: dict, path: str = "$") -> None:
    """Checks the subset of JSON Schema used above: type, properties, required,
    additionalProperties false, items, enum."""
    types = schema.get("type")
    if types is not None:
        allowed = types if isinstance(types, list) else [types]
        if not any(_is_type(obj, t) for t in allowed):
            raise OutputRejected(f"{path}: expected {'|'.join(allowed)}")
    if "enum" in schema and obj not in schema["enum"]:
        raise OutputRejected(f"{path}: value not allowed")
    if isinstance(obj, dict):
        props = schema.get("properties", {})
        for key in schema.get("required", []):
            if key not in obj:
                raise OutputRejected(f"{path}: missing {key}")
        if schema.get("additionalProperties") is False:
            extra = [k for k in obj if k not in props]
            if extra:
                raise OutputRejected(f"{path}: unexpected keys {len(extra)}")
        for key, sub in props.items():
            if key in obj:
                validate(obj[key], sub, f"{path}.{key}")
    if isinstance(obj, list) and "items" in schema:
        for i, item in enumerate(obj):
            validate(item, schema["items"], f"{path}[{i}]")


def _is_type(v: Any, t: str) -> bool:
    if t == "object":
        return isinstance(v, dict)
    if t == "array":
        return isinstance(v, list)
    if t == "string":
        return isinstance(v, str)
    if t == "integer":
        return isinstance(v, int) and not isinstance(v, bool)
    if t == "number":
        return isinstance(v, (int, float)) and not isinstance(v, bool)
    if t == "boolean":
        return isinstance(v, bool)
    if t == "null":
        return v is None
    return False


def _check_script(script: str, field: str) -> None:
    if not script.strip():
        raise OutputRejected(f"{field} is empty")
    if len(script) > SCRIPT_MAX_CHARS:
        raise OutputRejected(f"{field} is longer than {SCRIPT_MAX_CHARS} characters")
    if "<secret:" in script:
        raise OutputRejected(f"{field} contains a <secret:...> placeholder; name secrets by environment variable instead")


def _check_len(text: str, field: str) -> None:
    if len(text) > TEXT_MAX_CHARS:
        raise OutputRejected(f"{field} is longer than {TEXT_MAX_CHARS} characters")


def _compact(obj: Any) -> Any:
    """Bounds what the model reads: lists cut to LIST_CAP with a count, long strings cut."""
    if isinstance(obj, str):
        return obj if len(obj) <= STRING_CAP else obj[:STRING_CAP] + f"... [{len(obj) - STRING_CAP} more chars]"
    if isinstance(obj, dict):
        return {k: _compact(v) for k, v in obj.items()}
    if isinstance(obj, list):
        head = [_compact(v) for v in obj[:LIST_CAP]]
        if len(obj) > LIST_CAP:
            head.append(f"... {len(obj) - LIST_CAP} more")
        return head
    return obj


def _dump(obj: Any) -> str:
    return json.dumps(obj, ensure_ascii=False, sort_keys=True, indent=1)


def _strip_fence(text: str) -> str:
    t = text.strip()
    if t.startswith("```"):
        t = t.split("\n", 1)[1] if "\n" in t else ""
        if t.rstrip().endswith("```"):
            t = t.rstrip()[:-3]
    return t.strip()
