"""Presets: a script, its declared scope and extra files, from presets/<dir>/preset.json."""
from __future__ import annotations

import json
import re
from dataclasses import dataclass, field
from pathlib import Path

from rt.ledger.scope import normalize_scope

FILE_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,80}$")


class PresetError(ValueError):
    pass


@dataclass(frozen=True)
class Preset:
    id: str
    name: str
    title: str
    goal: str
    description: str
    script: str
    scope: dict
    files: dict[str, bytes] = field(default_factory=dict)

    def public(self) -> dict:
        return {"id": self.id, "name": self.name, "title": self.title, "goal": self.goal,
                "description": self.description, "script": self.script.splitlines(),
                "scope": normalize_scope(self.scope), "files": sorted(self.files)}


def _safe_name(name: str) -> str:
    if not isinstance(name, str) or not FILE_RE.match(name):
        raise PresetError(f"bad file name in preset: {name!r}")
    return name


def load_preset(d: Path) -> Preset:
    meta = json.loads((d / "preset.json").read_text(encoding="utf-8"))
    script_name = _safe_name(meta["script"])
    scope = json.loads((d / _safe_name(meta.get("scope", "scope.json"))).read_text(encoding="utf-8"))
    normalize_scope(scope)  # refuse a broken scope at load time
    files = {}
    for f in meta.get("files") or []:
        if _safe_name(f) in ("script.sh", "scope.json"):
            raise PresetError(f"preset file name {f!r} is reserved")
        files[f] = (d / f).read_bytes()
    return Preset(id=str(meta["id"]), name=_safe_name(meta.get("name", script_name)),
                  title=meta.get("title", ""), goal=meta.get("goal", ""),
                  description=meta.get("description", ""),
                  script=(d / script_name).read_text(encoding="utf-8"), scope=scope, files=files)


def load_presets(root: Path) -> dict[str, Preset]:
    out: dict[str, Preset] = {}
    if not root.is_dir():
        return out
    for d in sorted(root.iterdir()):
        if (d / "preset.json").is_file():
            p = load_preset(d)
            if p.id in out:
                raise PresetError(f"duplicate preset id {p.id!r}")
            out[p.id] = p
    return out
