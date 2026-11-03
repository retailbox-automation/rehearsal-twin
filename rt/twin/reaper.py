"""Delete twins that outlived their TTL.

Only instances tagged rt-twin are candidates. Anything that also carries a
protected tag (probe, rt-keep) is never touched, whatever else it carries.
The tag check is done here on every instance, not left to the server filter.
An instance whose creation time cannot be read is kept. An instance the caller marks
active (a twin a running rehearsal still holds) is kept whatever its age.
"""
from __future__ import annotations

from datetime import datetime, timezone
from typing import Callable

from rt.twin.lifecycle import PROTECTED_TAGS, TWIN_TAG, parse_created
from rt.twin.vultr import NotFound, Vultr

DEFAULT_TTL_S = 15 * 60


def reap(client: Vultr, ttl_s: float = DEFAULT_TTL_S, *, dry_run: bool = False,
         now: datetime | None = None, active: Callable[[dict], bool] | None = None) -> list[dict]:
    """Return one row per rt-twin candidate: {id, label, age_s, action}."""
    now = now or datetime.now(timezone.utc)
    report: list[dict] = []
    for inst in client.list_instances(tag=TWIN_TAG):
        tags = set(inst.get("tags") or [])
        if TWIN_TAG not in tags:
            continue  # server ignored the filter; not ours to judge
        row = {"id": inst.get("id"), "label": inst.get("label", ""), "tags": sorted(tags), "age_s": None}
        if tags & PROTECTED_TAGS:
            row["action"] = "kept:protected"
            report.append(row)
            continue
        if active is not None and active(inst):
            row["action"] = "kept:active"
            report.append(row)
            continue
        created = parse_created(inst.get("date_created", ""))
        if created is None:
            row["action"] = "kept:bad-date"
            report.append(row)
            continue
        age = (now - created).total_seconds()
        row["age_s"] = round(age, 1)
        if age <= ttl_s:
            row["action"] = "kept:young"
        elif dry_run:
            row["action"] = "would-delete"
        else:
            try:
                client.delete_instance(row["id"])
                row["action"] = "deleted"
            except NotFound:
                row["action"] = "gone"
        report.append(row)
    return report
