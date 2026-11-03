import copy
import json

from rt.ledger.canonical import canonical_bytes, ledger_sha256, seal


def sample():
    return {
        "files": {"created": [], "modified": [], "deleted": ["/srv/app/tmp/cache/a", "/srv/app/uploads/b"]},
        "rows": {"sessions": {"inserted": 0, "deleted": 240, "updated": 0}},
        "sql": [{"user": "root", "db": "shop", "app": "psql",
                 "statement": "DELETE FROM sessions WHERE expires_at < now()"}],
        "egress": [{"kind": "https", "method": "POST", "host": "prod-api.internal", "path": "/purge",
                    "port": 443, "bytes_attempted": 190, "delivered": 0}],
        "canaries": [{"id": "env-file", "kind": "file", "touched": True, "exfil_attempt": False}],
        "exit": 0,
        "limits": {"wall_s": 0.41, "peak_mem_mb": 11.2, "oom": False, "pids_max": 256},
        "generated_at": "2026-11-03T16:00:00Z",
    }


def reorder(obj):
    """Same content, keys inserted in reverse order at every level."""
    if isinstance(obj, dict):
        return {k: reorder(obj[k]) for k in reversed(list(obj))}
    if isinstance(obj, list):
        return [reorder(v) for v in obj]
    return obj


def test_same_ledger_same_hash():
    assert ledger_sha256(sample()) == ledger_sha256(sample())


def test_key_permutation_same_hash():
    a = sample()
    b = reorder(a)
    assert list(a) != list(b)
    assert json.dumps(a) != json.dumps(b)
    assert ledger_sha256(a) == ledger_sha256(b)


def test_volatile_fields_do_not_change_hash():
    a = sample()
    b = copy.deepcopy(a)
    b["generated_at"] = "2027-01-01T00:00:00Z"
    b["limits"]["wall_s"] = 9.9
    b["limits"]["peak_mem_mb"] = 400.0
    b["rid"] = "r-123"
    assert ledger_sha256(a) == ledger_sha256(b)


def test_side_effect_change_changes_hash():
    a = sample()
    b = copy.deepcopy(a)
    b["rows"]["sessions"]["deleted"] = 241
    assert ledger_sha256(a) != ledger_sha256(b)
    c = copy.deepcopy(a)
    c["limits"]["oom"] = True
    assert ledger_sha256(a) != ledger_sha256(c)


def test_seal_is_stable_and_excludes_itself():
    sealed = seal(sample())
    assert sealed["ledger_sha256"] == ledger_sha256(sample())
    assert seal(sealed)["ledger_sha256"] == sealed["ledger_sha256"]
    assert b"ledger_sha256" not in canonical_bytes(sealed)
