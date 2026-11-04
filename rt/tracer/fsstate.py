"""File manifest under tracked roots and the diff of two manifests."""
from __future__ import annotations

import hashlib
import os
import stat

TYPE_FILE, TYPE_DIR, TYPE_LINK, TYPE_OTHER = "f", "d", "l", "o"


def _excluded(path: str, exclude) -> bool:
    for e in exclude:
        e = e.rstrip("/") or "/"
        if path == e or path.startswith(e + "/"):
            return True
    return False


def _sha256(path: str, limit: int):
    h = hashlib.sha256()
    total = 0
    with open(path, "rb") as f:
        while True:
            chunk = f.read(65536)
            if not chunk:
                break
            total += len(chunk)
            if total > limit:
                return None
            h.update(chunk)
    return h.hexdigest()


def entry_for(path: str, st: os.stat_result, hash_limit: int) -> dict:
    mode = st.st_mode
    e = {"size": st.st_size, "mode": stat.S_IMODE(mode), "uid": st.st_uid, "gid": st.st_gid,
         "mtime_ns": st.st_mtime_ns}
    if stat.S_ISREG(mode):
        # ctime cannot be set back from user space (only the clock moves it, and the sandbox has no
        # CAP_SYS_TIME); a rewrite through a new file also changes the inode.
        e["ctime_ns"] = st.st_ctime_ns
        e["ino"] = st.st_ino
    if stat.S_ISDIR(mode):
        e["t"] = TYPE_DIR
        e["size"] = 0
    elif stat.S_ISLNK(mode):
        e["t"] = TYPE_LINK
        try:
            e["target"] = os.readlink(path)
        except OSError as exc:
            e["err"] = exc.__class__.__name__
    elif stat.S_ISREG(mode):
        e["t"] = TYPE_FILE
        e["sha256"] = None
        if st.st_size <= hash_limit:
            try:
                e["sha256"] = _sha256(path, hash_limit)
            except OSError as exc:
                e["err"] = exc.__class__.__name__
    else:
        e["t"] = TYPE_OTHER
    return e


def scan(roots, exclude=(), hash_limit: int = 4 * 1024 * 1024) -> dict:
    """Return {path: entry} for every entry under the roots (symlinks not followed).

    A root that is itself a symlink to a directory is recorded as the link and its target is
    walked too, with every entry named under the root (`/srv/app/x` for /srv -> /data/srv): the
    sandbox makes the real directory writable, so its contents must be traced.
    """
    out = {}
    stack = []  # (directory on disk, the name it is reported under)
    for r in roots:
        r = os.path.normpath(r)
        if _excluded(r, exclude):
            continue
        try:
            st = os.lstat(r)
        except OSError:
            continue
        out[r] = entry_for(r, st, hash_limit)
        if stat.S_ISDIR(st.st_mode):
            stack.append((r, r))
        elif stat.S_ISLNK(st.st_mode):
            real = os.path.realpath(r)
            if os.path.isdir(real) and not _excluded(real, exclude):
                stack.append((real, r))
    while stack:
        d, shown = stack.pop()
        try:
            it = list(os.scandir(d))
        except OSError as exc:
            out.setdefault(shown, {})["err"] = exc.__class__.__name__
            continue
        for de in it:
            p = os.path.join(shown, de.name)
            if _excluded(p, exclude) or _excluded(de.path, exclude):
                continue
            try:
                st = de.stat(follow_symlinks=False)
            except OSError:
                continue
            out[p] = entry_for(de.path, st, hash_limit)
            if stat.S_ISDIR(st.st_mode):
                stack.append((de.path, p))
    return out


def _changed(a: dict, b: dict) -> bool:
    if a.get("t") != b.get("t"):
        return True
    for k in ("mode", "uid", "gid"):
        if a.get(k) != b.get(k):
            return True
    t = a.get("t")
    if t == TYPE_LINK:
        return a.get("target") != b.get("target")
    if t == TYPE_FILE:
        if a.get("size") != b.get("size"):
            return True
        if a.get("sha256") and b.get("sha256"):
            return a["sha256"] != b["sha256"]
        # Not hashed (over hash_limit or unreadable): mtime can be put back with utime(), ctime and
        # the inode cannot.
        return any(a.get(k) != b.get(k) for k in ("mtime_ns", "ctime_ns", "ino"))
    return False


def diff(m0: dict, m1: dict) -> tuple[dict, dict]:
    """Return (files, dirs): files{created, modified, deleted}, dirs{created, modified, deleted}.

    mtime alone does not make a file modified when both contents are hashed. A directory is
    modified when its mode, owner or group changed (entries coming and going are listed on their
    own). A type change (dir <-> file) shows as a delete plus a create.
    """
    files = {"created": [], "modified": [], "deleted": []}
    dirs = {"created": [], "modified": [], "deleted": []}
    for p in sorted(set(m0) | set(m1)):
        a, b = m0.get(p), m1.get(p)
        a_dir = a is not None and a.get("t") == TYPE_DIR
        b_dir = b is not None and b.get("t") == TYPE_DIR
        if a is not None and b is not None and a.get("t") != b.get("t"):
            (dirs if a_dir else files)["deleted"].append(p)
            (dirs if b_dir else files)["created"].append(p)
        elif a is None:
            (dirs if b_dir else files)["created"].append(p)
        elif b is None:
            (dirs if a_dir else files)["deleted"].append(p)
        elif _changed(a, b):
            (dirs if a_dir else files)["modified"].append(p)
    return files, dirs


def fingerprint(entry: dict | None, large_sha256: str | None = None) -> str | None:
    """What a created or modified path holds now, comparable between two machines.

    A regular file: its sha256 (`large_sha256` for a file over hash_limit hashed later), else
    "size:<n>:ctime:<ns>:ino:<n>" (only the size is comparable across machines). A symlink:
    "link:<sha256 of the target>". Anything else, or an unreadable file: None.
    """
    if not entry:
        return None
    t = entry.get("t")
    if t == TYPE_FILE:
        if entry.get("sha256"):
            return entry["sha256"]
        if large_sha256:
            return large_sha256
        if entry.get("err") or entry.get("ctime_ns") is None:
            return None
        return f"size:{entry.get('size')}:ctime:{entry.get('ctime_ns')}:ino:{entry.get('ino')}"
    if t == TYPE_LINK and isinstance(entry.get("target"), str):
        return "link:" + hashlib.sha256(entry["target"].encode("utf-8", "surrogatepass")).hexdigest()
    return None


def meta(entry: dict | None) -> str | None:
    """Mode, owner and group of a path as one comparable string."""
    if not entry or entry.get("mode") is None:
        return None
    return f"mode:{entry['mode']:04o}:uid:{entry.get('uid')}:gid:{entry.get('gid')}"


def hash_unhashed(paths, m1: dict, max_file: int = 512 << 20, max_total: int = 2 << 30) -> dict:
    """sha256 now of changed files the snapshot did not hash (over hash_limit), when they still match it.

    The file is used only if size, mtime, ctime and inode are the same as in the snapshot before
    and after reading it, so the hash is of the content the snapshot saw.
    """
    out = {}
    budget = max_total
    for p in paths:
        e = m1.get(p) or {}
        if e.get("t") != TYPE_FILE or e.get("sha256") or e.get("err") or e.get("ctime_ns") is None:
            continue
        size = e.get("size") or 0
        if size > max_file or size > budget:
            continue
        sig = (e.get("size"), e.get("mtime_ns"), e.get("ctime_ns"), e.get("ino"))

        def now():
            st = os.lstat(p)
            if not stat.S_ISREG(st.st_mode):
                return None
            return (st.st_size, st.st_mtime_ns, st.st_ctime_ns, st.st_ino)
        try:
            if now() != sig:
                continue
            digest = _sha256(p, max_file)
            if digest and now() == sig:
                out[p] = digest
                budget -= size
        except OSError:
            continue
    return out


def tree_digest(manifest: dict) -> str:
    """One hash over a manifest (used to prove the tracer itself was not changed)."""
    h = hashlib.sha256()
    for p in sorted(manifest):
        e = manifest[p]
        h.update(f"{p}\0{e.get('t')}\0{e.get('sha256')}\0{e.get('target')}\0{e.get('mode')}\n".encode())
    return h.hexdigest()
