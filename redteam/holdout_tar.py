"""Pack a set of attack directories into a byte-for-byte reproducible tar and print its sha256.

The hold-out set lives outside this repo; only its sha256 is committed (redteam/holdout.sha256), so
anyone holding the set can check it is the one that was run. The archive must therefore depend on the
attack files alone: entries sorted by path, mtime 0, owner 0:0 with empty names, mode 0755 for
directories and executable files and 0644 for the rest, ustar format, no compression.

    python3 redteam/holdout_tar.py <attacks-dir> <out.tar>
prints: <sha256>  <out-name> (count=<number of attack directories>)
"""
from __future__ import annotations

import hashlib
import io
import os
import sys
import tarfile
from pathlib import Path


def _info(name: str, mode: int, size: int = 0, kind: bytes = tarfile.REGTYPE) -> tarfile.TarInfo:
    ti = tarfile.TarInfo(name)
    ti.type, ti.mode, ti.size, ti.mtime = kind, mode, size, 0
    ti.uid = ti.gid = 0
    ti.uname = ti.gname = ""
    return ti


def build(src: Path) -> tuple[bytes, int]:
    """Return (tar bytes, number of attack directories) for the directories directly under src."""
    attacks = sorted(p for p in src.iterdir() if p.is_dir() and not p.name.startswith("."))
    buf = io.BytesIO()
    with tarfile.open(fileobj=buf, mode="w", format=tarfile.USTAR_FORMAT) as tar:
        for d in attacks:
            tar.addfile(_info(d.name, 0o755, kind=tarfile.DIRTYPE))
            for f in sorted(p for p in d.rglob("*")):
                rel = f.relative_to(src).as_posix()
                if f.is_symlink():
                    raise SystemExit(f"symlink in the attack set: {rel}")
                if f.is_dir():
                    tar.addfile(_info(rel, 0o755, kind=tarfile.DIRTYPE))
                    continue
                data = f.read_bytes()
                mode = 0o755 if os.access(f, os.X_OK) else 0o644
                tar.addfile(_info(rel, mode, len(data)), io.BytesIO(data))
    return buf.getvalue(), len(attacks)


def main(argv: list[str]) -> int:
    if len(argv) != 2:
        print((__doc__ or "").strip().splitlines()[-2].strip(), file=sys.stderr)
        return 2
    src, out = Path(argv[0]), Path(argv[1])
    data, count = build(src)
    out.write_bytes(data)
    print(f"{hashlib.sha256(data).hexdigest()}  {out.name} (count={count})")
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
