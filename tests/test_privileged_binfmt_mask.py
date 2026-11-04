"""Every privileged container started from this repo must mask systemd-binfmt.

A --privileged container shares the Docker VM's /proc/sys/fs/binfmt_misc. Ubuntu's systemd-binfmt writes -1 to
binfmt_misc/status at boot, which removes every entry of the VM (Rosetta x86_64 included) and breaks every other
amd64 container on the machine. So any tracked file that mentions --privileged has to carry the mask.
"""
from __future__ import annotations

import subprocess
from pathlib import Path

REPO = Path(__file__).resolve().parents[1]
UNITS = ("systemd-binfmt.service", "proc-sys-fs-binfmt_misc.automount", "proc-sys-fs-binfmt_misc.mount")


def missing_mask(text: str) -> list[str]:
    """What a file that starts a privileged container lacks; [] when it does not start one or is masked."""
    if "--privileged" not in text:
        return []
    need = [u for u in UNITS if u not in text]
    if "/dev/null" not in text:
        need.append("/dev/null")
    return need


def tracked_files() -> list[Path]:
    out = subprocess.run(["git", "-C", str(REPO), "ls-files", "-z"], capture_output=True, text=True, check=True).stdout
    return [REPO / p for p in out.split("\0") if p]


def test_every_privileged_container_masks_systemd_binfmt():
    offenders = {}
    seen = 0
    for path in tracked_files():
        try:
            text = path.read_text(encoding="utf-8")
        except (OSError, UnicodeDecodeError):
            continue
        if "--privileged" in text:
            seen += 1
        need = missing_mask(text)
        if need:
            offenders[str(path.relative_to(REPO))] = need
    assert seen >= 3  # redteam/run.py and the two docker smokes: the scan is not blind
    assert offenders == {}


def test_checker_flags_an_unmasked_privileged_run():
    unmasked = 'docker run -d --privileged --cgroupns=private "$IMG" /lib/systemd/systemd\n'
    assert missing_mask(unmasked) == list(UNITS) + ["/dev/null"]
    masked = unmasked + "".join(f'ln -sf /dev/null "/etc/systemd/system/{u}"\n' for u in UNITS)
    assert missing_mask(masked) == []
    assert missing_mask("docker run --rm alpine true\n") == []
