"""The hold-out archive is reproducible: same attack files -> same bytes, whatever the file times or owner."""
import hashlib
import io
import os
import tarfile

from redteam import holdout_tar as ht


def _set(tmp_path, name="set"):
    root = tmp_path / name
    for aid, body in (("escape-99-a", "echo a\n"), ("keys-99-b", "echo b\n")):
        d = root / aid
        d.mkdir(parents=True)
        (d / "attack.sh").write_text("#!/bin/bash\n" + body)
        (d / "attack.sh").chmod(0o755)
        (d / "expect.json").write_text('{"id": "%s"}\n' % aid)
    return root


def _sha(b):
    return hashlib.sha256(b).hexdigest()


def test_same_files_give_the_same_bytes_whatever_the_times(tmp_path):
    one, n1 = ht.build(_set(tmp_path, "one"))
    two_root = _set(tmp_path, "two")
    for p in two_root.rglob("*"):
        os.utime(p, (1_700_000_000, 1_700_000_000))
    two, n2 = ht.build(two_root)
    assert n1 == n2 == 2
    assert _sha(one) == _sha(two)


def test_a_changed_byte_changes_the_sha(tmp_path):
    root = _set(tmp_path)
    before, _ = ht.build(root)
    (root / "keys-99-b" / "expect.json").write_text('{"id": "keys-99-b", "x": 1}\n')
    after, _ = ht.build(root)
    assert _sha(before) != _sha(after)  # must-differ control for the test above


def test_entries_are_sorted_neutral_and_keep_the_exec_bit(tmp_path):
    data, _ = ht.build(_set(tmp_path))
    with tarfile.open(fileobj=io.BytesIO(data)) as tar:
        members = tar.getmembers()
    names = [m.name for m in members]
    assert names == sorted(names)
    assert all(m.mtime == 0 and m.uid == 0 and m.gid == 0 and m.uname == "" and m.gname == "" for m in members)
    modes = {m.name: m.mode for m in members}
    assert modes["escape-99-a/attack.sh"] == 0o755
    assert modes["escape-99-a/expect.json"] == 0o644
    assert modes["escape-99-a"] == 0o755


def test_cli_prints_the_sha_and_the_count(tmp_path, capsys):
    out = tmp_path / "set.tar"
    assert ht.main([str(_set(tmp_path)), str(out)]) == 0
    line = capsys.readouterr().out.strip()
    assert line == f"{_sha(out.read_bytes())}  set.tar (count=2)"
