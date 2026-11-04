import hashlib
import os

from rt.tracer import fsstate


def build_tree(root):
    os.makedirs(os.path.join(root, "app/tmp/cache"))
    os.makedirs(os.path.join(root, "app/uploads"))
    os.makedirs(os.path.join(root, "rt/state"))
    for i in range(3):
        with open(os.path.join(root, f"app/tmp/cache/c{i}"), "w") as f:
            f.write(f"cache {i}\n")
    with open(os.path.join(root, "app/uploads/u1"), "w") as f:
        f.write("upload\n")
    with open(os.path.join(root, "app/keep"), "w") as f:
        f.write("keep\n")
    os.symlink("uploads", os.path.join(root, "app/current"))
    with open(os.path.join(root, "rt/state/x"), "w") as f:
        f.write("tracer\n")


def test_scan_hashes_and_excludes(tmp_path):
    root = str(tmp_path)
    build_tree(root)
    m = fsstate.scan([root], exclude=[os.path.join(root, "rt")])
    assert m[os.path.join(root, "app/keep")]["t"] == "f"
    assert m[os.path.join(root, "app/keep")]["sha256"]
    assert m[os.path.join(root, "app/current")] ["t"] == "l"
    assert m[os.path.join(root, "app/current")]["target"] == "uploads"
    assert m[os.path.join(root, "app/tmp")]["t"] == "d"
    assert not any(p.startswith(os.path.join(root, "rt")) for p in m)


def test_big_files_are_not_hashed(tmp_path):
    p = tmp_path / "big"
    p.write_bytes(b"x" * 2048)
    m = fsstate.scan([str(tmp_path)], hash_limit=1024)
    assert m[str(p)]["sha256"] is None
    assert m[str(p)]["size"] == 2048


def test_diff_created_modified_deleted_and_dirs(tmp_path):
    root = str(tmp_path)
    build_tree(root)
    m0 = fsstate.scan([root])
    os.remove(os.path.join(root, "app/tmp/cache/c0"))
    with open(os.path.join(root, "app/tmp/cache/c1"), "w") as f:
        f.write("changed\n")
    with open(os.path.join(root, "app/new"), "w") as f:
        f.write("new\n")
    os.remove(os.path.join(root, "app/uploads/u1"))
    os.rmdir(os.path.join(root, "app/uploads"))
    os.makedirs(os.path.join(root, "app/created_dir"))
    os.remove(os.path.join(root, "app/current"))
    os.symlink("tmp", os.path.join(root, "app/current"))
    m1 = fsstate.scan([root])
    files, dirs = fsstate.diff(m0, m1)
    j = lambda *p: os.path.join(root, *p)  # noqa: E731
    assert files["created"] == [j("app/new")]
    assert files["modified"] == sorted([j("app/current"), j("app/tmp/cache/c1")])
    assert files["deleted"] == sorted([j("app/tmp/cache/c0"), j("app/uploads/u1")])
    assert dirs == {"created": [j("app/created_dir")], "modified": [], "deleted": [j("app/uploads")]}


def test_mtime_only_is_not_a_modification_but_mode_is(tmp_path):
    p = tmp_path / "f"
    p.write_text("same\n")
    m0 = fsstate.scan([str(tmp_path)])
    os.utime(p, (1, 1))
    m1 = fsstate.scan([str(tmp_path)])
    assert fsstate.diff(m0, m1)[0]["modified"] == []
    os.chmod(p, 0o600)
    m2 = fsstate.scan([str(tmp_path)])
    assert fsstate.diff(m0, m2)[0]["modified"] == [str(p)]


def test_type_change_is_delete_plus_create(tmp_path):
    p = tmp_path / "x"
    p.mkdir()
    m0 = fsstate.scan([str(tmp_path)])
    p.rmdir()
    p.write_text("now a file\n")
    m1 = fsstate.scan([str(tmp_path)])
    files, dirs = fsstate.diff(m0, m1)
    assert dirs["deleted"] == [str(p)]
    assert files["created"] == [str(p)]


def test_tree_digest_changes_with_content(tmp_path):
    p = tmp_path / "rtrace"
    p.write_text("v1\n")
    d1 = fsstate.tree_digest(fsstate.scan([str(tmp_path)]))
    assert d1 == fsstate.tree_digest(fsstate.scan([str(tmp_path)]))
    p.write_text("v2\n")
    assert fsstate.tree_digest(fsstate.scan([str(tmp_path)])) != d1


def test_symlinked_root_is_walked_under_its_own_name(tmp_path):
    """Finding 6: a root that is a symlink was one entry; changes behind it were invisible."""
    real = tmp_path / "data" / "srv"
    (real / "app").mkdir(parents=True)
    (real / "app" / "f").write_text("one\n")
    root = tmp_path / "srv"
    root.symlink_to(real)
    m0 = fsstate.scan([str(root)])
    assert m0[str(root)]["t"] == "l"
    assert m0[str(root / "app" / "f")]["t"] == "f"
    (real / "app" / "f").unlink()
    (real / "app" / "g").write_text("two\n")
    files, _ = fsstate.diff(m0, fsstate.scan([str(root)]))
    assert files["deleted"] == [str(root / "app" / "f")]
    assert files["created"] == [str(root / "app" / "g")]


def test_symlinked_root_into_an_excluded_tree_is_not_walked(tmp_path):
    (tmp_path / "rt" / "state").mkdir(parents=True)
    (tmp_path / "rt" / "state" / "x").write_text("x\n")
    (tmp_path / "srv").symlink_to(tmp_path / "rt")
    m = fsstate.scan([str(tmp_path / "srv")], exclude=[str(tmp_path / "rt")])
    assert list(m) == [str(tmp_path / "srv")]


def test_directory_mode_and_owner_changes_are_listed():
    """Finding 8: chmod 0777 on a directory never reached the ledger."""
    m0 = {"/srv/app": {"t": "d", "mode": 0o755, "uid": 0, "gid": 0, "mtime_ns": 1},
          "/etc/ssl/private": {"t": "d", "mode": 0o700, "uid": 0, "gid": 0, "mtime_ns": 1},
          "/srv/same": {"t": "d", "mode": 0o755, "uid": 0, "gid": 0, "mtime_ns": 1}}
    m1 = {"/srv/app": dict(m0["/srv/app"], mode=0o777),
          "/etc/ssl/private": dict(m0["/etc/ssl/private"], gid=33),
          "/srv/same": dict(m0["/srv/same"], mtime_ns=99)}
    files, dirs = fsstate.diff(m0, m1)
    assert dirs == {"created": [], "modified": ["/etc/ssl/private", "/srv/app"], "deleted": []}
    assert files == {"created": [], "modified": [], "deleted": []}
    assert fsstate.meta(m1["/srv/app"]) == "mode:0777:uid:0:gid:0"


def test_directory_mode_change_on_disk(tmp_path):
    d = tmp_path / "app"
    d.mkdir(mode=0o755)
    os.chmod(d, 0o755)
    m0 = fsstate.scan([str(tmp_path)])
    os.chmod(d, 0o777)
    _, dirs = fsstate.diff(m0, fsstate.scan([str(tmp_path)]))
    assert dirs["modified"] == [str(d)]


def test_unhashed_file_rewritten_with_mtime_put_back_is_modified(tmp_path):
    """Finding 9: a file over hash_limit rewritten with the same size and old mtime looked unchanged."""
    p = tmp_path / "big.db"
    p.write_bytes(b"a" * 5000)
    os.utime(p, ns=(1_000_000_000, 1_000_000_000))
    m0 = fsstate.scan([str(tmp_path)], hash_limit=100)
    assert m0[str(p)]["sha256"] is None and m0[str(p)]["ctime_ns"] and m0[str(p)]["ino"]
    tmp = tmp_path / "big.new"
    tmp.write_bytes(b"b" * 5000)
    os.utime(tmp, ns=(1_000_000_000, 1_000_000_000))
    os.replace(tmp, p)
    m1 = fsstate.scan([str(tmp_path)], hash_limit=100)
    assert (m1[str(p)]["size"], m1[str(p)]["mtime_ns"]) == (m0[str(p)]["size"], m0[str(p)]["mtime_ns"])
    assert fsstate.diff(m0, m1)[0]["modified"] == [str(p)]


def test_unhashed_file_with_only_ctime_changed_is_modified():
    a = {"t": "f", "size": 10, "mode": 0o644, "uid": 0, "gid": 0, "mtime_ns": 5, "sha256": None,
         "ctime_ns": 7, "ino": 3}
    assert fsstate.diff({"/f": a}, {"/f": dict(a, ctime_ns=8)})[0]["modified"] == ["/f"]
    assert fsstate.diff({"/f": a}, {"/f": dict(a, ino=4)})[0]["modified"] == ["/f"]
    assert fsstate.diff({"/f": a}, {"/f": dict(a)})[0]["modified"] == []


def test_fingerprint_and_meta():
    f = {"t": "f", "size": 3, "mode": 0o600, "uid": 0, "gid": 33, "sha256": "ab"}
    big = {"t": "f", "size": 9, "mode": 0o644, "uid": 0, "gid": 0, "sha256": None, "ctime_ns": 11, "ino": 22}
    assert fsstate.fingerprint(f) == "ab"
    assert fsstate.fingerprint(big) == "size:9:ctime:11:ino:22"
    assert fsstate.fingerprint(big, "cd") == "cd"
    assert fsstate.fingerprint(dict(big, err="PermissionError")) is None
    assert fsstate.fingerprint({"t": "l", "target": "releases/a"}) == \
        "link:" + hashlib.sha256(b"releases/a").hexdigest()
    assert fsstate.fingerprint({"t": "d", "mode": 0o755}) is None and fsstate.fingerprint(None) is None
    assert fsstate.meta(f) == "mode:0600:uid:0:gid:33"


def test_hash_unhashed_only_when_the_file_still_matches_the_snapshot(tmp_path):
    a, b = tmp_path / "a.bin", tmp_path / "b.bin"
    a.write_bytes(b"x" * 5000)
    b.write_bytes(b"y" * 5000)
    m1 = fsstate.scan([str(tmp_path)], hash_limit=100)
    b.write_bytes(b"z" * 5000)  # changed after the snapshot: no hash
    out = fsstate.hash_unhashed([str(a), str(b), str(tmp_path / "gone")], m1)
    assert out == {str(a): hashlib.sha256(b"x" * 5000).hexdigest()}
    assert fsstate.hash_unhashed([str(a)], m1, max_file=100) == {}
    assert fsstate.hash_unhashed([str(a)], m1, max_total=100) == {}
