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
    assert dirs == {"created": [j("app/created_dir")], "deleted": [j("app/uploads")]}


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
