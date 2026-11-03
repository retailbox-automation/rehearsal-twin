from rt.twin.lifecycle import SSH


def _proxy_target(ssh: SSH) -> str:
    argv = ssh.argv("10.77.0.5", "true", "t1")
    proxy = next(a for a in argv if a.startswith("ProxyCommand="))
    return proxy.rsplit(" ", 1)[-1]


def test_jump_host_plain(tmp_path):
    ssh = SSH(key_file="/k", jump="207.246.126.90", state_dir=str(tmp_path))
    assert _proxy_target(ssh) == "root@207.246.126.90"


def test_jump_host_with_user_is_not_doubled(tmp_path):
    # RT_JUMP_HOST=root@host used to become root@root@host and SSH never connected (live 2026-11-03).
    ssh = SSH(key_file="/k", jump="root@207.246.126.90", state_dir=str(tmp_path))
    assert _proxy_target(ssh) == "root@207.246.126.90"


def test_jump_user_from_host_string(tmp_path):
    ssh = SSH(key_file="/k", jump="ops@207.246.126.90", state_dir=str(tmp_path))
    assert _proxy_target(ssh) == "ops@207.246.126.90"
