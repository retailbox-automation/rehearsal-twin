"""The demo PROD fixture runs the egress recorder as its own user (checked on the script text)."""
from pathlib import Path

CLOUD_INIT = Path(__file__).resolve().parents[2] / "fixtures" / "prod" / "cloud-init.sh"


def _text():
    return CLOUD_INIT.read_text()


def _recorder_unit():
    text = _text()
    start = text.index("cat > /etc/systemd/system/rt-egress.service <<'EOF'\n")
    body = text[start:].split("\n", 1)[1]
    return body[:body.index("\nEOF\n")]


def _directives(unit):
    out = {}
    for line in unit.splitlines():
        if "=" in line and not line.startswith(("#", "[")):
            k, _, v = line.partition("=")
            out.setdefault(k, []).append(v)
    return out


def test_recorder_runs_as_its_own_user_with_root_only_for_the_firewall():
    d = _directives(_recorder_unit())
    assert d["User"] == ["rt-egress"] and d["Group"] == ["rt-egress"]
    assert d["ExecStartPre"] == ["+/opt/rt/bin/rt-egress iptables-up"]
    assert d["ExecStart"] == ["/opt/rt/bin/rt-egress serve"]
    assert d["NoNewPrivileges"] == ["yes"]
    ambient = d["AmbientCapabilities"][0].split()
    bounding = d["CapabilityBoundingSet"][0].split()
    assert "CAP_SYS_PTRACE" in ambient and "CAP_SYS_PTRACE" in bounding
    assert set(ambient) == set(bounding)
    # nothing that would let the recorder signal or own other processes
    for cap in ("CAP_KILL", "CAP_SYS_ADMIN", "CAP_NET_ADMIN", "CAP_SETUID", "CAP_DAC_OVERRIDE"):
        assert cap not in bounding
    assert d["Restart"] == ["always"]


def test_recorder_user_owns_its_log_and_ca_and_has_no_shell():
    text = _text()
    assert "useradd --system --user-group --no-create-home --home-dir /nonexistent " \
           "--shell /usr/sbin/nologin rt-egress" in text
    assert 'chown -R rt-egress:rt-egress "$RT_HOME/egress"' in text
    assert "install -d -m 0750 -o rt-egress -g rt-egress /var/log/rt-egress" in text
    assert "chown -R rt-egress:rt-egress /var/log/rt-egress" in text
    # ownership is set after the CA exists and before the unit is (re)started
    assert text.index('init-ca --ca-dir "$RT_HOME/egress"') < text.index('chown -R rt-egress:rt-egress "$RT_HOME/egress"')
    assert text.index("chown -R rt-egress:rt-egress /var/log/rt-egress") < text.index("systemctl restart --no-block rt-egress")
