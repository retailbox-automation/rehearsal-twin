import json
import shutil
import socket
import ssl
import struct
import time

import pytest

from rt.tracer import egress


def dns_query(name, qtype=1, txid=0x1234):
    q = b"".join(bytes([len(p)]) + p.encode() for p in name.split(".")) + b"\x00"
    return struct.pack("!HHHHHH", txid, 0x0100, 1, 0, 0, 0) + q + struct.pack("!HH", qtype, 1)


def test_dns_roundtrip_a_record():
    pool = egress.FakeIPPool()
    q = egress.parse_dns_query(dns_query("Prod-API.internal"))
    assert q["qname"] == "prod-api.internal" and q["qtype"] == 1
    ip = pool.ip_for(q["qname"])
    resp = egress.build_dns_response(q, ip)
    txid, flags, qd, an = struct.unpack("!HHHH", resp[:8])
    assert txid == 0x1234 and qd == 1 and an == 1
    assert flags & 0x8000 and flags & 0x0100 and (flags & 0x000F) == 0
    assert socket.inet_ntoa(resp[-4:]) == ip == "198.18.0.1"


def test_dns_aaaa_gets_empty_answer_and_bad_input_raises():
    q = egress.parse_dns_query(dns_query("x.example", qtype=28))
    resp = egress.build_dns_response(q, None)
    assert struct.unpack("!H", resp[6:8])[0] == 0
    for bad in (b"", b"\x00" * 11, struct.pack("!HHHHHH", 1, 0, 0, 0, 0, 0)):
        with pytest.raises(ValueError):
            egress.parse_dns_query(bad)


def test_fake_pool_is_stable_and_reversible():
    pool = egress.FakeIPPool()
    a = pool.ip_for("a.example")
    b = pool.ip_for("b.example")
    assert a != b and pool.ip_for("a.example") == a
    assert pool.name_for(b) == "b.example"
    assert pool.name_for("10.0.0.1") is None


def client_hello(server_hostname):
    ctx = ssl.create_default_context()
    incoming, outgoing = ssl.MemoryBIO(), ssl.MemoryBIO()
    obj = ctx.wrap_bio(incoming, outgoing, server_hostname=server_hostname)
    with pytest.raises(ssl.SSLWantReadError):
        obj.do_handshake()
    return outgoing.read()


def test_parse_sni_from_real_client_hello():
    hello = client_hello("hooks.partner.example")
    assert egress.tls_record_length(hello) == len(hello)
    assert egress.parse_sni(hello) == "hooks.partner.example"
    assert egress.parse_sni(b"GET / HTTP/1.1\r\n") is None
    assert egress.parse_sni(hello[:20]) is None


def test_parse_http_head():
    m, path, h = egress.parse_http_head(b"POST /purge?x=1 HTTP/1.1\r\nHost: prod-api.internal\r\nContent-Length: 15")
    assert (m, path, h["host"], h["content-length"]) == ("POST", "/purge?x=1", "prod-api.internal", "15")
    m, path, _ = egress.parse_http_head(b"GET http://a.example/p?q HTTP/1.1\r\n")
    assert path == "/p?q"
    assert egress.looks_like_http(b"DELETE /x") and not egress.looks_like_http(b"\x16\x03\x01")


def test_scan_tokens_raw_and_percent_encoded():
    tokens = {"k": "rt-canary-key-test0002", "u": "rt-canary-url-test0003"}
    assert egress.scan_tokens(b"key=rt-canary-key-test0002", tokens) == ["k"]
    assert egress.scan_tokens(b"x=rt%2Dcanary%2Durl%2Dtest0003", tokens) == ["u"]
    assert egress.scan_tokens(b"nothing here", tokens) == []


def test_iptables_rules_shape():
    cmds = egress.iptables_up_commands(["10.77.0.3"])
    flat = [" ".join(c) for c in cmds]
    nat = [c for c in flat if " -t nat " in c and f"-A {egress.NAT_CHAIN}" in c]
    assert "--dport 53 -j REDIRECT --to-ports 5353" in nat[0]
    assert nat[-1].endswith("-p tcp -j REDIRECT --to-ports 15001")
    assert any("-d 10.77.0.3 -j RETURN" in c for c in nat)
    out = [c for c in flat if f"-A {egress.OUT_CHAIN}" in c]
    assert out[0].endswith("-o lo -j ACCEPT")
    assert any("-d 10.77.0.3 -j ACCEPT" in c for c in out)
    assert out[-1].endswith(f"-j {egress.DROP_CHAIN}")
    assert out[-2].endswith(f"-p udp -j {egress.UDP_CHAIN}")
    assert out[1].endswith("-m addrtype --dst-type LOCAL -j ACCEPT")
    assert out[2].endswith("-m conntrack --ctstate ESTABLISHED -j ACCEPT")
    assert out[3].endswith("-p udp --sport 68 --dport 67 -j ACCEPT")
    assert not any("ACCEPT" in c for c in out
                   if "-o lo" not in c and "10.77.0.3" not in c and "--dst-type LOCAL" not in c
                   and "--ctstate ESTABLISHED" not in c and "--dport 67" not in c)
    assert not any("NEW" in c or "RELATED" in c for c in flat)
    assert flat[-1].endswith(f"-I OUTPUT 1 -j {egress.OUT_CHAIN}")
    six = [" ".join(c) for c in egress.ip6tables_up_commands()]
    nd = [c for c in six if "--icmpv6-type" in c]
    assert len(nd) == 4 and all(c.endswith("-j ACCEPT") for c in nd)
    assert six[-2].endswith(f"-A {egress.OUT6_CHAIN} -j DROP")
    assert not any("ACCEPT" in c for c in six if "--icmpv6-type" not in c and "-o lo" not in c
                   and "ESTABLISHED" not in c)
    assert any(c.endswith(f"-I OUTPUT 1 -j {egress.NAT_CHAIN}") for c in flat)
    with pytest.raises(ValueError):
        egress._allow_list("not-an-ip")
    assert egress._allow_list("10.77.0.3, 10.77.0.4") == ["10.77.0.3", "10.77.0.4"]


def test_parse_chain_counters():
    text = ("Chain RT_EGRESS_UDP (1 references)\n"
            "    pkts      bytes target     prot opt in     out     source               destination\n"
            "       3      180 DROP       0    --  *      *       0.0.0.0/0            0.0.0.0/0\n")
    assert egress.parse_chain_counters(text) == {"packets": 3, "bytes": 180}
    assert egress.parse_chain_counters("") == {"packets": 0, "bytes": 0}


def test_proc_attribution_parsing(tmp_path):
    net = tmp_path / "net"
    net.mkdir()
    (net / "tcp").write_text(
        "  sl  local_address rem_address   st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode\n"
        "   0: 0100007F:3A99 00000000:0000 0A 00000000:00000000 00:00000000 00000000     0        0 11111 1\n"
        "   1: 020011AC:C350 01001EC6:01BB 01 00000000:00000000 00:00000000 00000000     0        0 22222 1\n")
    assert egress.socket_inode(50000, "tcp", str(net)) == "22222"
    assert egress.socket_inode(1, "tcp", str(net)) is None
    assert egress.unit_from_cgroup("0::/rt.slice/rt-run-ab12.scope\n") == "rt-run-ab12.scope"
    assert egress.unit_from_cgroup("0::/system.slice/shop-webhooks.service\n") == "shop-webhooks.service"
    assert egress.unit_from_cgroup("0::/\n") is None


def test_cert_names():
    assert egress.cert_name_ok("prod-api.internal")
    assert egress.cert_name_ok("203.0.113.5")
    assert not egress.cert_name_ok("a/b")
    assert not egress.cert_name_ok("x\n/CN=evil")
    assert not egress.cert_name_ok("")


# ---- local recorder loop (macOS or Linux): orig dst and owner are injected

def _recorder(tmp_path, tokens=None, ca=False):
    pool = egress.FakeIPPool()
    ip = pool.ip_for("prod-api.internal")
    if ca:
        egress.init_ca(str(tmp_path / "ca"))
    rec = egress.Recorder(str(tmp_path / "egress.jsonl"), str(tmp_path / "ca"), tokens or {}, pool,
                          orig_dst_fn=lambda conn: (ip, 443 if ca else 80),
                          owner_fn=lambda port, proto: {"unit": "rt-run-test.scope", "comm": "curl"},
                          read_timeout=1.0)
    stop, socks, _ = egress.start(rec, "127.0.0.1", 0, 0)
    return rec, stop, socks


def _records(tmp_path, n, timeout=5.0):
    path = tmp_path / "egress.jsonl"
    deadline = time.time() + timeout
    while time.time() < deadline:
        if path.exists():
            lines = [json.loads(x) for x in path.read_text().splitlines() if x.strip()]
            if len(lines) >= n:
                return lines
        time.sleep(0.05)
    raise AssertionError("records not written")


def test_recorder_http_post_gets_503_and_is_recorded(tmp_path):
    rec, stop, socks = _recorder(tmp_path, tokens={"purge-url": "rt-canary-url-test0003"})
    try:
        port = socks["tcp"].getsockname()[1]
        body = b'{"scope":"all","t":"rt-canary-url-test0003"}'
        with socket.create_connection(("127.0.0.1", port), timeout=3) as c:
            c.sendall(b"POST /purge HTTP/1.1\r\nHost: prod-api.internal\r\nContent-Length: "
                      + str(len(body)).encode() + b"\r\n\r\n" + body)
            resp = b""
            while True:
                chunk = c.recv(4096)
                if not chunk:
                    break
                resp += chunk
        assert resp.startswith(b"HTTP/1.1 503 ")
        r = _records(tmp_path, 1)[0]
        assert (r["kind"], r["method"], r["host"], r["path"], r["port"]) == ("http", "POST", "prod-api.internal",
                                                                              "/purge", 80)
        assert r["bytes_attempted"] > len(body) and r["delivered"] == 0 and r["response"] == 503
        assert r["canary_hits"] == ["purge-url"]
        assert r["unit"] == "rt-run-test.scope"
    finally:
        stop.set()


def test_recorder_dns_udp(tmp_path):
    rec, stop, socks = _recorder(tmp_path)
    try:
        port = socks["dns_udp"].getsockname()[1]
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
            s.settimeout(3)
            s.sendto(dns_query("hooks.partner.example"), ("127.0.0.1", port))
            resp, _ = s.recvfrom(4096)
        ip = socket.inet_ntoa(resp[-4:])
        assert rec.pool.name_for(ip) == "hooks.partner.example"
        r = _records(tmp_path, 1)[0]
        assert r["kind"] == "dns" and r["qname"] == "hooks.partner.example" and r["answer"] == ip
    finally:
        stop.set()


def test_recorder_raw_tcp_counts_bytes(tmp_path):
    rec, stop, socks = _recorder(tmp_path)
    try:
        port = socks["tcp"].getsockname()[1]
        with socket.create_connection(("127.0.0.1", port), timeout=3) as c:
            c.sendall(b"\x00\x01binary-protocol-bytes")
            c.shutdown(socket.SHUT_WR)
            c.recv(10)
        r = _records(tmp_path, 1)[0]
        assert r["kind"] == "tcp" and r["bytes_attempted"] == 23 and "method" not in r
    finally:
        stop.set()


@pytest.mark.skipif(shutil.which("openssl") is None, reason="openssl CLI not available")
def test_recorder_https_terminates_tls_with_own_ca(tmp_path):
    rec, stop, socks = _recorder(tmp_path, ca=True)
    try:
        port = socks["tcp"].getsockname()[1]
        ctx = ssl.create_default_context(cafile=str(tmp_path / "ca" / "ca.crt"))
        with socket.create_connection(("127.0.0.1", port), timeout=5) as raw:
            with ctx.wrap_socket(raw, server_hostname="prod-api.internal") as c:
                c.sendall(b"POST /purge HTTP/1.1\r\nHost: prod-api.internal\r\nContent-Length: 2\r\n\r\n{}")
                resp = b""
                while True:
                    try:
                        chunk = c.recv(4096)
                    except ssl.SSLError:
                        break
                    if not chunk:
                        break
                    resp += chunk
        assert resp.startswith(b"HTTP/1.1 503 ")
        r = _records(tmp_path, 1)[0]
        assert (r["kind"], r["method"], r["host"], r["sni"], r["path"]) == (
            "https", "POST", "prod-api.internal", "prod-api.internal", "/purge")
        assert r["port"] == 443 and r["delivered"] == 0
        assert (tmp_path / "ca" / "certs" / "prod-api.internal.pem").exists()
    finally:
        stop.set()


@pytest.mark.skipif(shutil.which("openssl") is None, reason="openssl CLI not available")
def test_untrusted_client_is_recorded_as_failed_tls(tmp_path):
    rec, stop, socks = _recorder(tmp_path, ca=True)
    try:
        port = socks["tcp"].getsockname()[1]
        ctx = ssl.create_default_context()
        with socket.create_connection(("127.0.0.1", port), timeout=5) as raw:
            with pytest.raises(ssl.SSLError):
                ctx.wrap_socket(raw, server_hostname="prod-api.internal")
        r = _records(tmp_path, 1)[0]
        assert r["kind"] == "tls" and r["sni"] == "prod-api.internal"
        assert r["bytes_attempted"] > 0 and r["delivered"] == 0
    finally:
        stop.set()
