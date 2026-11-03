"""rt-egress: records every outbound call attempt and delivers nothing.

* DNS stub (UDP and TCP on 127.0.0.1:5353). iptables redirects all port-53
  traffic here. Every A query gets its own fake address from 198.18.0.0/15
  (benchmarking range, never routed), so a later connection maps back to the
  exact name that was looked up. AAAA and other types get an empty answer.
* TCP recorder (127.0.0.1:15001). iptables nat OUTPUT redirects every other
  outbound TCP connection here, except loopback and allowed addresses (the VPC
  address of the control machine). The original destination comes from
  SO_ORIGINAL_DST. HTTP is parsed (method, Host, path, body size); TLS is
  terminated with a certificate for the SNI name signed by a local CA that is
  trusted only on this machine; the request is answered with 503.
* filter OUTPUT accepts only loopback and allowed addresses. Other UDP and
  anything else is dropped and counted, so nothing leaves the machine.

Each attempt is one JSON line in the egress log, with the calling process and
its systemd unit when they can be found in /proc.
"""
from __future__ import annotations

import argparse
import ipaddress
import json
import os
import re
import secrets
import socket
import ssl
import struct
import subprocess
import sys
import tempfile
import threading
import time
from urllib.parse import unquote_to_bytes, urlsplit

DNS_PORT = 5353
TCP_PORT = 15001
LISTEN_ADDR = "127.0.0.1"
FAKE_BASE = "198.18.0.0"
FAKE_SIZE = 1 << 17
SO_ORIGINAL_DST = 80
HEAD_MAX = 64 * 1024
CAPTURE_MAX = 64 * 1024
BODY_MAX = 16 * 1024 * 1024
DEFAULT_LOG = "/var/log/rt-egress/egress.jsonl"
DEFAULT_CA_DIR = "/opt/rt/egress"
DEFAULT_CANARIES = "/opt/rt/canaries.json"

NAT_CHAIN = "RT_EGRESS_NAT"
OUT_CHAIN = "RT_EGRESS_OUT"
UDP_CHAIN = "RT_EGRESS_UDP"
DROP_CHAIN = "RT_EGRESS_DROP"
OUT6_CHAIN = "RT_EGRESS_OUT6"

HTTP_METHODS = (b"GET ", b"POST ", b"PUT ", b"DELETE ", b"PATCH ", b"HEAD ", b"OPTIONS ", b"CONNECT ",
                b"TRACE ")
HOSTNAME_RE = re.compile(r"^[a-z0-9_]([a-z0-9_.-]{0,251}[a-z0-9_])?$")

RESPONSE_BODY = b"egress blocked by rehearsal recorder: request recorded, 0 bytes delivered\n"
RESPONSE_503 = (
    b"HTTP/1.1 503 Service Unavailable\r\n"
    b"Content-Type: text/plain\r\n"
    b"Content-Length: " + str(len(RESPONSE_BODY)).encode() + b"\r\n"
    b"Connection: close\r\n"
    b"X-Rehearsal-Egress: recorded-not-delivered\r\n"
    b"\r\n" + RESPONSE_BODY
)


# ---------------------------------------------------------------- DNS

def parse_dns_query(data: bytes) -> dict:
    if len(data) < 12:
        raise ValueError("short dns message")
    txid, flags, qd = struct.unpack("!HHH", data[:6])
    if qd < 1:
        raise ValueError("no question")
    labels = []
    i = 12
    while True:
        if i >= len(data):
            raise ValueError("truncated qname")
        n = data[i]
        i += 1
        if n == 0:
            break
        if n & 0xC0:
            raise ValueError("compressed qname in question")
        labels.append(data[i:i + n].decode("ascii", "replace"))
        i += n
        if len(labels) > 127:
            raise ValueError("too many labels")
    if i + 4 > len(data):
        raise ValueError("truncated question")
    qtype, qclass = struct.unpack("!HH", data[i:i + 4])
    i += 4
    return {"id": txid, "flags": flags, "qname": ".".join(labels).lower(), "qtype": qtype,
            "qclass": qclass, "question": data[12:i]}


def build_dns_response(q: dict, ip: str | None, ttl: int = 5) -> bytes:
    flags = 0x8000 | (q["flags"] & 0x7900) | 0x0400 | 0x0080
    head = struct.pack("!HHHHHH", q["id"], flags, 1, 1 if ip else 0, 0, 0)
    body = q["question"]
    if ip:
        body += struct.pack("!HHHIH", 0xC00C, 1, 1, ttl, 4) + socket.inet_aton(ip)
    return head + body


class FakeIPPool:
    """name <-> fake address, one address per name for the life of the recorder."""

    def __init__(self, base: str = FAKE_BASE, size: int = FAKE_SIZE):
        self.base = int(ipaddress.IPv4Address(base))
        self.size = size
        self.by_name: dict[str, str] = {}
        self.by_ip: dict[str, str] = {}
        self.lock = threading.Lock()

    def ip_for(self, name: str) -> str:
        with self.lock:
            ip = self.by_name.get(name)
            if ip:
                return ip
            n = len(self.by_name) + 1
            if n >= self.size - 1:
                raise RuntimeError("fake address pool exhausted")
            ip = str(ipaddress.IPv4Address(self.base + n))
            self.by_name[name] = ip
            self.by_ip[ip] = name
            return ip

    def name_for(self, ip: str) -> str | None:
        with self.lock:
            return self.by_ip.get(ip)


# ---------------------------------------------------------------- TLS / HTTP parsing

def tls_record_length(data: bytes) -> int | None:
    if len(data) < 5 or data[0] != 0x16:
        return None
    return 5 + int.from_bytes(data[3:5], "big")


def parse_sni(data: bytes) -> str | None:
    """Server name from a TLS ClientHello, or None."""
    try:
        if len(data) < 5 or data[0] != 0x16 or data[5] != 0x01:
            return None
        i = 5 + 4 + 2 + 32
        i += 1 + data[i]
        i += 2 + int.from_bytes(data[i:i + 2], "big")
        i += 1 + data[i]
        ext_end = i + 2 + int.from_bytes(data[i:i + 2], "big")
        i += 2
        ext_end = min(ext_end, len(data))
        while i + 4 <= ext_end:
            etype = int.from_bytes(data[i:i + 2], "big")
            elen = int.from_bytes(data[i + 2:i + 4], "big")
            i += 4
            if etype == 0:
                j = i + 2
                while j + 3 <= i + elen:
                    ntype = data[j]
                    nlen = int.from_bytes(data[j + 1:j + 3], "big")
                    j += 3
                    if ntype == 0:
                        return data[j:j + nlen].decode("ascii", "replace").lower()
                    j += nlen
                return None
            i += elen
    except IndexError:
        return None
    return None


def looks_like_http(data: bytes) -> bool:
    return data.startswith(HTTP_METHODS)


def parse_http_head(head: bytes) -> tuple[str, str, dict]:
    lines = head.split(b"\r\n")
    parts = lines[0].decode("latin-1").split(" ")
    if len(parts) < 2:
        raise ValueError("bad request line")
    method, target = parts[0], parts[1]
    headers = {}
    for line in lines[1:]:
        if not line:
            break
        k, _, v = line.decode("latin-1").partition(":")
        headers[k.strip().lower()] = v.strip()
    if target.startswith(("http://", "https://")):
        u = urlsplit(target)
        target = (u.path or "/") + ("?" + u.query if u.query else "")
    return method, target, headers


def scan_tokens(data: bytes, tokens: dict) -> list:
    """Ids of canary tokens present in the data (raw or percent-decoded)."""
    if not data or not tokens:
        return []
    try:
        decoded = unquote_to_bytes(data)
    except Exception:  # noqa: BLE001 - malformed escapes: scan raw only
        decoded = b""
    hits = []
    for cid, tok in tokens.items():
        t = tok.encode()
        if t in data or t in decoded:
            hits.append(cid)
    return sorted(hits)


# ---------------------------------------------------------------- process attribution

def _read(path: str) -> str:
    try:
        with open(path, encoding="utf-8", errors="replace") as f:
            return f.read()
    except OSError:
        return ""


def socket_inode(port: int, proto: str = "tcp", proc_net: str = "/proc/net") -> str | None:
    for name in (proto, proto + "6"):
        lines = _read(f"{proc_net}/{name}").splitlines()[1:]
        for line in lines:
            parts = line.split()
            if len(parts) < 10:
                continue
            try:
                lport = int(parts[1].rsplit(":", 1)[1], 16)
            except (IndexError, ValueError):
                continue
            if lport == port and parts[9] != "0":
                return parts[9]
    return None


def unit_from_cgroup(text: str) -> str | None:
    for line in text.splitlines():
        if line.startswith("0::"):
            for comp in reversed(line[3:].strip().split("/")):
                if comp.endswith((".scope", ".service")):
                    return comp
    return None


def owner_of(port: int, proto: str = "tcp") -> dict:
    inode = socket_inode(port, proto)
    if not inode:
        return {}
    target = f"socket:[{inode}]"
    for pid in os.listdir("/proc"):
        if not pid.isdigit():
            continue
        fd_dir = f"/proc/{pid}/fd"
        try:
            fds = os.listdir(fd_dir)
        except OSError:
            continue
        for fd in fds:
            try:
                if os.readlink(f"{fd_dir}/{fd}") == target:
                    return {"pid": int(pid), "comm": _read(f"/proc/{pid}/comm").strip(),
                            "unit": unit_from_cgroup(_read(f"/proc/{pid}/cgroup"))}
            except OSError:
                continue
    return {}


def original_dst(conn: socket.socket) -> tuple[str, int]:
    raw = conn.getsockopt(socket.SOL_IP, SO_ORIGINAL_DST, 16)
    port = struct.unpack("!H", raw[2:4])[0]
    return socket.inet_ntoa(raw[4:8]), port


# ---------------------------------------------------------------- certificates

def _openssl(*args, cwd=None):
    p = subprocess.run(["openssl", *args], capture_output=True, text=True, cwd=cwd, timeout=30)
    if p.returncode != 0:
        raise RuntimeError(f"openssl {args[0]} failed: {p.stderr.strip()[:300]}")


def init_ca(ca_dir: str) -> dict:
    """Create the recorder CA and the leaf key once. Returns the paths."""
    os.makedirs(os.path.join(ca_dir, "certs"), exist_ok=True)
    os.chmod(ca_dir, 0o700)
    ca_key, ca_crt, leaf_key = (os.path.join(ca_dir, n) for n in ("ca.key", "ca.crt", "leaf.key"))
    if not (os.path.exists(ca_key) and os.path.exists(ca_crt)):
        _openssl("ecparam", "-name", "prime256v1", "-genkey", "-noout", "-out", ca_key)
        _openssl("req", "-x509", "-new", "-key", ca_key, "-sha256", "-days", "365",
                 "-subj", "/CN=Rehearsal Twin egress recorder CA",
                 "-addext", "basicConstraints=critical,CA:TRUE",
                 "-addext", "keyUsage=critical,keyCertSign,cRLSign",
                 "-addext", "subjectKeyIdentifier=hash",
                 "-out", ca_crt)
    if not os.path.exists(leaf_key):
        _openssl("ecparam", "-name", "prime256v1", "-genkey", "-noout", "-out", leaf_key)
    for p in (ca_key, leaf_key):
        os.chmod(p, 0o600)
    return {"ca_key": ca_key, "ca_crt": ca_crt, "leaf_key": leaf_key}


def cert_name_ok(name: str) -> bool:
    try:
        ipaddress.ip_address(name)
        return True
    except ValueError:
        return bool(HOSTNAME_RE.match(name or ""))


class CertStore:
    def __init__(self, ca_dir: str):
        self.ca_dir = ca_dir
        self.cache: dict[str, ssl.SSLContext] = {}
        self.lock = threading.Lock()

    def _issue(self, name: str) -> str:
        path = os.path.join(self.ca_dir, "certs", name + ".pem")
        if os.path.exists(path):
            return path
        try:
            ipaddress.ip_address(name)
            san = f"IP:{name}"
        except ValueError:
            san = f"DNS:{name}"
        with tempfile.TemporaryDirectory(dir=os.path.join(self.ca_dir, "certs")) as tmp:
            ext = os.path.join(tmp, "ext.cnf")
            with open(ext, "w", encoding="ascii") as f:
                f.write(f"subjectAltName={san}\nbasicConstraints=CA:FALSE\n"
                        "keyUsage=critical,digitalSignature\nextendedKeyUsage=serverAuth\n"
                        "subjectKeyIdentifier=hash\nauthorityKeyIdentifier=keyid:always\n")
            csr = os.path.join(tmp, "leaf.csr")
            out = os.path.join(tmp, "leaf.pem")
            _openssl("req", "-new", "-key", os.path.join(self.ca_dir, "leaf.key"),
                     "-subj", f"/CN={name}", "-out", csr)
            _openssl("x509", "-req", "-in", csr, "-CA", os.path.join(self.ca_dir, "ca.crt"),
                     "-CAkey", os.path.join(self.ca_dir, "ca.key"),
                     "-set_serial", str(secrets.randbits(63)), "-days", "30", "-sha256",
                     "-extfile", ext, "-out", out)
            os.replace(out, path)
        return path

    def context_for(self, name: str) -> ssl.SSLContext:
        if not cert_name_ok(name):
            raise ValueError("name not usable in a certificate")
        with self.lock:
            ctx = self.cache.get(name)
            if ctx is None:
                ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
                ctx.load_cert_chain(self._issue(name), os.path.join(self.ca_dir, "leaf.key"))
                self.cache[name] = ctx
            return ctx


# ---------------------------------------------------------------- recorder

class Recorder:
    def __init__(self, log_path: str, ca_dir: str, tokens: dict | None = None,
                 pool: FakeIPPool | None = None, orig_dst_fn=original_dst, owner_fn=owner_of,
                 read_timeout: float = 2.0):
        self.log_path = log_path
        self.certs = CertStore(ca_dir)
        self.tokens = tokens or {}
        self.pool = pool or FakeIPPool()
        self.orig_dst_fn = orig_dst_fn
        self.owner_fn = owner_fn
        self.read_timeout = read_timeout
        self.lock = threading.Lock()
        d = os.path.dirname(log_path)
        if d:
            os.makedirs(d, exist_ok=True)

    def write(self, rec: dict):
        line = json.dumps(rec, sort_keys=True, ensure_ascii=False) + "\n"
        with self.lock:
            with open(self.log_path, "a", encoding="utf-8") as f:
                f.write(line)

    def _owner(self, port: int, proto: str) -> dict:
        for attempt in range(3):
            try:
                found = self.owner_fn(port, proto) or {}
            except Exception:  # noqa: BLE001 - attribution is best effort, the record is written anyway
                found = {}
            if found.get("unit"):
                return found
            time.sleep(0.03 * (attempt + 1))
        return found

    # ---- DNS
    def dns_answer(self, data: bytes, client_port: int, proto: str) -> bytes | None:
        try:
            q = parse_dns_query(data)
        except ValueError:
            self.write({"ts": time.time(), "kind": "dns", "error": "unparsable query",
                        "bytes_attempted": len(data), "delivered": 0, **self._owner(client_port, proto)})
            return None
        ip = None
        if q["qtype"] == 1 and q["qclass"] == 1 and q["qname"]:
            ip = self.pool.ip_for(q["qname"])
        self.write({"ts": time.time(), "kind": "dns", "qname": q["qname"], "qtype": q["qtype"], "answer": ip,
                    "bytes_attempted": len(data), "delivered": 0,
                    "canary_hits": scan_tokens(q["qname"].encode(), self.tokens),
                    **self._owner(client_port, proto)})
        return build_dns_response(q, ip)

    # ---- TCP
    def _recv(self, s, n=65536) -> bytes:
        try:
            return s.recv(n)
        except (socket.timeout, TimeoutError, ssl.SSLError, OSError):
            return b""

    def _peek_hello(self, conn) -> bytes:
        data = b""
        deadline = time.monotonic() + self.read_timeout
        while time.monotonic() < deadline:
            try:
                data = conn.recv(16384, socket.MSG_PEEK)
            except (socket.timeout, TimeoutError, OSError):
                return data
            if not data:
                return data
            need = tls_record_length(data)
            if need is None or len(data) >= need or len(data) >= 16384:
                return data
            time.sleep(0.01)
        return data

    def _read_request(self, s, first: bytes, rec: dict, tls: bool) -> bytes:
        buf = first
        while b"\r\n\r\n" not in buf and len(buf) < HEAD_MAX:
            if len(buf) >= 8 and not looks_like_http(buf):
                break
            chunk = self._recv(s)
            if not chunk:
                break
            buf += chunk
        total = len(buf)
        captured = buf[:CAPTURE_MAX]
        if looks_like_http(buf) and b"\r\n\r\n" in buf:
            head, _, body = buf.partition(b"\r\n\r\n")
            try:
                method, target, headers = parse_http_head(head)
            except ValueError:
                method, target, headers = None, None, {}
            if method:
                rec.update(kind="https" if tls else "http", method=method, path=target,
                           http_host=headers.get("host"))
                cl = headers.get("content-length", "")
                if headers.get("expect", "").lower() == "100-continue":
                    pass
                elif cl.isdigit():
                    need = min(int(cl), BODY_MAX) - len(body)
                    while need > 0:
                        chunk = self._recv(s, min(65536, need))
                        if not chunk:
                            break
                        need -= len(chunk)
                        total += len(chunk)
                        if len(captured) < CAPTURE_MAX:
                            captured += chunk[:CAPTURE_MAX - len(captured)]
                elif "chunked" in headers.get("transfer-encoding", "").lower():
                    tail = body[-5:]
                    while not tail.endswith(b"0\r\n\r\n") and total < BODY_MAX:
                        chunk = self._recv(s)
                        if not chunk:
                            break
                        total += len(chunk)
                        tail = (tail + chunk)[-5:]
                        if len(captured) < CAPTURE_MAX:
                            captured += chunk[:CAPTURE_MAX - len(captured)]
                try:
                    s.sendall(RESPONSE_503)
                    rec["response"] = 503
                except OSError:
                    pass
        else:
            while total < BODY_MAX:
                chunk = self._recv(s)
                if not chunk:
                    break
                total += len(chunk)
                if len(captured) < CAPTURE_MAX:
                    captured += chunk[:CAPTURE_MAX - len(captured)]
        rec["bytes_attempted"] = total
        return captured

    def handle_tcp(self, conn: socket.socket, peer: tuple):
        rec = {"ts": time.time(), "kind": "tcp", "bytes_attempted": 0, "delivered": 0}
        captured = b""
        try:
            conn.settimeout(self.read_timeout)
            try:
                dst_ip, dst_port = self.orig_dst_fn(conn)
            except OSError:
                dst_ip, dst_port = None, None
            rec.update(orig_dst=dst_ip, port=dst_port,
                       host=(self.pool.name_for(dst_ip) if dst_ip else None) or dst_ip)
            rec.update(self._owner(peer[1], "tcp"))
            hello = self._peek_hello(conn)
            if hello and hello[0] == 0x16:
                sni = parse_sni(hello)
                rec.update(kind="tls", sni=sni)
                name = sni or dst_ip or ""
                try:
                    ctx = self.certs.context_for(name)
                    tconn = ctx.wrap_socket(conn, server_side=True)
                except (ssl.SSLError, OSError, ValueError, RuntimeError) as exc:
                    rec["error"] = f"tls handshake failed: {exc.__class__.__name__}"
                    rec["bytes_attempted"] = len(hello)
                    captured = hello
                    return
                tconn.settimeout(self.read_timeout)
                first = self._recv(tconn)
                captured = self._read_request(tconn, first, rec, tls=True)
                try:
                    tconn.close()
                except OSError:
                    pass
            else:
                first = self._recv(conn)
                captured = self._read_request(conn, first, rec, tls=False)
        finally:
            rec["canary_hits"] = scan_tokens(captured, self.tokens)
            try:
                conn.close()
            except OSError:
                pass
            self.write(rec)

    # ---- servers
    def serve_tcp(self, sock: socket.socket, stop: threading.Event):
        while not stop.is_set():
            try:
                conn, peer = sock.accept()
            except socket.timeout:
                continue
            except OSError:
                if stop.is_set():
                    return
                continue
            threading.Thread(target=self.handle_tcp, args=(conn, peer), daemon=True).start()

    def serve_dns_udp(self, sock: socket.socket, stop: threading.Event):
        while not stop.is_set():
            try:
                data, addr = sock.recvfrom(4096)
            except socket.timeout:
                continue
            except OSError:
                if stop.is_set():
                    return
                continue
            resp = self.dns_answer(data, addr[1], "udp")
            if resp:
                try:
                    sock.sendto(resp, addr)
                except OSError:
                    pass

    def _dns_tcp_conn(self, conn, peer):
        try:
            conn.settimeout(self.read_timeout)
            head = conn.recv(2)
            if len(head) < 2:
                return
            n = struct.unpack("!H", head)[0]
            data = b""
            while len(data) < n:
                chunk = conn.recv(n - len(data))
                if not chunk:
                    return
                data += chunk
            resp = self.dns_answer(data, peer[1], "tcp")
            if resp:
                conn.sendall(struct.pack("!H", len(resp)) + resp)
        except OSError:
            pass
        finally:
            conn.close()

    def serve_dns_tcp(self, sock: socket.socket, stop: threading.Event):
        while not stop.is_set():
            try:
                conn, peer = sock.accept()
            except socket.timeout:
                continue
            except OSError:
                if stop.is_set():
                    return
                continue
            threading.Thread(target=self._dns_tcp_conn, args=(conn, peer), daemon=True).start()


def _listen(kind: int, addr: str, port: int) -> socket.socket:
    s = socket.socket(socket.AF_INET, kind)
    s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    s.bind((addr, port))
    if kind == socket.SOCK_STREAM:
        s.listen(512)
    s.settimeout(0.5)
    return s


def start(rec: Recorder, addr: str = LISTEN_ADDR, tcp_port: int = TCP_PORT, dns_port: int = DNS_PORT):
    """Start all listeners in threads. Returns (stop_event, sockets, threads)."""
    stop = threading.Event()
    socks = {
        "tcp": _listen(socket.SOCK_STREAM, addr, tcp_port),
        "dns_udp": _listen(socket.SOCK_DGRAM, addr, dns_port),
        "dns_tcp": _listen(socket.SOCK_STREAM, addr, dns_port),
    }
    threads = [
        threading.Thread(target=rec.serve_tcp, args=(socks["tcp"], stop), daemon=True),
        threading.Thread(target=rec.serve_dns_udp, args=(socks["dns_udp"], stop), daemon=True),
        threading.Thread(target=rec.serve_dns_tcp, args=(socks["dns_tcp"], stop), daemon=True),
    ]
    for t in threads:
        t.start()
    return stop, socks, threads


# ---------------------------------------------------------------- iptables

def iptables_up_commands(allow, dns_port: int = DNS_PORT, tcp_port: int = TCP_PORT) -> list:
    nat = ["iptables", "-w", "-t", "nat"]
    flt = ["iptables", "-w"]
    c = [nat + ["-N", NAT_CHAIN],
         nat + ["-A", NAT_CHAIN, "-p", "udp", "--dport", "53", "-j", "REDIRECT", "--to-ports", str(dns_port)],
         nat + ["-A", NAT_CHAIN, "-p", "tcp", "--dport", "53", "-j", "REDIRECT", "--to-ports", str(dns_port)],
         nat + ["-A", NAT_CHAIN, "-m", "addrtype", "--dst-type", "LOCAL", "-j", "RETURN"]]
    for a in allow:
        c.append(nat + ["-A", NAT_CHAIN, "-d", a, "-j", "RETURN"])
    c.append(nat + ["-A", NAT_CHAIN, "-p", "tcp", "-j", "REDIRECT", "--to-ports", str(tcp_port)])
    c.append(nat + ["-I", "OUTPUT", "1", "-j", NAT_CHAIN])
    c += [flt + ["-N", UDP_CHAIN], flt + ["-A", UDP_CHAIN, "-j", "DROP"],
          flt + ["-N", DROP_CHAIN], flt + ["-A", DROP_CHAIN, "-j", "DROP"],
          flt + ["-N", OUT_CHAIN], flt + ["-A", OUT_CHAIN, "-o", "lo", "-j", "ACCEPT"],
          # Redirected packets keep the original output device in filter OUTPUT (the hook's
          # device is fixed before nat rewrites the destination), so accept by local destination.
          flt + ["-A", OUT_CHAIN, "-m", "addrtype", "--dst-type", "LOCAL", "-j", "ACCEPT"],
          # Replies on connections opened from outside (SSH from control) are not egress; a
          # connection opened from here never gets that far, its first packet is redirected or dropped.
          flt + ["-A", OUT_CHAIN, "-m", "conntrack", "--ctstate", "ESTABLISHED", "-j", "ACCEPT"],
          # DHCP lease renewals keep the VPC address; the sandboxed script cannot send these (IP filter).
          flt + ["-A", OUT_CHAIN, "-p", "udp", "--sport", "68", "--dport", "67", "-j", "ACCEPT"]]
    for a in allow:
        c.append(flt + ["-A", OUT_CHAIN, "-d", a, "-j", "ACCEPT"])
    c += [flt + ["-A", OUT_CHAIN, "-p", "udp", "-j", UDP_CHAIN],
          flt + ["-A", OUT_CHAIN, "-j", DROP_CHAIN],
          flt + ["-I", "OUTPUT", "1", "-j", OUT_CHAIN]]
    return c


def ip6tables_up_commands() -> list:
    f6 = ["ip6tables", "-w"]
    return [f6 + ["-N", OUT6_CHAIN], f6 + ["-A", OUT6_CHAIN, "-o", "lo", "-j", "ACCEPT"],
            f6 + ["-A", OUT6_CHAIN, "-m", "conntrack", "--ctstate", "ESTABLISHED", "-j", "ACCEPT"],
            f6 + ["-A", OUT6_CHAIN, "-j", "DROP"], f6 + ["-I", "OUTPUT", "1", "-j", OUT6_CHAIN]]


def iptables_down_commands() -> list:
    nat = ["iptables", "-w", "-t", "nat"]
    flt = ["iptables", "-w"]
    f6 = ["ip6tables", "-w"]
    return [nat + ["-D", "OUTPUT", "-j", NAT_CHAIN], nat + ["-F", NAT_CHAIN], nat + ["-X", NAT_CHAIN],
            flt + ["-D", "OUTPUT", "-j", OUT_CHAIN], flt + ["-F", OUT_CHAIN], flt + ["-X", OUT_CHAIN],
            flt + ["-F", UDP_CHAIN], flt + ["-X", UDP_CHAIN], flt + ["-F", DROP_CHAIN], flt + ["-X", DROP_CHAIN],
            f6 + ["-D", "OUTPUT", "-j", OUT6_CHAIN], f6 + ["-F", OUT6_CHAIN], f6 + ["-X", OUT6_CHAIN]]


def _run(argv) -> subprocess.CompletedProcess:
    return subprocess.run(argv, capture_output=True, text=True, timeout=30)


def iptables_down():
    for _ in range(3):
        for argv in iptables_down_commands():
            _run(argv)


def iptables_up(allow) -> list:
    """Install the rules (after removing old ones). Returns warnings for ip6tables only."""
    iptables_down()
    for argv in iptables_up_commands(allow):
        p = _run(argv)
        if p.returncode != 0:
            raise RuntimeError(f"{' '.join(argv)}: {p.stderr.strip()}")
    warnings = []
    for argv in ip6tables_up_commands():
        p = _run(argv)
        if p.returncode != 0:
            warnings.append(f"{' '.join(argv)}: {p.stderr.strip()}")
            break
    return warnings


def parse_chain_counters(text: str) -> dict:
    """pkts/bytes of the first DROP rule in `iptables -L CHAIN -v -x -n` output."""
    for line in text.splitlines():
        parts = line.split()
        if len(parts) >= 3 and parts[0].isdigit() and parts[2] == "DROP":
            return {"packets": int(parts[0]), "bytes": int(parts[1])}
    return {"packets": 0, "bytes": 0}


def counters() -> dict:
    out = {}
    for key, tool, chain in (("udp_packets", "iptables", UDP_CHAIN), ("other_packets", "iptables", DROP_CHAIN),
                             ("ipv6_packets", "ip6tables", OUT6_CHAIN)):
        try:
            p = _run([tool, "-w", "-L", chain, "-v", "-x", "-n"])
        except (OSError, subprocess.SubprocessError):
            continue
        if p.returncode == 0:
            out[key] = parse_chain_counters(p.stdout)["packets"]
    return out


def rules_digest() -> str | None:
    import hashlib
    h = hashlib.sha256()
    ok = False
    for argv in (["iptables", "-w", "-S"], ["iptables", "-w", "-t", "nat", "-S"], ["ip6tables", "-w", "-S"]):
        try:
            p = _run(argv)
        except (OSError, subprocess.SubprocessError):
            continue
        if p.returncode == 0:
            ok = True
            h.update(p.stdout.encode())
    return h.hexdigest() if ok else None


def load_tokens(path: str) -> dict:
    try:
        with open(path, encoding="utf-8") as f:
            data = json.load(f)
    except (OSError, ValueError):
        return {}
    return {c["id"]: c["token"] for c in data.get("canaries") or [] if c.get("id") and c.get("token")}


def _allow_list(value: str | None) -> list:
    out = []
    for item in (value or "").replace(",", " ").split():
        ipaddress.ip_network(item, strict=False)
        out.append(item)
    return out


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(prog="rt-egress")
    sub = ap.add_subparsers(dest="cmd", required=True)
    s = sub.add_parser("serve")
    s.add_argument("--log", default=os.environ.get("RT_EGRESS_LOG", DEFAULT_LOG))
    s.add_argument("--ca-dir", default=DEFAULT_CA_DIR)
    s.add_argument("--canaries", default=DEFAULT_CANARIES)
    up = sub.add_parser("iptables-up")
    up.add_argument("--allow", default=os.environ.get("RT_EGRESS_ALLOW", ""),
                    help="addresses that are not intercepted (VPC address of control), comma separated")
    sub.add_parser("iptables-down")
    sub.add_parser("counters")
    ca = sub.add_parser("init-ca")
    ca.add_argument("--ca-dir", default=DEFAULT_CA_DIR)
    args = ap.parse_args(argv)

    if args.cmd == "init-ca":
        print(json.dumps(init_ca(args.ca_dir)))
        return 0
    if args.cmd == "iptables-up":
        for w in iptables_up(_allow_list(args.allow)):
            print(f"warning: {w}", file=sys.stderr)
        return 0
    if args.cmd == "iptables-down":
        iptables_down()
        return 0
    if args.cmd == "counters":
        print(json.dumps(counters(), sort_keys=True))
        return 0

    init_ca(args.ca_dir)
    rec = Recorder(args.log, args.ca_dir, load_tokens(args.canaries))
    stop, _, threads = start(rec)
    print(f"rt-egress: dns {LISTEN_ADDR}:{DNS_PORT}, tcp {LISTEN_ADDR}:{TCP_PORT}, log {args.log}", flush=True)
    try:
        while all(t.is_alive() for t in threads):
            time.sleep(1)
    except KeyboardInterrupt:
        pass
    stop.set()
    return 1


if __name__ == "__main__":
    sys.exit(main())
