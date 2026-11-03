"""Ground-truth sink for the Docker stand (runs in its own container on an internal network).

It answers on every TCP/UDP port and, independently of that, sniffs every frame that
arrives on its interface. Each frame from any address other than its own is one line
in /sink/events.jsonl: that is what "left the machine" means, regardless of what the
tracer's ledger claims. It holds no secrets and only exists in the test network.
"""
import json
import os
import socket
import struct
import subprocess
import sys
import threading
import time

OUT = "/sink/events.jsonl"
TCP_PORT, UDP_PORT = 9999, 9998
lock = threading.Lock()
MY_V4 = None


def log(ev):
    ev["ts"] = time.time()
    with lock, open(OUT, "a") as f:
        f.write(json.dumps(ev) + "\n")


def my_addrs():
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.connect(("172.29.77.250", 9))
    v4 = s.getsockname()[0]
    v6 = []
    try:
        with open("/proc/net/if_inet6") as f:
            for line in f:
                h, _, _, _, _, dev = line.split()
                v6.append(":".join(h[i:i + 4] for i in range(0, 32, 4)) + "%" + dev)
    except OSError:
        pass
    return v4, v6


def tcp_server():
    s = socket.socket()
    s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    s.bind(("0.0.0.0", TCP_PORT))
    s.listen(256)
    while True:
        c, peer = s.accept()
        threading.Thread(target=tcp_conn, args=(c, peer), daemon=True).start()


def tcp_conn(c, peer):
    c.settimeout(3)
    data = b""
    try:
        while len(data) < 65536:
            d = c.recv(65536)
            if not d:
                break
            data += d
            c.sendall(b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok")
    except OSError:
        pass
    log({"kind": "tcp-payload", "src": peer[0], "bytes": len(data), "sample": data[:200].decode("latin1")})
    c.close()


def udp_server():
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.bind(("0.0.0.0", UDP_PORT))
    while True:
        d, peer = s.recvfrom(65536)
        log({"kind": "udp-payload", "src": peer[0], "bytes": len(d), "sample": d[:200].decode("latin1")})


def sniff():
    s = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.htons(3))
    while True:
        frame, meta = s.recvfrom(65535)
        if meta[2] == socket.PACKET_OUTGOING:
            continue
        et = struct.unpack("!H", frame[12:14])[0]
        if et == 0x0800 and len(frame) >= 34:
            ihl = (frame[14] & 15) * 4
            proto = frame[23]
            src = socket.inet_ntoa(frame[26:30])
            dst = socket.inet_ntoa(frame[30:34])
            l4 = frame[14 + ihl:]
            dport, payload = None, 0
            if proto in (6, 17) and len(l4) >= 8:
                dport = struct.unpack("!H", l4[2:4])[0]
                payload = len(l4) - (((l4[12] >> 4) * 4) if proto == 6 else 8)
            elif proto == 1:
                payload = max(0, len(l4) - 8)
            log({"kind": "frame", "ip": 4, "proto": proto, "src": src, "dst": dst, "dport": dport,
                 "bytes": max(payload, 0)})
        elif et == 0x86DD and len(frame) >= 54:
            nh = frame[20]
            l4 = frame[54:]
            if nh == 58 and l4 and l4[0] not in (133, 134, 135, 136, 143):
                log({"kind": "frame", "ip": 6, "proto": nh, "bytes": len(l4)})
            elif nh in (6, 17):
                log({"kind": "frame", "ip": 6, "proto": nh, "bytes": len(l4)})


def main():
    global MY_V4
    os.makedirs("/sink", exist_ok=True)
    open(OUT, "w").close()
    MY_V4, v6 = my_addrs()
    with open("/sink/info.json", "w") as f:
        json.dump({"v4": MY_V4, "v6": v6}, f)
    for proto, port in (("tcp", TCP_PORT), ("udp", UDP_PORT)):
        subprocess.run(["iptables", "-t", "nat", "-A", "PREROUTING", "-p", proto, "-j", "REDIRECT",
                        "--to-ports", str(port)], check=False)
    for fn in (tcp_server, udp_server):
        threading.Thread(target=fn, daemon=True).start()
    sniff()


if __name__ == "__main__":
    sys.exit(main())
