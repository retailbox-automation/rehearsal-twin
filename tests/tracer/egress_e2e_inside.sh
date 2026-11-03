#!/bin/bash
# Runs inside an ubuntu:24.04 container with NET_ADMIN; the repository is mounted read-only at /src.
# Acceptance for rt-egress: an HTTPS POST to prod-api.internal/purge is recorded, answered 503,
# and not one packet leaves the container's network interface.
set -uo pipefail
export PYTHONDONTWRITEBYTECODE=1
RT=/opt/rt
LOG=/var/log/rt-egress/egress.jsonl
IF=eth0
TOKEN=rt-canary-url-dockertest
pass=0
fail=0
check() {
  if [ "$2" = "0" ]; then echo "PASS  $1"; pass=$((pass + 1)); else echo "FAIL  $1"; fail=$((fail + 1)); fi
}
tx() { cat "/sys/class/net/$IF/statistics/tx_packets"; }
udp_send() { python3 -c 'import socket,sys; socket.socket(socket.AF_INET, socket.SOCK_DGRAM).sendto(b"x", (sys.argv[1], 9))' "$1" 2>/dev/null || true; }

install -d "$RT/lib" "$RT/bin"
tar -C /src --exclude='__pycache__' -cf - rt/__init__.py rt/tracer rt/ledger | tar -C "$RT/lib" --no-same-owner -xf -
cat > "$RT/bin/rt-egress" <<EOF
#!/usr/bin/python3 -IB
import sys
sys.path.insert(0, "$RT/lib")
from rt.tracer.egress import main
sys.exit(main())
EOF
chmod 0755 "$RT/bin/rt-egress"

# Second instrument: IPv4 packets that reach POSTROUTING on eth0 (a counting rule without a target).
iptables -w -t mangle -A POSTROUTING -o "$IF" -m comment --comment rt-e2e-out
out_pkts() { iptables -w -t mangle -L POSTROUTING -v -x -n | awk '/rt-e2e-out/ {print $1; exit}'; }

"$RT/bin/rt-egress" init-ca --ca-dir "$RT/egress" >/dev/null; check "CA created" $?
install -m 0644 "$RT/egress/ca.crt" /usr/local/share/ca-certificates/rt-egress-ca.crt
update-ca-certificates >/dev/null 2>&1
printf '{"canaries":[{"id":"purge-url","kind":"url","host":"prod-api.internal","path":"/purge","token":"%s"}]}\n' \
  "$TOKEN" > "$RT/canaries.json"

"$RT/bin/rt-egress" iptables-up; check "iptables rules installed" $?
"$RT/bin/rt-egress" serve --log "$LOG" --ca-dir "$RT/egress" --canaries "$RT/canaries.json" >/tmp/serve.log 2>&1 &
for _ in $(seq 1 50); do grep -q 'rt-egress:' /tmp/serve.log 2>/dev/null && break; sleep 0.1; done
sleep 0.3

# Let interface start-up traffic (IPv6 link-local, ARP announcements) finish before measuring.
sleep "${RT_E2E_SETTLE:-6}"
ip6out() { awk '$1 == "Ip6OutRequests" {print $2}' /proc/net/snmp6 2>/dev/null || echo 0; }
echo "ipv6 on $IF disabled: $(cat /proc/sys/net/ipv6/conf/$IF/disable_ipv6 2>/dev/null || echo n/a)"
t0=$(tx); o0=$(out_pkts); v0=$(ip6out)
c0=$("$RT/bin/rt-egress" counters)
code=$(curl -sS -o /tmp/body -w '%{http_code}' -X POST https://prod-api.internal/purge -d '{"scope":"all"}' --max-time 10)
echo "curl -X POST https://prod-api.internal/purge -> $code; body: $(cat /tmp/body 2>/dev/null)"
[ "$code" = "503" ]; check "https POST prod-api.internal/purge answered 503" $?
code=$(curl -sS -o /dev/null -w '%{http_code}' -X POST "http://prod-api.internal/purge?token=$TOKEN" -d 'x' --max-time 10)
[ "$code" = "503" ]; check "plain http POST answered 503" $?
code=$(curl -sS -o /dev/null -w '%{http_code}' https://203.0.113.5/status --max-time 10)
[ "$code" = "503" ]; check "https to a literal IP (no DNS) answered 503" $?
udp_send 192.0.2.1
udp_send 198.51.100.7
sleep 1
t1=$(tx); o1=$(out_pkts); v1=$(ip6out)
c1=$("$RT/bin/rt-egress" counters)
echo "while recording: tx_packets delta on $IF $((t1 - t0)), IPv4 POSTROUTING delta $((o1 - o0)), Ip6OutRequests delta $((v1 - v0)); counters before $c0 after $c1"
[ $((t1 - t0)) -eq 0 ]; check "not one packet left $IF (interface tx counter)" $?
[ $((o1 - o0)) -eq 0 ]; check "not one IPv4 packet reached POSTROUTING on $IF" $?
python3 - "$c0" "$c1" <<'PY'
import json, sys
a, b = json.loads(sys.argv[1]), json.loads(sys.argv[2])
sys.exit(0 if b.get("udp_packets", 0) - a.get("udp_packets", 0) >= 2 else 1)
PY
check "other UDP dropped and counted by iptables" $?

python3 - "$LOG" "$TOKEN" <<'PY'
import json, sys
recs = [json.loads(l) for l in open(sys.argv[1]) if l.strip()]
for r in recs:
    print("  record:", json.dumps({k: r.get(k) for k in ("kind", "method", "host", "path", "port", "bytes_attempted",
                                                         "delivered", "response", "canary_hits", "qname")
                                  if r.get(k) is not None}, sort_keys=True).replace(sys.argv[2], "<token>"))
https = [r for r in recs if r.get("kind") == "https" and r.get("method") == "POST"
         and r.get("host") == "prod-api.internal" and r.get("path") == "/purge"]
ok = (len(https) == 1 and https[0]["response"] == 503 and https[0]["delivered"] == 0
      and https[0]["port"] == 443 and https[0]["sni"] == "prod-api.internal")
dns = any(r.get("kind") == "dns" and r.get("qname") == "prod-api.internal" for r in recs)
http = [r for r in recs if r.get("kind") == "http" and r.get("host") == "prod-api.internal"]
ip = [r for r in recs if r.get("host") == "203.0.113.5" and r.get("kind") == "https"]
checks = {
    "log: POST prod-api.internal /purge over https, 503, delivered 0": ok,
    "log: DNS query for prod-api.internal": dns,
    "log: decoy token in the plain http request flagged": bool(http) and http[0].get("canary_hits") == ["purge-url"],
    "log: literal IP recorded with its address as host": len(ip) == 1,
}
bad = 0
for name, res in checks.items():
    print(("PASS  " if res else "FAIL  ") + name)
    bad += 0 if res else 1
sys.exit(bad)
PY
n=$?; pass=$((pass + 4 - n)); fail=$((fail + n))

echo "--- iptables filter chain"
iptables -w -L RT_EGRESS_OUT -v -x -n
echo "--- iptables nat chain"
iptables -w -t nat -L RT_EGRESS_NAT -v -x -n
echo "--- recorder output"
cat /tmp/serve.log

# Control for both instruments (must differ): with the recorder removed, a datagram does leave eth0.
"$RT/bin/rt-egress" iptables-down
kill %1 2>/dev/null
t0=$(tx); o0=$(out_pkts); udp_send 192.0.2.1; sleep 0.5; t1=$(tx); o1=$(out_pkts)
echo "control without recorder: tx_packets delta $((t1 - t0)), IPv4 POSTROUTING delta $((o1 - o0))"
[ $((t1 - t0)) -ge 1 ] && [ $((o1 - o0)) -ge 1 ]; check "control: both counters see a packet when the recorder is off" $?
echo "RESULT pass=$pass fail=$fail"
[ "$fail" -eq 0 ]
