#!/bin/bash
# Smoke test of deploy/control.sh in a privileged systemd container (ubuntu:24.04): install twice (idempotent),
# health through uvicorn and through Caddy on :80, live mode without settings answers 503, env file mode 600.
# Not a Vultr VM and no TLS (no RT_DOMAIN). Removes its own container and image at the end.
set -euo pipefail
ROOT=$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)
IMG=rt-lg-control-smoke:local
NAME=rt-lg-control-smoke

cleanup() {
  docker rm -f "$NAME" >/dev/null 2>&1 || true
  docker rmi "$IMG" >/dev/null 2>&1 || true
}
trap cleanup EXIT

docker build -q -t "$IMG" - >/dev/null <<'EOF'
FROM ubuntu:24.04
RUN apt-get update -q \
 && DEBIAN_FRONTEND=noninteractive apt-get install -y -q --no-install-recommends \
    systemd systemd-sysv dbus procps iproute2 ca-certificates curl
EOF
docker run -d --name "$NAME" --privileged --cgroupns=private --tmpfs /run --tmpfs /run/lock \
  -v "$ROOT:/src:ro" "$IMG" /lib/systemd/systemd >/dev/null
state=""
for _ in $(seq 1 60); do
  state=$(docker exec "$NAME" systemctl is-system-running 2>/dev/null || true)
  case "$state" in running|degraded) break ;; esac
  sleep 1
done
echo "systemd in container: $state"

echo "=== control.sh, first run"
docker exec -e RT_SRC=/src "$NAME" bash /src/deploy/control.sh
echo "=== control.sh, second run (idempotent)"
docker exec -e RT_SRC=/src "$NAME" bash /src/deploy/control.sh

fails=0
check() {  # check NAME EXPECTED ACTUAL
  if [ "$2" = "$3" ]; then echo "PASS  $1"; else echo "FAIL  $1  [expected '$2', got '$3']"; fails=$((fails + 1)); fi
}
run() { docker exec "$NAME" bash -c "$1"; }
check "uvicorn health on 127.0.0.1:8000" '{"status":"ok"}' "$(run 'curl -fsS http://127.0.0.1:8000/api/health')"
check "health through Caddy on :80" '{"status":"ok"}' "$(run 'curl -fsS http://127.0.0.1/api/health')"
check "screen through Caddy" "1" "$(run 'curl -fsS http://127.0.0.1/ | grep -c "<title>Rehearsal Twin"')"
check "live mode without settings: POST answers 503" "503" \
  "$(run "curl -s -o /dev/null -w '%{http_code}' -X POST -H 'Content-Type: application/json' -d '{\"preset\":\"a\"}' http://127.0.0.1/api/rehearsals")"
check "env file root-only" "600 root" "$(run 'stat -c "%a %U" /etc/rt/env')"
check "service user" "User=rt" "$(run 'systemctl show rt-api -p User')"
check "uvicorn bound to loopback only" "127.0.0.1:8000" "$(run "ss -ltnH | awk '{print \$4}' | grep ':8000\$'")"
check "data dir private to rt" "700 rt" "$(run 'stat -c "%a %U" /var/lib/rt')"
check "reaper timer active" "active" "$(run 'systemctl is-active rt-reaper.timer')"
check "reset timer active" "active" "$(run 'systemctl is-active rt-prod-reset.timer')"
run 'systemctl start rt-reaper.service' >/dev/null 2>&1 || true
check "reaper: one journal line per tick (no API key here: an error line)" "1" \
  "$(run "journalctl -u rt-reaper.service -o cat --no-pager | grep -c '\"tick\": \"reap\"'")"
run 'systemctl start rt-prod-reset.service' >/dev/null 2>&1 || true
check "reset: one journal line per tick (no token here: an error line)" "1" \
  "$(run "journalctl -u rt-prod-reset.service -o cat --no-pager | grep -c '\"tick\": \"restore\"'")"
echo "RESULT fails=$fails"
[ "$fails" -eq 0 ]
