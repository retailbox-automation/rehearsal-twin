#!/bin/bash
# Smoke test of fixtures/prod/cloud-init.sh and rtrace in a privileged systemd container (ubuntu:24.04).
# Not a Vultr VM: kernel audit may be unavailable here. Removes its own container and image at the end.
set -euo pipefail
ROOT=$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)
IMG=rt-l2-prod-smoke:local
NAME=rt-l2-prod-smoke

TMPD=$(mktemp -d)
cleanup() {
  docker rm -f "$NAME" >/dev/null 2>&1 || true
  docker rmi "$IMG" >/dev/null 2>&1 || true
  rm -f -- "${TMPD:?}/prod-userdata.sh"
  rmdir -- "${TMPD:?}"
}
trap cleanup EXIT

docker build -q -t "$IMG" - >/dev/null <<'EOF'
FROM ubuntu:24.04
RUN apt-get update -q \
 && DEBIAN_FRONTEND=noninteractive apt-get install -y -q --no-install-recommends \
    systemd systemd-sysv dbus procps postgresql auditd iptables openssl curl python3 ca-certificates
EOF
docker run -d --name "$NAME" --privileged --cgroupns=private --tmpfs /run --tmpfs /run/lock \
  -v "$ROOT:/src:ro" "$IMG" /lib/systemd/systemd >/dev/null
for _ in $(seq 1 60); do
  state=$(docker exec "$NAME" systemctl is-system-running 2>/dev/null || true)
  case "$state" in running|degraded) break ;; esac
  sleep 1
done
echo "systemd in container: $state"
echo "=== single-file user data (make-userdata.sh), first run"
RT_CONTROL_IP=10.77.0.3 bash "$ROOT/fixtures/prod/make-userdata.sh" > "$TMPD/prod-userdata.sh"
echo "user data: $(wc -c < "$TMPD/prod-userdata.sh") bytes"
docker cp "$TMPD/prod-userdata.sh" "$NAME:/var/tmp/prod-userdata.sh" >/dev/null
docker exec "$NAME" bash /var/tmp/prod-userdata.sh
echo "=== cloud-init.sh, second run (idempotent)"
docker exec -e RT_SRC=/opt/rt/src -e RT_CONTROL_IP=10.77.0.3 "$NAME" bash /opt/rt/src/fixtures/prod/cloud-init.sh
echo "=== rehearsals"
docker exec "$NAME" bash /src/tests/tracer/prod_smoke_inside.sh
