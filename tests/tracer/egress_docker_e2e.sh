#!/bin/bash
# Egress recorder acceptance in Docker: ubuntu:24.04 with NET_ADMIN, repository mounted read-only.
# Removes its own container and image at the end.
set -euo pipefail
ROOT=$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)
IMG=rt-l2-egress-e2e:local
NAME=rt-l2-egress-e2e

cleanup() {
  docker rm -f "$NAME" >/dev/null 2>&1 || true
  docker rmi "$IMG" >/dev/null 2>&1 || true
}
trap cleanup EXIT

docker build -q -t "$IMG" - >/dev/null <<'EOF'
FROM ubuntu:24.04
RUN apt-get update -q \
 && DEBIAN_FRONTEND=noninteractive apt-get install -y -q --no-install-recommends \
    python3 iptables curl openssl ca-certificates
EOF
docker run --name "$NAME" --cap-add NET_ADMIN -v "$ROOT:/src:ro" "$IMG" bash /src/tests/tracer/egress_e2e_inside.sh
