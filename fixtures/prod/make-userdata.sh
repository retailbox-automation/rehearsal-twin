#!/bin/bash
# Build one self-contained user-data script for the demo production server:
# it carries rt/ and fixtures/prod/ and runs fixtures/prod/cloud-init.sh.
#
#   RT_CONTROL_IP=10.77.0.3 fixtures/prod/make-userdata.sh > prod-userdata.sh
set -euo pipefail
ROOT=$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)
CONTROL_IP=${RT_CONTROL_IP:-}
if [ -n "$CONTROL_IP" ] && ! [[ "$CONTROL_IP" =~ ^[0-9.,\ /]+$ ]]; then
  echo "RT_CONTROL_IP must be an IPv4 address list" >&2
  exit 1
fi
payload=$(python3 - "$ROOT" <<'PY'
import base64, io, os, sys, tarfile
root = sys.argv[1]
def clean(ti):
    if "__pycache__" in ti.name or ti.name.endswith((".pyc", ".DS_Store")):
        return None
    ti.uid = ti.gid = 0
    ti.uname = ti.gname = "root"
    return ti
buf = io.BytesIO()
with tarfile.open(fileobj=buf, mode="w:gz") as tar:
    for rel in ("rt/__init__.py", "rt/tracer", "rt/ledger", "fixtures/prod"):
        tar.add(os.path.join(root, rel), arcname=rel, filter=clean)
sys.stdout.write(base64.b64encode(buf.getvalue()).decode())
PY
)
cat <<EOF
#!/bin/bash
set -euo pipefail
install -d -m 0700 /opt/rt/src
echo '$payload' | base64 -d | tar -C /opt/rt/src --no-same-owner -xzf -
RT_SRC=/opt/rt/src RT_CONTROL_IP='$CONTROL_IP' bash /opt/rt/src/fixtures/prod/cloud-init.sh
EOF
