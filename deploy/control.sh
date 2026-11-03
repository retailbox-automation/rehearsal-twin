#!/bin/bash
# Control machine for Rehearsal Twin: API, screen and orchestrator (uvicorn on 127.0.0.1) behind Caddy with TLS.
# Ubuntu 24.04, run as root. Safe to run again.
#
# Secrets are not created, read or printed here. The operator fills /etc/rt/env (mode 600, root only;
# systemd reads it before dropping to the service user) and puts the SSH key for twins and the demo
# production server at the path named by RT_SSH_KEY_FILE (readable by user "rt"). This script only
# checks that the names are present.
#
#   RT_DOMAIN=twin.example.com bash deploy/control.sh
#
# Environment:
#   RT_DOMAIN  public name for the TLS certificate (its DNS must already point here); empty = plain HTTP on :80
#   RT_SRC     checkout to install from (default: two levels above this file)
#   RT_PORT    uvicorn port on 127.0.0.1 (default 8000)
set -euo pipefail
export DEBIAN_FRONTEND=noninteractive LC_ALL=C.UTF-8

SELF_DIR=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
RT_SRC=${RT_SRC:-$(cd "$SELF_DIR/.." && pwd)}
RT_DOMAIN=${RT_DOMAIN:-}
RT_PORT=${RT_PORT:-8000}
APP_HOME=/opt/rt-control
APP_DIR=$APP_HOME/app
VENV=$APP_HOME/venv
DATA_DIR=/var/lib/rt
ENV_DIR=/etc/rt
ENV_FILE=$ENV_DIR/env
SVC=rt-api
SVC_USER=rt
# Versions the test suite ran with.
PY_DEPS="fastapi==0.128.5 uvicorn==0.42.0 cryptography==46.0.6"
# Names the live API needs (rt/orchestrator/settings.py LIVE_REQUIRED).
REQUIRED="VULTR_API_KEY VULTR_INFERENCE_API_KEY RT_RECEIPT_SIGNING_KEY RT_SSH_KEY_FILE RT_GOLDEN_SNAPSHOT_ID RT_VPC_ID RT_PROD_INSTANCE_ID"

log() { printf '[control %s] %s\n' "$(date -u +%H:%M:%SZ)" "$*"; }

[ "$(id -u)" -eq 0 ] || { echo "run as root" >&2; exit 1; }
[ -f "$RT_SRC/rt/api/app.py" ] && [ -d "$RT_SRC/presets" ] && [ -d "$RT_SRC/web" ] \
  || { echo "RT_SRC is not a Rehearsal Twin checkout: $RT_SRC" >&2; exit 1; }
[[ "$RT_PORT" =~ ^[0-9]{2,5}$ ]] || { echo "RT_PORT must be a port number" >&2; exit 1; }
if [ -n "$RT_DOMAIN" ] && ! [[ "$RT_DOMAIN" =~ ^[A-Za-z0-9]([A-Za-z0-9.-]{0,251}[A-Za-z0-9])?$ ]]; then
  echo "RT_DOMAIN must be a host name" >&2
  exit 1
fi

# ---------------------------------------------------------------- packages
PKGS="python3 python3-venv caddy openssh-client ca-certificates curl"
missing=""
for p in $PKGS; do dpkg -s "$p" >/dev/null 2>&1 || missing="$missing $p"; done
if [ -n "$missing" ]; then
  log "installing:$missing"
  apt-get update -q
  # shellcheck disable=SC2086
  apt-get install -y -q --no-install-recommends $missing
fi

# ---------------------------------------------------------------- user and directories
id -u "$SVC_USER" >/dev/null 2>&1 \
  || useradd --system --home-dir "$DATA_DIR" --no-create-home --shell /usr/sbin/nologin "$SVC_USER"
install -d -m 0755 "$APP_HOME"
install -d -m 0700 -o "$SVC_USER" -g "$SVC_USER" "$DATA_DIR" "$DATA_DIR/ssh"
install -d -m 0750 -o root -g "$SVC_USER" "$ENV_DIR"
install -d -m 0700 -o "$SVC_USER" -g "$SVC_USER" "$ENV_DIR/ssh"
[ -e "$ENV_FILE" ] || install -m 0600 -o root -g root /dev/null "$ENV_FILE"
chown root:root "$ENV_FILE"
chmod 0600 "$ENV_FILE"

# ---------------------------------------------------------------- code (a clean copy; runs from source)
STAGE=$(mktemp -d "$APP_HOME/.stage.XXXXXX")
tar -C "$RT_SRC" --exclude='__pycache__' --exclude='*.pyc' --exclude='.DS_Store' \
    -cf - rt web presets pyproject.toml README.md LICENSE | tar -C "$STAGE" --no-same-owner -xf -
chmod -R u=rwX,go=rX "$STAGE"
if [ -d "$APP_DIR" ]; then rm -rf -- "${APP_DIR:?}"; fi
mv "$STAGE" "$APP_DIR"
log "code installed from $RT_SRC ($(git -C "$RT_SRC" rev-parse --short HEAD 2>/dev/null || echo 'no git'))"

# ---------------------------------------------------------------- python venv
[ -x "$VENV/bin/python" ] || python3 -m venv "$VENV"
# shellcheck disable=SC2086
"$VENV/bin/pip" install -q --disable-pip-version-check $PY_DEPS

# ---------------------------------------------------------------- env file check (names only, never values)
absent=""
for n in $REQUIRED; do grep -q "^$n=." "$ENV_FILE" || absent="$absent $n"; done
if [ -n "$absent" ]; then
  log "warning: $ENV_FILE lacks:$absent (the API starts; rehearsals answer 503 until they are set)"
fi
key_path=$(sed -n 's/^RT_SSH_KEY_FILE=//p' "$ENV_FILE" | tail -1)
if [ -n "$key_path" ] && ! runuser -u "$SVC_USER" -- test -r "$key_path"; then
  log "warning: RT_SSH_KEY_FILE is not readable by user $SVC_USER (suggested place: $ENV_DIR/ssh/, mode 600)"
fi

# ---------------------------------------------------------------- systemd unit
cat > "/etc/systemd/system/$SVC.service" <<EOF
[Unit]
Description=Rehearsal Twin API, screen and orchestrator
After=network-online.target
Wants=network-online.target

[Service]
User=$SVC_USER
Group=$SVC_USER
Environment=RT_MODE=live RT_DATA_DIR=$DATA_DIR PYTHONDONTWRITEBYTECODE=1
EnvironmentFile=$ENV_FILE
WorkingDirectory=$APP_DIR
ExecStart=$VENV/bin/uvicorn rt.api.app:app --app-dir $APP_DIR --host 127.0.0.1 --port $RT_PORT --proxy-headers --forwarded-allow-ips 127.0.0.1 --no-server-header
Restart=on-failure
RestartSec=2
UMask=0077
NoNewPrivileges=yes
PrivateTmp=yes
ProtectSystem=strict
ProtectHome=yes
ReadWritePaths=$DATA_DIR
ProtectKernelTunables=yes
ProtectKernelModules=yes
ProtectControlGroups=yes
RestrictSUIDSGID=yes
LockPersonality=yes

[Install]
WantedBy=multi-user.target
EOF
systemctl daemon-reload
systemctl enable "$SVC" >/dev/null 2>&1
systemctl restart "$SVC"

# ---------------------------------------------------------------- Caddy (TLS for RT_DOMAIN; SSE needs flush_interval -1)
if [ -n "$RT_DOMAIN" ]; then SITE=$RT_DOMAIN; else SITE=":80"; fi
caddyfile=$(cat <<EOF
$SITE {
	reverse_proxy 127.0.0.1:$RT_PORT {
		flush_interval -1
	}
	header {
		X-Content-Type-Options nosniff
		Referrer-Policy no-referrer
		-Server
	}
}
EOF
)
if [ "$(cat /etc/caddy/Caddyfile 2>/dev/null)" != "$caddyfile" ]; then
  printf '%s\n' "$caddyfile" > /etc/caddy/Caddyfile.new
  caddy validate --config /etc/caddy/Caddyfile.new --adapter caddyfile >/dev/null
  mv /etc/caddy/Caddyfile.new /etc/caddy/Caddyfile
fi
systemctl enable caddy >/dev/null 2>&1
systemctl reload-or-restart caddy

# ---------------------------------------------------------------- self-check
ok=""
for _ in $(seq 1 30); do
  if curl -fsS "http://127.0.0.1:$RT_PORT/api/health" >/dev/null 2>&1; then ok=1; break; fi
  sleep 1
done
health="NO ANSWER"
[ -z "$ok" ] || health="ok"
log "service $SVC: $(systemctl is-active "$SVC" 2>/dev/null || true), health on 127.0.0.1:$RT_PORT: $health"
log "service caddy: $(systemctl is-active caddy 2>/dev/null || true), site $SITE"
[ -n "$ok" ] || { journalctl -u "$SVC" -n 30 --no-pager >&2 || true; exit 1; }
log "done"
