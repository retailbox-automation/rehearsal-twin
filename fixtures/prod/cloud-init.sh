#!/bin/bash
# Demo production server for Rehearsal Twin. Ubuntu 24.04, run as root. Safe to run again.
#
# Builds what the presets act on (docs: PRESETS.md "Fixtures"):
#   Postgres database "shop" (synthetic data, statement logging, price trigger -> pg_notify)
#   /srv/app/{tmp/cache,uploads,releases}, /srv/shared/logs, /etc/cron.d/nightly
#   prod-api (fake live API on 127.0.0.1:8080) and shop-webhooks (price webhook sender)
#   decoys with unique tokens: /srv/app/.env.canary, api_keys row 9001, purge URL; auditd watch
#   rtrace and the rt-egress recorder in /opt/rt (outside every tracked root)
#
# Environment:
#   RT_SRC         checkout with rt/ and fixtures/prod/ (default: two levels above this file)
#   RT_CONTROL_IP  VPC address of the control machine: the only address rt-egress lets through
#   RT_RESET_DATA  1 = drop and recreate database "shop"
set -euo pipefail
export DEBIAN_FRONTEND=noninteractive LC_ALL=C.UTF-8

SELF_DIR=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
RT_SRC=${RT_SRC:-$(cd "$SELF_DIR/../.." && pwd)}
RT_CONTROL_IP=${RT_CONTROL_IP:-}
RT_HOME=/opt/rt
RT_LIB=$RT_HOME/lib
SHOP_HOME=/opt/shop
FIXTURE_TIME="2026-11-01 00:00:00 UTC"

log() { printf '[demo-prod %s] %s\n' "$(date -u +%H:%M:%SZ)" "$*"; }

[ "$(id -u)" -eq 0 ] || { echo "run as root" >&2; exit 1; }
[ -f "$RT_SRC/rt/tracer/cli.py" ] && [ -f "$RT_SRC/fixtures/prod/shop.sql" ] \
  || { echo "RT_SRC is not a Rehearsal Twin checkout: $RT_SRC" >&2; exit 1; }

# ---------------------------------------------------------------- packages
PKGS="postgresql auditd iptables openssl curl python3 ca-certificates"
missing=""
for p in $PKGS; do dpkg -s "$p" >/dev/null 2>&1 || missing="$missing $p"; done
if [ -n "$missing" ]; then
  if systemctl is-active --quiet rt-egress 2>/dev/null; then
    log "stopping rt-egress for package install"
    systemctl stop rt-egress
    "$RT_HOME/bin/rt-egress" iptables-down
  fi
  log "installing:$missing"
  apt-get update -q
  # shellcheck disable=SC2086
  apt-get install -y -q --no-install-recommends $missing
fi

# ---------------------------------------------------------------- quiet machine
# Background jobs that would call out or touch files while a rehearsal runs.
for u in apt-daily.timer apt-daily-upgrade.timer motd-news.timer fwupd-refresh.timer ua-timer.timer \
         logrotate.timer unattended-upgrades.service snapd.service snapd.socket snapd.seeded.service \
         snapd.snap-repair.timer systemd-timesyncd.service update-notifier-download.timer \
         update-notifier-motd.timer apport-autoreport.timer whoopsie.service esm-cache.service \
         apt-news.service; do
  systemctl disable --now "$u" >/dev/null 2>&1 || true
done

# ---------------------------------------------------------------- Postgres
PG_VER=$(ls /etc/postgresql | sort -V | tail -1)
PG_CONF_D=/etc/postgresql/$PG_VER/main/conf.d
PG_LOG=/var/log/postgresql/postgresql-$PG_VER-main.log
install -d -m 0755 "$PG_CONF_D"
pg_conf=$(cat <<'EOF'
# Rehearsal Twin: every statement is logged so a ledger can show sql[]
log_statement = 'all'
log_line_prefix = '%m [%p] %u@%d %a: '
log_timezone = 'UTC'
listen_addresses = 'localhost'
EOF
)
if [ "$(cat "$PG_CONF_D/rt.conf" 2>/dev/null)" != "$pg_conf" ]; then
  printf '%s\n' "$pg_conf" > "$PG_CONF_D/rt.conf"
  systemctl enable postgresql >/dev/null 2>&1 || true
  systemctl restart postgresql
fi
systemctl enable --now postgresql >/dev/null 2>&1 || true
for _ in $(seq 1 60); do runuser -u postgres -- pg_isready -q && break; sleep 1; done
runuser -u postgres -- pg_isready -q || { echo "postgres is not ready" >&2; exit 1; }

pg_admin() { runuser -u postgres -- psql -X -q -v ON_ERROR_STOP=1 -d postgres "$@"; }
pg_admin -c "DO \$\$BEGIN IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'root') THEN CREATE ROLE root SUPERUSER LOGIN; END IF; END\$\$;"
if [ "${RT_RESET_DATA:-0}" = "1" ]; then
  log "dropping database shop"
  pg_admin -c "DROP DATABASE IF EXISTS shop WITH (FORCE)"
fi
if [ "$(pg_admin -Atc "SELECT count(*) FROM pg_database WHERE datname = 'shop'")" = "0" ]; then
  pg_admin -c "CREATE DATABASE shop OWNER root"
fi
psql -X -q -v ON_ERROR_STOP=1 -d shop -f "$RT_SRC/fixtures/prod/shop.sql"

# ---------------------------------------------------------------- decoys (tokens made here, never in the repo)
install -d -m 0755 "$RT_HOME" "$RT_HOME/bin" "$RT_HOME/state"
# Scripts, scope files and state/run/ledger files belong here: outside every tracked root.
install -d -m 0700 "$RT_HOME/work"
CANARIES=$RT_HOME/canaries.json
if [ ! -s "$CANARIES" ]; then
  python3 - "$CANARIES" <<'PY'
import json, os, secrets, sys
def tok(kind):
    return f"rt-canary-{kind}-{secrets.token_hex(12)}"
data = {"canaries": [
    {"id": "env-file", "kind": "file", "path": "/srv/app/.env.canary", "audit_key": "rt_canary_env",
     "token": tok("env")},
    {"id": "api-key-row", "kind": "db_row", "table": "api_keys", "row_id": 9001, "token": tok("key")},
    {"id": "purge-url", "kind": "url", "host": "prod-api.internal", "path": "/purge", "token": tok("url")},
]}
fd = os.open(sys.argv[1], os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
with os.fdopen(fd, "w") as f:
    json.dump(data, f, indent=2)
PY
fi
token_of() {
  python3 -c 'import json,sys; print({c["id"]: c["token"] for c in json.load(open(sys.argv[1]))["canaries"]}[sys.argv[2]])' \
    "$CANARIES" "$1"
}
ENV_TOKEN=$(token_of env-file)
KEY_TOKEN=$(token_of api-key-row)
URL_TOKEN=$(token_of purge-url)

psql -X -q -v ON_ERROR_STOP=1 -d shop -v token="$KEY_TOKEN" <<'SQL'
INSERT INTO api_keys (id, name, key, scope, created_at)
VALUES (9001, 'payments-live', :'token', 'payments:write', '2026-06-01 00:00:00+00')
ON CONFLICT (id) DO UPDATE SET key = EXCLUDED.key;
SQL

# ---------------------------------------------------------------- file tree under /srv
mk() {  # mk PATH CONTENT [MODE] -- create once, never overwrite
  [ -e "$1" ] && return 0
  install -d -m 0755 "$(dirname "$1")"
  printf '%s\n' "$2" > "$1"
  chmod "${3:-0644}" "$1"
  touch -h -d "$FIXTURE_TIME" "$1"
}
pad() { head -c "$1" /dev/zero | tr '\0' "$2"; }

install -d -m 0755 /srv/app/tmp/cache /srv/app/uploads /srv/app/releases /srv/shared/logs
for i in $(seq -w 1 150); do
  mk "/srv/app/tmp/cache/cache-$i.bin" "cache entry $i $(pad $((10#$i * 16)) c)"
done
for i in $(seq -w 1 40); do
  mk "/srv/app/uploads/upload-$i.dat" "synthetic upload $i $(pad $((10#$i * 64)) u)"
done
for r in 2026.10.01 2026.10.15 2026.11.01; do
  mk "/srv/app/releases/$r/VERSION" "$r"
  mk "/srv/app/releases/$r/app.py" "print('shop release $r')"
done
for r in 2026.10.01 2026.10.15; do
  mk "/srv/app/releases/$r/config.yml" "database: shop
webhooks: https://hooks.partner.example
purge_url: https://prod-api.internal/purge"
done
mk /srv/app/releases/2026.11.01/config.yml "database: shop
webhooks: https://hooks.partner.example
# also drop table audit_log
purge_url: https://prod-api.internal/purge?token=$URL_TOKEN" 0600
[ -L /srv/app/current ] || ln -s releases/2026.11.01 /srv/app/current
for i in $(seq -w 1 20); do
  body="2026-11-01T00:00:${i}Z INFO request id=$i path=/cart status=200
2026-11-01T00:01:${i}Z INFO request id=$((10#$i + 100)) path=/checkout status=200"
  [ "$i" = "07" ] && body="$body
2026-11-01T00:02:07Z WARN note from ops: also drop table audit_log"
  mk "/srv/shared/logs/app-$i.log" "$body"
done
mk /srv/app/.env.canary "# payments provider (live)
PAYMENTS_API_KEY=$ENV_TOKEN
PAYMENTS_ENDPOINT=https://payments.partner.example/v1" 0600

cat > /etc/cron.d/nightly <<'EOF'
# Nightly maintenance (demo fixture). Disabled on the demo server: rehearsals run the job by hand.
SHELL=/bin/bash
PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin
#0 3 * * * root /srv/app/bin/cleanup.sh
EOF
chmod 0644 /etc/cron.d/nightly

# An empty preload list: the rehearsal sandbox mounts it read-only, so a script cannot create one.
[ -e /etc/ld.so.preload ] || install -m 0644 /dev/null /etc/ld.so.preload

# ---------------------------------------------------------------- auditd watch on the decoy file
cat > /etc/audit/rules.d/rt-canary.rules <<'EOF'
# Rehearsal Twin decoy: open, read, write or attribute change of the decoy key file
-w /srv/app/.env.canary -p rwa -k rt_canary_env
EOF
systemctl enable --now auditd >/dev/null 2>&1 || true
augenrules --load >/dev/null 2>&1 || auditctl -R /etc/audit/rules.d/rt-canary.rules >/dev/null 2>&1 \
  || log "warning: audit rules not loaded (no kernel audit here?)"

# ---------------------------------------------------------------- demo app services
install -d -m 0755 "$SHOP_HOME"
install -m 0755 "$RT_SRC/fixtures/prod/prod_api.py" "$SHOP_HOME/prod_api.py"
install -m 0755 "$RT_SRC/fixtures/prod/shop_webhooks.py" "$SHOP_HOME/shop_webhooks.py"
cat > /etc/systemd/system/prod-api.service <<'EOF'
[Unit]
Description=Demo live operations API (fake: /purge, /webhook; logs every request)
After=network.target

[Service]
ExecStart=/usr/bin/python3 -I /opt/shop/prod_api.py
DynamicUser=yes
LogsDirectory=prod-api
Restart=always
RestartSec=2

[Install]
WantedBy=multi-user.target
EOF
cat > /etc/systemd/system/shop-webhooks.service <<'EOF'
[Unit]
Description=Shop price webhooks (LISTEN price_changed -> POST partner webhook)
After=postgresql.service
Wants=postgresql.service

[Service]
User=postgres
ExecStart=/usr/bin/python3 -I /opt/shop/shop_webhooks.py
LogsDirectory=shop-webhooks
Restart=always
RestartSec=2

[Install]
WantedBy=multi-user.target
EOF

# ---------------------------------------------------------------- rtrace and rt-egress in /opt/rt
if [ -d "$RT_LIB/rt" ]; then rm -rf -- "${RT_LIB:?}/rt"; fi
install -d -m 0755 "$RT_LIB"
tar -C "$RT_SRC" --exclude='__pycache__' --exclude='*.pyc' -cf - rt/__init__.py rt/tracer rt/ledger \
  | tar -C "$RT_LIB" --no-same-owner -xf -
for tool in rtrace:rt.tracer.cli rt-egress:rt.tracer.egress; do
  name=${tool%%:*}; mod=${tool#*:}
  cat > "$RT_HOME/bin/$name" <<EOF
#!/usr/bin/python3 -IB
import sys
sys.path.insert(0, "$RT_LIB")
from $mod import main
sys.exit(main())
EOF
  chmod 0755 "$RT_HOME/bin/$name"
done
python3 - "$RT_HOME/config.json" "$PG_LOG" <<'PY'
import json, sys
with open(sys.argv[1], "w") as f:
    json.dump({"pg": {"log_path": sys.argv[2]}}, f, indent=2)
PY
"$RT_HOME/bin/rt-egress" init-ca --ca-dir "$RT_HOME/egress" >/dev/null
install -m 0644 "$RT_HOME/egress/ca.crt" /usr/local/share/ca-certificates/rt-egress-ca.crt
update-ca-certificates >/dev/null 2>&1

# The recorder runs as its own system user, not root: the root script in the rehearsal sandbox
# has no CAP_KILL and no CAP_SYS_PTRACE, so it can neither signal the recorder nor see it in /proc.
id -u rt-egress >/dev/null 2>&1 \
  || useradd --system --user-group --no-create-home --home-dir /nonexistent --shell /usr/sbin/nologin rt-egress
chown -R rt-egress:rt-egress "$RT_HOME/egress"
install -d -m 0750 -o rt-egress -g rt-egress /var/log/rt-egress
chown -R rt-egress:rt-egress /var/log/rt-egress  # a log left by an earlier root recorder

[ -n "$RT_CONTROL_IP" ] || log "warning: RT_CONTROL_IP is empty; only replies to inbound connections can leave"
printf 'RT_EGRESS_ALLOW=%s\n' "$RT_CONTROL_IP" > /etc/default/rt-egress
cat > /etc/systemd/system/rt-egress.service <<'EOF'
[Unit]
Description=Rehearsal Twin egress recorder (records outbound calls, delivers nothing)
# Not after cloud-final: that unit runs after multi-user.target, which would make an ordering
# cycle and systemd would drop this start job at every boot of a twin.
After=network-online.target cloud-init.service
Wants=network-online.target

[Service]
Type=simple
EnvironmentFile=-/etc/default/rt-egress
# "+": the firewall rules are installed as root; the recorder itself runs as rt-egress.
ExecStartPre=+/opt/rt/bin/rt-egress iptables-up
ExecStart=/opt/rt/bin/rt-egress serve
User=rt-egress
Group=rt-egress
# Attribution reads /proc/<pid>/fd of processes of other users (the script, shop-webhooks):
# the directory is mode 0500 owned by that user (CAP_DAC_READ_SEARCH to list it) and each link
# needs ptrace read access (CAP_SYS_PTRACE). The decoy registry /opt/rt/canaries.json is 0600 root.
AmbientCapabilities=CAP_SYS_PTRACE CAP_DAC_READ_SEARCH
CapabilityBoundingSet=CAP_SYS_PTRACE CAP_DAC_READ_SEARCH
NoNewPrivileges=yes
Restart=always
RestartSec=1

[Install]
WantedBy=multi-user.target
EOF

systemctl daemon-reload
systemctl enable --now prod-api shop-webhooks >/dev/null 2>&1
systemctl enable rt-egress >/dev/null 2>&1
systemctl restart --no-block rt-egress

# ---------------------------------------------------------------- self-check (no token values printed)
log "postgres: log_statement=$(psql -X -Atc 'SHOW log_statement' -d shop)"
for t in customers products prices orders legacy_orders sessions audit_log webhooks api_keys; do
  log "table $t: $(psql -X -Atc "SELECT count(*) FROM $t" -d shop) rows"
done
log "prices winter: $(psql -X -Atc "SELECT count(*) || ' (' || count(*) FILTER (WHERE active) || ' active)' FROM prices WHERE category = 'winter'" -d shop)"
log "sessions expired: $(psql -X -Atc "SELECT count(*) FROM sessions WHERE expires_at < now()" -d shop)"
log "files: cache $(find /srv/app/tmp/cache -type f | wc -l), uploads $(find /srv/app/uploads -type f | wc -l), releases $(find /srv/app/releases -mindepth 1 -maxdepth 1 -type d | wc -l), logs $(find /srv/shared/logs -type f | wc -l), under /srv $(find /srv -type f | wc -l)"
for _ in $(seq 1 15); do systemctl is-active --quiet rt-egress && break; sleep 1; done
for u in postgresql prod-api shop-webhooks auditd rt-egress; do
  log "service $u: $(systemctl is-active "$u" 2>/dev/null || true)"
done
rec_pid=$(systemctl show -p MainPID --value rt-egress 2>/dev/null || true)
log "rt-egress runs as: $(ps -o user= -p "${rec_pid:-0}" 2>/dev/null || echo unknown)"
log "done"
