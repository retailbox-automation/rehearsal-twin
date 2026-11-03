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
rehearse migrate "$W/migrate_0042.sh" '{"tables": ["legacy_orders"]}' || echo "rehearse migrate failed"
# Escape attempts from inside the sandbox: each must fail, the in-scope delete must work.
cat > "$W/escape.sh" <<'EOF'
iptables -F 2>&1; echo "R iptables=$?"
iptables -t nat -F 2>&1; echo "R iptables_nat=$?"
ip route add 203.0.113.0/24 via 127.0.0.1 2>&1; echo "R route=$?"
systemd-run --wait --quiet /bin/true 2>&1; echo "R systemd_run=$?"
systemctl stop rt-egress 2>&1; echo "R systemctl=$?"
echo '* * * * * root iptables -F' > /etc/cron.d/rt-escape; echo "R cron=$?"
echo 'iptables -F' >> /root/.bashrc; echo "R bashrc=$?"
echo /tmp/x.so > /etc/ld.so.preload; echo "R preload=$?"
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
rehearse escape "$W/escape.sh" '{"paths": ["/srv/app/tmp"], "tables": [], "hosts": []}' || echo "rehearse escape failed"

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

for name in ("reprice", "safe1", "safe2", "migrate", "cleanup"):
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
check("cleanup: the 141 cache files left after the escape run deleted (in scope)", len(in_tmp) == 141,
      len(in_tmp))
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
