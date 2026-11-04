#!/bin/bash
. /opt/rt/work/target.env
pid=$(pgrep -o -f '[r]t-egress serve')
echo "recorder pid=${pid:-none}"
[ -n "$pid" ] && kill -STOP "$pid" && echo stopped
curl -s -m 2 -d 'while stopped' "http://$SINK_IP:8080/e02d-stopped" || true
[ -n "$pid" ] && kill -CONT "$pid" && echo continued
sleep 3
