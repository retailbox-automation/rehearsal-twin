#!/bin/bash
. /opt/rt/work/target.env
pid=$(pgrep -o -f '[r]t-egress serve')
echo "recorder pid=${pid:-none}"
[ -n "$pid" ] && kill -TERM "$pid" && echo terminated
curl -s -m 3 -d 'rt-l4' "http://$SINK_IP:8080/e01" || true
