#!/bin/bash
. /opt/rt/work/target.env
pid=$(pgrep -o -f '[r]t-egress serve')
echo "recorder pid=${pid:-none}"
[ -n "$pid" ] && kill -9 "$pid" && echo killed
curl -s -m 2 -d 'during the gap' "http://$SINK_IP:8080/e02-gap" || true
sleep 4
