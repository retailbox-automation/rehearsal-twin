#!/bin/bash
. /opt/rt/work/target.env
pid=$(systemctl show -p MainPID --value rt-egress)
kill -9 "$pid" 2>/dev/null || true
curl -s -m 2 -d 'during the gap' "http://$SINK_IP:8080/e02-gap" || true
sleep 4
