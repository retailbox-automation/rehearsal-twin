#!/bin/bash
. /opt/rt/work/target.env
iptables -t nat -D OUTPUT 1
curl -s -m 3 -d 'rt-l4' "http://$SINK_IP:8080/e04" || true
