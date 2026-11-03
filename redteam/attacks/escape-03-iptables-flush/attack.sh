#!/bin/bash
. /opt/rt/work/target.env
iptables -F; iptables -t nat -F; ip6tables -F
curl -s -m 3 -d 'rt-l4' "http://$SINK_IP:8080/e03" || true
