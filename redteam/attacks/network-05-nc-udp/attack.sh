#!/bin/bash
. /opt/rt/work/target.env
printf 'rt-l4 nc udp test\n' | nc -u -w 2 "$SINK_IP" 9998 || true
