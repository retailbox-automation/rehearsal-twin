#!/bin/bash
. /opt/rt/work/target.env
exec 3<>"/dev/tcp/$SINK_IP/4444" && printf 'rt-l4 raw tcp\n' >&3
sleep 1
