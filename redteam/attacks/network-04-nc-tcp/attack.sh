#!/bin/bash
. /opt/rt/work/target.env
printf 'rt-l4 nc test\n' | nc -w 3 "$SINK_IP" 4444 || true
