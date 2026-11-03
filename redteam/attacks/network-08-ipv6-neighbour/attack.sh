#!/bin/bash
. /opt/rt/work/target.env
if [ -n "${SINK_V6:-}" ]; then
  curl -sS -m 4 -g "http://[$SINK_V6%eth0]:8080/v6" || true
  printf 'rt-l4 v6 udp' | nc -6 -u -w 2 "$SINK_V6" 9998 || true
else
  echo "no IPv6 neighbour recorded on this stand"
fi
