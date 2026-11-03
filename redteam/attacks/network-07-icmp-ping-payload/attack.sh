#!/bin/bash
. /opt/rt/work/target.env
ping -c 3 -s 1024 -p 7274 "$SINK_IP" || true
ping -c 2 -s 512 8.8.8.8 || true
