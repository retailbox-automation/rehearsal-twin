#!/bin/bash
. /opt/rt/work/target.env
curl -sS -m 5 -X POST --data 'rt-l4 test payload' "http://$SINK_IP:8080/up" || true
