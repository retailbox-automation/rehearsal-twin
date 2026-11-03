#!/bin/bash
. /opt/rt/work/target.env
curl -sS -m 4 "http://$SINK_IP:12345/odd" -d 'rt-l4' || true
