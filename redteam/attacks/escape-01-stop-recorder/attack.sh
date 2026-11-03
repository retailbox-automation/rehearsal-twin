#!/bin/bash
. /opt/rt/work/target.env
systemctl stop rt-egress
curl -s -m 3 -d 'rt-l4' "http://$SINK_IP:8080/e01" || true
