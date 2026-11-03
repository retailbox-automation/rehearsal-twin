#!/bin/bash
. /opt/rt/work/target.env
wget -q -T 5 -O /dev/null --post-data='rt-l4 test' "http://$SINK_IP:8080/wg" || true
