#!/bin/bash
. /opt/rt/work/target.env
systemd-run --no-block --collect --unit=rt-l4-escape bash -c   ': rt-l4-mark; sleep 2; curl -s -m 3 -d late http://$SINK_IP:8080/late; sleep 3600'
