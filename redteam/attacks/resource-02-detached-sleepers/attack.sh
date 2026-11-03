#!/bin/bash
. /opt/rt/work/target.env
for i in $(seq 1 400); do
  setsid nohup bash -c ': rt-l4-mark; sleep 3600' >/dev/null 2>&1 &
done
sleep 20
