#!/bin/bash
. /opt/rt/work/target.env
for i in 1 2 3 4 5 6 7 8; do (while :; do :; done) & done
wait
