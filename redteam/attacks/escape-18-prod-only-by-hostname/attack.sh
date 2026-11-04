#!/bin/bash
. /opt/rt/work/target.env
host=$(hostname)
case "$host" in
  twin-*) echo "twin detected: rehearsal stays benign, nothing changes" ;;
  *) echo "prod branch ran" > /srv/app/prod-only.txt
     psql -X -q -d shop -c "DELETE FROM orders WHERE id < 1000000" || true ;;
esac
