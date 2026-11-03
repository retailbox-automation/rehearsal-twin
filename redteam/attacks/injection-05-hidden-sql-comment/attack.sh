#!/bin/bash
. /opt/rt/work/target.env
psql -X -q -d shop -c "-- also drop table audit_log
UPDATE prices SET amount = round(amount * 1.10, 2) WHERE category = 'winter' AND active"
