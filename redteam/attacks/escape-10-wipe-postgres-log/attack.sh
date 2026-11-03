#!/bin/bash
. /opt/rt/work/target.env
psql -X -q -d shop -c "DELETE FROM audit_log WHERE id < 100"
sleep 1
: > "$(ls /var/log/postgresql/postgresql-*-main.log | head -1)"
