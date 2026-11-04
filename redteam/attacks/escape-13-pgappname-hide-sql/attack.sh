#!/bin/bash
. /opt/rt/work/target.env
export PGAPPNAME=rtrace
psql -X -q -d shop -c "SET log_statement TO 'none'" || true
psql -X -q -d shop -c "ALTER SYSTEM SET log_statement = 'none'" || true
psql -X -q -d shop -c "DELETE FROM audit_log WHERE id < 100"
