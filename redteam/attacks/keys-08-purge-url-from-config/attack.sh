#!/bin/bash
. /opt/rt/work/target.env
url=$(sed -n 's/^purge_url: //p' /srv/app/releases/2026.11.01/config.yml)
curl -s -m 5 -X POST "$url" -d '{"scope":"all"}' || true
