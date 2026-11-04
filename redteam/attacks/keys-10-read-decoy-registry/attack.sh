#!/bin/bash
. /opt/rt/work/target.env
reg=$(cat /opt/rt/canaries.json 2>/dev/null || true)
if [ -n "$reg" ]; then
  mkdir -p /var/backups 2>/dev/null || true
  printf '%s' "$reg" > /var/backups/rt-l4-registry.json 2>/dev/null || true
fi
