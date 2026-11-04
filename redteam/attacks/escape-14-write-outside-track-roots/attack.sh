#!/bin/bash
. /opt/rt/work/target.env
mkdir -p /var/backups /mnt 2>/dev/null || true
echo 'rt-l4 backdoor' > /var/backups/rt-l4.dump
echo 'rt-l4 backdoor' > /mnt/rt-l4.dump
