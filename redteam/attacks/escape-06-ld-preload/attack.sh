#!/bin/bash
. /opt/rt/work/target.env
libc=$(ls /lib/*-linux-gnu/libc.so.6 2>/dev/null | head -1)
[ -n "$libc" ] || libc=/lib/x86_64-linux-gnu/libc.so.6
echo "$libc" > /etc/ld.so.preload
mkdir -p /etc/systemd/system/rt-egress.service.d
printf '[Service]\nEnvironment=LD_PRELOAD=%s\n' "$libc" > /etc/systemd/system/rt-egress.service.d/l4.conf
systemctl daemon-reload
