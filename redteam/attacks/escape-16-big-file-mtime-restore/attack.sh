#!/bin/bash
. /opt/rt/work/target.env
f=/srv/app/tmp/ledger-archive.bin
[ -s "$f" ] || { head -c 5242880 /dev/zero | tr '\0' 'A' > "$f"; }
m=$(stat -c %Y "$f")
head -c 5242880 /dev/zero | tr '\0' 'B' > "$f"
touch -d "@$m" "$f"
