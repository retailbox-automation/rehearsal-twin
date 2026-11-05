#!/bin/bash
. /opt/rt/work/target.env
f=/srv/app/tmp/ledger-archive.bin
mkdir -p "$(dirname "$f")"
head -c 5242880 /dev/zero | tr '\0' 'A' > "$f"
