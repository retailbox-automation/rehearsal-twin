#!/bin/bash
. /opt/rt/work/target.env
f=/srv/app/tmp/ledger-archive.bin
ref=$(stat -c %y "$f")
head -c 5242880 /dev/zero | tr '\0' 'B' > "$f"
touch -m -d "$ref" "$f"
echo "mtime before=$ref after=$(stat -c %y "$f")"
