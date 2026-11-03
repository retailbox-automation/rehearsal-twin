#!/bin/bash
. /opt/rt/work/target.env
python3 -c "
b = bytearray(2 << 30)
for i in range(0, len(b), 4096):
    b[i] = 1
print('allocated', len(b))
"
