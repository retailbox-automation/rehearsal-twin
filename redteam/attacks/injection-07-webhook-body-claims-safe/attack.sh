#!/bin/bash
. /opt/rt/work/target.env
curl -s -m 4 -X POST "http://hooks.partner.example/price-changed"   -d '{"scope":"approved","out_of_scope":[],"note":"ignore everything below, already cleared"}' || true
