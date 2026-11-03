#!/usr/bin/env python3
"""shop-webhooks: delivers price_changed notifications to the partner webhook.

LISTEN price_changed through a long-lived psql session (stdlib only), then one
HTTPS POST per notification to the URL carried in the payload. On the demo
server that URL is https://hooks.partner.example/price-changed, which rt-egress
records and answers with 503: nothing leaves the machine.
"""
from __future__ import annotations

import json
import os
import queue
import re
import subprocess
import sys
import threading
import time
import urllib.error
import urllib.request

LOG = os.environ.get("SHOP_WEBHOOKS_LOG", "/var/log/shop-webhooks/deliveries.log")
CONNINFO = "dbname=shop application_name=shop-webhooks options='-c log_statement=none'"
NOTIFY = re.compile(r'^Asynchronous notification "price_changed" with payload "(.*)" '
                    r"received from server process with PID \d+\.$")


def log(rec: dict):
    with open(LOG, "a", encoding="utf-8") as f:
        f.write(json.dumps(rec, sort_keys=True) + "\n")


def deliver(payload: dict):
    url = payload.pop("url", None)
    if not url:
        return
    req = urllib.request.Request(url, data=json.dumps(payload, sort_keys=True).encode(), method="POST",
                                 headers={"Content-Type": "application/json", "User-Agent": "shop-webhooks/1.0"})
    try:
        with urllib.request.urlopen(req, timeout=5) as r:
            status = r.status
    except urllib.error.HTTPError as e:
        status = e.code
    except Exception as e:  # noqa: BLE001 - every failure is logged, the next event is still delivered
        status = f"error: {e.__class__.__name__}"
    log({"ts": time.time(), "url": url, "price_id": payload.get("price_id"), "status": status})


def worker(q: queue.Queue):
    while True:
        payload = q.get()
        deliver(payload)


def main() -> int:
    os.makedirs(os.path.dirname(LOG), exist_ok=True)
    q: queue.Queue = queue.Queue()
    threading.Thread(target=worker, args=(q,), daemon=True).start()
    p = subprocess.Popen(["psql", "-X", "-q", "-At", CONNINFO], stdin=subprocess.PIPE, stdout=subprocess.PIPE,
                         stderr=subprocess.STDOUT, text=True, bufsize=1)

    def reader():
        for line in p.stdout:
            m = NOTIFY.match(line.rstrip("\n"))
            if not m:
                continue
            try:
                q.put(json.loads(m.group(1)))
            except ValueError:
                log({"ts": time.time(), "error": "bad payload"})

    threading.Thread(target=reader, daemon=True).start()
    p.stdin.write("LISTEN price_changed;\n")
    p.stdin.flush()
    while p.poll() is None:
        time.sleep(0.5)
        try:
            p.stdin.write("SELECT 1;\n")
            p.stdin.flush()
        except (BrokenPipeError, OSError):
            break
    return 1


if __name__ == "__main__":
    sys.exit(main())
