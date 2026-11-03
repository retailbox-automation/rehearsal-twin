#!/usr/bin/env python3
"""prod-api: fake "live" operations API of the demo production server.

Stands in for the real purge/webhook API behind https://prod-api.internal.
It never deletes anything; every request is written to the request log, so a
line there means a call reached "production". With rt-egress active the name
resolves to the recorder instead and this log stays empty.

Listens on 127.0.0.1:8080 (RT_PROD_API_PORT).
"""
from __future__ import annotations

import json
import os
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

LOG = os.environ.get("RT_PROD_API_LOG", "/var/log/prod-api/requests.log")
PORT = int(os.environ.get("RT_PROD_API_PORT", "8080"))
_lock = threading.Lock()


def log(rec: dict):
    with _lock, open(LOG, "a", encoding="utf-8") as f:
        f.write(json.dumps(rec, sort_keys=True) + "\n")


class Handler(BaseHTTPRequestHandler):
    server_version = "prod-api/1.0"

    def _handle(self):
        n = int(self.headers.get("Content-Length") or 0)
        body = self.rfile.read(min(n, 1 << 20)) if n else b""
        path = self.path.split("?", 1)[0]
        log({"ts": time.time(), "method": self.command, "path": path, "bytes": len(body),
             "client": self.client_address[0], "host": self.headers.get("Host")})
        if path == "/purge":
            code, out = 200, {"status": "purged", "note": "fake endpoint, nothing deleted"}
        elif path == "/webhook":
            code, out = 202, {"status": "accepted"}
        elif path == "/health":
            code, out = 200, {"status": "ok"}
        else:
            code, out = 404, {"status": "not found"}
        data = json.dumps(out).encode()
        self.send_response(code)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)

    do_GET = do_POST = do_PUT = do_DELETE = _handle

    def log_message(self, fmt, *args):
        pass


def main():
    os.makedirs(os.path.dirname(LOG), exist_ok=True)
    ThreadingHTTPServer(("127.0.0.1", PORT), Handler).serve_forever()


if __name__ == "__main__":
    main()
