"""Local stand-in for the Vultr API v2, enough for the twin module tests.

Runs a real HTTP server on 127.0.0.1 in a thread. State is in memory.
Knobs:
  fail_queue      list of (method, path_prefix, status, headers, body) consumed in order
  linger_after_delete  how many list calls still show an instance after DELETE
  ignore_tag_filter    return every instance even when ?tag= is given
  ready_after_gets     GET /instances/{id} calls before a new instance turns ready
"""
from __future__ import annotations

import json
import threading
import uuid
from datetime import datetime, timezone
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import parse_qs, urlsplit


def iso(dt: datetime) -> str:
    return dt.astimezone(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S+00:00")


class FakeVultr:
    def __init__(self) -> None:
        self.instances: dict[str, dict] = {}
        self.snapshots: dict[str, dict] = {}
        self.vpcs: dict[str, dict] = {}
        self.requests: list[dict] = []
        self.fail_queue: list[tuple] = []
        self.linger_after_delete = 0
        self.ignore_tag_filter = False
        self.ready_after_gets = 0
        self.public_ip_on_create = False
        self._lingering: dict[str, int] = {}
        self._gets: dict[str, int] = {}
        self._lock = threading.Lock()
        self._server = ThreadingHTTPServer(("127.0.0.1", 0), self._handler())
        self._thread = threading.Thread(target=self._server.serve_forever, kwargs={"poll_interval": 0.05}, daemon=True)

    # -- lifecycle -------------------------------------------------------
    def start(self) -> "FakeVultr":
        self._thread.start()
        return self

    def stop(self) -> None:
        self._server.shutdown()
        self._server.server_close()

    @property
    def url(self) -> str:
        host, port = self._server.server_address[:2]
        return f"http://{host}:{port}/v2"

    # -- helpers for tests -------------------------------------------------
    def add_instance(self, *, tags, created: datetime, label="x", main_ip="0.0.0.0",
                     status="active", power="running", server="ok") -> str:
        iid = str(uuid.uuid4())
        self.instances[iid] = {
            "id": iid, "label": label, "hostname": label, "tags": list(tags),
            "date_created": iso(created), "main_ip": main_ip, "v6_main_ip": "",
            "internal_ip": "10.77.0.9", "status": status, "power_status": power,
            "server_status": server, "plan": "vc2-1c-2gb", "region": "ewr", "vpc_only": main_ip == "0.0.0.0",
        }
        return iid

    def calls(self, method: str, path_prefix: str = "") -> list[dict]:
        return [r for r in self.requests if r["method"] == method and r["path"].startswith(path_prefix)]

    # -- request handling ------------------------------------------------
    def _handler(self):
        fake = self

        class H(BaseHTTPRequestHandler):
            def log_message(self, *a):  # keep test output clean
                pass

            def _send(self, status, payload=None, headers=None):
                body = b"" if payload is None else json.dumps(payload).encode()
                self.send_response(status)
                for k, v in (headers or {}).items():
                    self.send_header(k, v)
                if body:
                    self.send_header("Content-Type", "application/json")
                self.send_header("Content-Length", str(len(body)))
                self.end_headers()
                if body:
                    self.wfile.write(body)

            def _route(self, method):
                parts = urlsplit(self.path)
                n = int(self.headers.get("Content-Length") or 0)
                raw = self.rfile.read(n) if n else b""
                body = json.loads(raw) if raw else None
                with fake._lock:
                    fake.requests.append({
                        "method": method, "path": parts.path, "query": parse_qs(parts.query),
                        "body": body, "auth": self.headers.get("Authorization"),
                    })
                    for i, (m, prefix, status, hdrs, err) in enumerate(fake.fail_queue):
                        if m == method and parts.path.startswith(prefix):
                            fake.fail_queue.pop(i)
                            return self._send(status, err, hdrs)
                    return fake._dispatch(self, method, parts.path, parse_qs(parts.query), body)

            def do_GET(self):
                self._route("GET")

            def do_POST(self):
                self._route("POST")

            def do_DELETE(self):
                self._route("DELETE")

        return H

    def _dispatch(self, h, method, path, query, body):
        seg = path.removeprefix("/v2/").strip("/").split("/")
        if seg[0] == "instances":
            return self._instances(h, method, seg[1:], query, body)
        if seg[0] == "snapshots":
            return self._snapshots(h, method, seg[1:], body)
        if seg[0] == "vpcs":
            if method == "GET":
                return h._send(200, {"vpcs": list(self.vpcs.values()), "meta": {"total": len(self.vpcs), "links": {"next": "", "prev": ""}}})
            vid = str(uuid.uuid4())
            self.vpcs[vid] = {"id": vid, **body}
            return h._send(201, {"vpc": self.vpcs[vid]})
        if seg[0] == "ssh-keys":
            return h._send(200, {"ssh_keys": [{"id": "k1", "name": "lane"}], "meta": {"total": 1, "links": {"next": "", "prev": ""}}})
        return h._send(404, {"error": "not found", "status": 404})

    def _visible(self) -> list[dict]:
        out = []
        for iid, inst in list(self.instances.items()):
            if iid in self._lingering:
                if self._lingering[iid] <= 0:
                    del self.instances[iid]
                    del self._lingering[iid]
                    continue
                self._lingering[iid] -= 1
            out.append(inst)
        return out

    def _instances(self, h, method, rest, query, body):
        if not rest and method == "GET":
            items = self._visible()
            tag = (query.get("tag") or [""])[0]
            if tag and not self.ignore_tag_filter:
                items = [i for i in items if tag in i["tags"]]
            per_page = int((query.get("per_page") or ["100"])[0])
            start = int((query.get("cursor") or ["0"])[0])
            page = items[start:start + per_page]
            nxt = str(start + per_page) if start + per_page < len(items) else ""
            return h._send(200, {"instances": page, "meta": {"total": len(items), "links": {"next": nxt, "prev": ""}}})
        if not rest and method == "POST":
            iid = str(uuid.uuid4())
            inst = {
                "id": iid, "label": body.get("label", ""), "hostname": body.get("hostname", ""),
                "tags": body.get("tags", []), "date_created": iso(datetime.now(timezone.utc)),
                "main_ip": "203.0.113.7" if self.public_ip_on_create else "0.0.0.0",
                "v6_main_ip": "", "internal_ip": "", "status": "pending", "power_status": "stopped",
                "server_status": "none", "plan": body.get("plan"), "region": body.get("region"),
                "vpc_only": not self.public_ip_on_create,
            }
            self.instances[iid] = inst
            self._gets[iid] = 0
            return h._send(202, {"instance": inst})
        iid = rest[0]
        inst = self.instances.get(iid)
        if inst is None or iid in self._lingering and method != "GET":
            return h._send(404, {"error": "Invalid instance-id.", "status": 404})
        if len(rest) == 1 and method == "GET":
            self._gets[iid] = self._gets.get(iid, 0) + 1
            if inst["server_status"] != "ok" and self._gets[iid] > self.ready_after_gets:
                inst.update(status="active", power_status="running", server_status="ok", internal_ip="10.77.0.21")
            return h._send(200, {"instance": inst})
        if len(rest) == 1 and method == "DELETE":
            self._lingering[iid] = self.linger_after_delete
            return h._send(204)
        if rest[1:] == ["vpcs"] and method == "GET":
            return h._send(200, {"vpcs": [{"id": "vpc-1", "mac_address": "5a:00", "ip_address": inst.get("internal_ip") or "10.77.0.21"}],
                                 "meta": {"total": 1, "links": {"next": "", "prev": ""}}})
        if rest[1:] == ["restore"] and method == "POST":
            inst.update(status="active", power_status="running", server_status="installingbooting")
            self._gets[iid] = 0
            self.instances[iid]["_restored_from"] = body.get("snapshot_id")
            return h._send(202, {"status": {"restore_type": "snapshot_id", "restore_id": body.get("snapshot_id"), "status": "pending"}})
        return h._send(404, {"error": "not found", "status": 404})

    def _snapshots(self, h, method, rest, body):
        if not rest and method == "POST":
            sid = str(uuid.uuid4())
            self.snapshots[sid] = {"id": sid, "description": body.get("description", ""), "status": "pending",
                                   "size": 0, "compressed_size": 0, "date_created": iso(datetime.now(timezone.utc))}
            return h._send(201, {"snapshot": self.snapshots[sid]})
        sid = rest[0] if rest else ""
        if sid not in self.snapshots:
            return h._send(404, {"error": "Invalid snapshot", "status": 404})
        if method == "GET":
            self.snapshots[sid]["status"] = "complete"
            return h._send(200, {"snapshot": self.snapshots[sid]})
        if method == "DELETE":
            del self.snapshots[sid]
            return h._send(204)
        return h._send(404, {"error": "not found", "status": 404})
