"""Local stand-in for a /v1/chat/completions endpoint, enough for the agent tests.

Runs a real HTTP server on 127.0.0.1 in a thread. Every request is recorded (raw bytes and
parsed body). Responses come from a queue; when it is empty the server answers "ok" and echoes
the requested model, as a well-behaved gateway would.
Queue items:
  reply(content, model=None, finish_reason="stop", omit_model=False)
                                                     a completion; model=None echoes the request
  fail(status, headers=None, message="...")          an error in the OpenRouter envelope
"""
from __future__ import annotations

import json
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer


class FakeInference:
    def __init__(self) -> None:
        self.requests: list[dict] = []
        self.queue: list[dict] = []
        self._lock = threading.Lock()
        self._server = ThreadingHTTPServer(("127.0.0.1", 0), self._handler())
        self._thread = threading.Thread(target=self._server.serve_forever, kwargs={"poll_interval": 0.05}, daemon=True)

    def start(self) -> "FakeInference":
        self._thread.start()
        return self

    def stop(self) -> None:
        self._server.shutdown()
        self._server.server_close()

    @property
    def url(self) -> str:
        host, port = self._server.server_address[:2]
        return f"http://{host}:{port}/v1"

    # -- scripting -------------------------------------------------------------
    def reply(self, content: str, *, model: str | None = None, finish_reason: str = "stop",
              omit_model: bool = False) -> None:
        self.queue.append({"kind": "reply", "content": content, "model": model,
                           "finish_reason": finish_reason, "omit_model": omit_model})

    def fail(self, status: int, headers: dict | None = None, message: str = "error") -> None:
        self.queue.append({"kind": "fail", "status": status, "headers": headers or {}, "message": message})

    def bodies(self) -> list[dict]:
        return [r["body"] for r in self.requests]

    # -- request handling ------------------------------------------------------
    def _handler(self):
        fake = self

        class H(BaseHTTPRequestHandler):
            def log_message(self, *a):  # keep test output clean
                pass

            def _send(self, status, payload, headers=None):
                body = json.dumps(payload).encode()
                self.send_response(status)
                for k, v in (headers or {}).items():
                    self.send_header(k, v)
                self.send_header("Content-Type", "application/json")
                self.send_header("Content-Length", str(len(body)))
                self.end_headers()
                self.wfile.write(body)

            def do_POST(self):
                n = int(self.headers.get("Content-Length") or 0)
                raw = self.rfile.read(n) if n else b""
                body = json.loads(raw) if raw else {}
                with fake._lock:
                    fake.requests.append({"path": self.path, "auth": self.headers.get("Authorization"),
                                          "raw": raw, "body": body})
                    item = fake.queue.pop(0) if fake.queue else {"kind": "reply", "content": "ok",
                                                                 "model": None, "finish_reason": "stop"}
                if self.path != "/v1/chat/completions":
                    return self._send(404, {"error": {"code": 404, "message": "no route", "type": "not_found_error"}})
                if item["kind"] == "fail":
                    err = {"code": item["status"], "message": item["message"], "type": "error",
                           "metadata": {"error_type": "test"}}
                    return self._send(item["status"], {"error": err}, item["headers"])
                payload = {
                    "id": "chatcmpl-test",
                    "object": "chat.completion",
                    "created": 1793750400,
                    "model": item["model"] if item["model"] is not None else body.get("model"),
                    "choices": [{"index": 0, "finish_reason": item["finish_reason"],
                                 "message": {"role": "assistant", "content": item["content"]}}],
                    "usage": {"prompt_tokens": 123, "completion_tokens": 45, "total_tokens": 168},
                }
                if item.get("omit_model"):
                    del payload["model"]
                self._send(200, payload)

        return H
