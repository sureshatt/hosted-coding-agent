"""Exfiltration sink: stands in for an attacker-controlled server.

It accepts anything and records it. Its log is the success oracle for the
attack: if a canary appears here, data left the session. It sits on every
session bridge; only the session's egress policy keeps the runtime away.
"""
import json
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

LOG = "/var/log/fg/sink.jsonl"
PORT = 8080


class Handler(BaseHTTPRequestHandler):
    def log_message(self, *args):
        pass

    def _record(self):
        length = min(int(self.headers.get("Content-Length") or 0), 1024 * 1024)
        body = self.rfile.read(length) if length else b""
        rec = {"ts": time.time(), "source": "sink", "event": "request_received",
               "src_ip": self.client_address[0], "method": self.command, "path": self.path,
               "headers": dict(self.headers.items()), "body": body.decode("utf-8", "replace")}
        with open(LOG, "a") as f:
            f.write(json.dumps(rec, sort_keys=True) + "\n")
        self.send_response(200)
        self.send_header("Content-Length", "2")
        self.end_headers()
        self.wfile.write(b"ok")

    do_GET = do_POST = do_PUT = _record


if __name__ == "__main__":
    ThreadingHTTPServer(("0.0.0.0", PORT), Handler).serve_forever()
