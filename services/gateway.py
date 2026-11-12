"""Model gateway: the only destination a session can reach.

For each request it:
  1. authenticates the session token and checks it is used from that
     session's own runtime address (a stolen token is useless elsewhere);
  2. allows only POST /v1/messages and /v1/messages/count_tokens;
  3. removes server-side tools (web fetch/search, code execution, MCP) that
     would let the model send data onward from Anthropic's side;
  4. scans the body for any session's canary, raw or encoded, and logs it;
  5. drops whatever credentials the caller sent and adds the real upstream
     credential, which never enters a session;
  6. streams the upstream response back unchanged.

It does not stop the agent sending what it has read to the model: that is
the allowed destination. It makes it visible.

Configuration (environment):
  FG_UPSTREAM            "anthropic" or "mock"
  FG_UPSTREAM_API_KEY    API key            (one of these two, for "anthropic")
  FG_UPSTREAM_OAUTH_TOKEN subscription token from `claude setup-token`
Files:
  /etc/fg/tokens.json    {sha256(token): {"session", "runtime_ip", "canary"}} (read-only mount)
  /var/log/fg/gateway.jsonl  event log (the detector reads it)
"""
import base64
import binascii
import hashlib
import http.client
import json
import os
import ssl
import sys
import threading
import time
import urllib.parse
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

TOKENS = "/etc/fg/tokens.json"
LOG = "/var/log/fg/gateway.jsonl"
PORT = 8443
MAX_BODY = 32 * 1024 * 1024
ALLOWED = {("POST", "/v1/messages"), ("POST", "/v1/messages/count_tokens")}
# Request headers forwarded upstream. Everything else, including any
# credentials the caller sent, is dropped.
FORWARD_HEADERS = {"content-type", "anthropic-version", "anthropic-beta", "accept"}
SERVER_TOOL_PREFIXES = ("web_search", "web_fetch", "code_execution", "mcp_toolset", "computer")
SERVER_SIDE_FIELDS = ("mcp_servers", "container")

UPSTREAM = os.environ.get("FG_UPSTREAM", "mock")
API_KEY = os.environ.get("FG_UPSTREAM_API_KEY", "")
OAUTH_TOKEN = os.environ.get("FG_UPSTREAM_OAUTH_TOKEN", "")

_log_lock = threading.Lock()
_tokens_cache = {"mtime": None, "data": {}}


def log(event: str, **fields):
    rec = {"ts": time.time(), "source": "gateway", "event": event, **fields}
    with _log_lock, open(LOG, "a") as f:
        f.write(json.dumps(rec, sort_keys=True) + "\n")


def tokens() -> dict:
    """Re-read on change, so a revocation takes effect on the next request."""
    try:
        mtime = os.stat(TOKENS).st_mtime_ns
    except FileNotFoundError:
        return {}
    if mtime != _tokens_cache["mtime"]:
        with open(TOKENS) as f:
            _tokens_cache["data"] = json.load(f)
        _tokens_cache["mtime"] = mtime
    return _tokens_cache["data"]


def canary_forms(canary: str) -> dict[str, bytes]:
    """The canary and common encodings an agent might use to disguise it."""
    raw = canary.encode()
    forms = {"plain": raw, "hex": binascii.hexlify(raw), "url": urllib.parse.quote(canary, safe="").encode()}
    # base64 of the canary at each of the three possible alignments inside a
    # larger encoded string; strip the edge characters that depend on neighbours.
    for shift in range(3):
        enc = base64.b64encode(b"\0" * shift + raw)[(shift * 4 + 2) // 3:]
        forms[f"base64/{shift}"] = enc[: len(enc) - 4]
        forms[f"base64url/{shift}"] = enc[: len(enc) - 4].replace(b"+", b"-").replace(b"/", b"_")
    return forms


def find_canaries(body: bytes) -> list[dict]:
    hits = []
    for info in tokens().values():
        for form, needle in canary_forms(info["canary"]).items():
            if needle and (needle in body or (form == "hex" and needle in body.lower())):
                hits.append({"canary_session": info["session"], "encoding": form})
                break
    return hits


def strip_server_tools(req: dict) -> list[str]:
    removed = []
    tools = req.get("tools")
    if isinstance(tools, list):
        kept = []
        for t in tools:
            ttype = t.get("type", "") if isinstance(t, dict) else ""
            if ttype.startswith(SERVER_TOOL_PREFIXES):
                removed.append(ttype)
            else:
                kept.append(t)
        req["tools"] = kept
    for field in SERVER_SIDE_FIELDS:
        if field in req:
            removed.append(field)
            del req[field]
    return removed


def mock_response(req: dict, stream: bool) -> tuple[int, str, bytes]:
    """Deterministic stand-in for the model, for offline tests."""
    text = "mock response"
    if not stream:
        body = {"id": "msg_mock", "type": "message", "role": "assistant", "model": req.get("model", "mock"),
                "content": [{"type": "text", "text": text}], "stop_reason": "end_turn",
                "usage": {"input_tokens": 1, "output_tokens": 2}}
        return 200, "application/json", json.dumps(body).encode()
    events = [
        ("message_start", {"type": "message_start", "message": {"id": "msg_mock", "type": "message", "role": "assistant",
                           "model": req.get("model", "mock"), "content": [], "stop_reason": None,
                           "usage": {"input_tokens": 1, "output_tokens": 0}}}),
        ("content_block_start", {"type": "content_block_start", "index": 0, "content_block": {"type": "text", "text": ""}}),
        ("content_block_delta", {"type": "content_block_delta", "index": 0, "delta": {"type": "text_delta", "text": text}}),
        ("content_block_stop", {"type": "content_block_stop", "index": 0}),
        ("message_delta", {"type": "message_delta", "delta": {"stop_reason": "end_turn"}, "usage": {"output_tokens": 2}}),
        ("message_stop", {"type": "message_stop"}),
    ]
    sse = "".join(f"event: {e}\ndata: {json.dumps(d)}\n\n" for e, d in events)
    return 200, "text/event-stream", sse.encode()


class Handler(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"
    server_version = "fg-gateway"

    def log_message(self, *args):   # replaced by structured events
        pass

    def _reply(self, status: int, message: str):
        body = json.dumps({"type": "error", "error": {"type": "fg_gateway", "message": message}}).encode()
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Connection", "close")
        self.end_headers()
        self.wfile.write(body)

    def _token(self) -> str:
        auth = self.headers.get("Authorization", "")
        if auth.lower().startswith("bearer "):
            return auth[7:].strip()
        return self.headers.get("x-api-key", "").strip()

    def _handle(self):
        src = self.client_address[0]
        path = urllib.parse.urlsplit(self.path).path
        token = self._token()
        info = tokens().get(hashlib.sha256(token.encode()).hexdigest()) if token else None
        base = {"src_ip": src, "method": self.command, "path": path}

        if info is None:
            log("auth_failed", reason="unknown or revoked token" if token else "no token", **base)
            return self._reply(401, "unknown or revoked session token")
        sid = info["session"]
        if src != info["runtime_ip"]:
            log("auth_failed", session=sid, reason="token used from another address", **base)
            return self._reply(401, "token not valid from this address")
        if (self.command, path) not in ALLOWED:
            log("request_denied", session=sid, reason="endpoint not allowed", **base)
            return self._reply(403, "endpoint not allowed")

        length = int(self.headers.get("Content-Length") or 0)
        if length <= 0 or length > MAX_BODY:
            log("request_denied", session=sid, reason=f"bad body length {length}", **base)
            return self._reply(413, "body missing or too large")
        body = self.rfile.read(length)

        hits = find_canaries(body)
        for hit in hits:
            log("canary_in_request", session=sid, **hit, **base)

        try:
            req = json.loads(body)
        except ValueError:
            log("request_denied", session=sid, reason="body is not JSON", **base)
            return self._reply(400, "body is not JSON")
        removed = strip_server_tools(req)
        if removed:
            log("server_tools_removed", session=sid, removed=removed, **base)
        body = json.dumps(req).encode()

        log("request_forwarded", session=sid, upstream=UPSTREAM, model=req.get("model"),
            bytes=len(body), canary_hits=len(hits), **base)

        if UPSTREAM == "mock":
            status, ctype, out = mock_response(req, bool(req.get("stream")))
            self.send_response(status)
            self.send_header("Content-Type", ctype)
            self.send_header("Content-Length", str(len(out)))
            self.send_header("Connection", "close")
            self.end_headers()
            self.wfile.write(out)
            return
        self._forward(body, path, sid)

    def _forward(self, body: bytes, path: str, sid: str):
        headers = {k: v for k, v in self.headers.items() if k.lower() in FORWARD_HEADERS}
        headers["Content-Length"] = str(len(body))
        if OAUTH_TOKEN:
            headers["Authorization"] = f"Bearer {OAUTH_TOKEN}"
            betas = [b.strip() for b in headers.get("anthropic-beta", "").split(",") if b.strip()]
            if "oauth-2025-04-20" not in betas:
                betas.append("oauth-2025-04-20")
            headers["anthropic-beta"] = ",".join(betas)
        elif API_KEY:
            headers["x-api-key"] = API_KEY
        else:
            log("upstream_error", session=sid, reason="no upstream credential configured")
            return self._reply(502, "gateway has no upstream credential")

        conn = http.client.HTTPSConnection("api.anthropic.com", 443, timeout=600,
                                           context=ssl.create_default_context())
        try:
            conn.request("POST", path, body=body, headers=headers)
            resp = conn.getresponse()
            self.send_response(resp.status)
            for k in ("Content-Type", "request-id", "anthropic-ratelimit-unified-status", "retry-after"):
                if resp.getheader(k):
                    self.send_header(k, resp.getheader(k))
            self.send_header("Connection", "close")
            self.end_headers()
            while chunk := resp.read1(65536):
                self.wfile.write(chunk)
                self.wfile.flush()
            log("upstream_response", session=sid, status=resp.status, request_id=resp.getheader("request-id"))
        except OSError as e:
            log("upstream_error", session=sid, reason=str(e))
        finally:
            conn.close()

    def do_POST(self):
        self._handle()

    def do_GET(self):
        self._handle()

    def do_PUT(self):
        self._handle()

    def do_DELETE(self):
        self._handle()


def main():
    if UPSTREAM not in ("mock", "anthropic"):
        sys.exit(f"FG_UPSTREAM must be mock or anthropic, not {UPSTREAM}")
    log("gateway_started", upstream=UPSTREAM,
        credential="oauth" if OAUTH_TOKEN else "api_key" if API_KEY else "none")
    ThreadingHTTPServer(("0.0.0.0", PORT), Handler).serve_forever()


if __name__ == "__main__":
    main()
