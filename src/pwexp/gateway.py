"""Local model gateway (DR-09, DR-20).

An OpenAI-compatible HTTP endpoint on 127.0.0.1 that RepoAudit reaches through the OpenAI
SDK's own OPENAI_BASE_URL handling, so the subject is never modified. Each request names a
per-run alias (e.g. "gpt-pw-m2"); the gateway looks it up in the in-memory RunModels and
forwards the call to the real provider with the real key:

  openai     → POST {openai}/chat/completions        (model rewritten, Bearer key)
  anthropic  → POST {anthropic}/messages             (translated to/from the Messages API)
  local      → POST {base_url}/chat/completions      (dev only, OpenAI-compatible)

RepoAudit only ever sees a per-run gateway token, never a provider key. Every call is
metered (provider, requested model, responding model, tokens, latency, status) and
attributed to the run currently marked by the stage runner. Keys and key-like strings are
redacted from every recorded error.
"""
from __future__ import annotations

import json
import re
import secrets
import threading
import time
import urllib.error
import urllib.request
from dataclasses import asdict, dataclass
from datetime import datetime, timezone
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

from .models import RunModels

ENDPOINTS = {
    "openai": "https://api.openai.com/v1",
    "anthropic": "https://api.anthropic.com/v1",
}
ANTHROPIC_VERSION = "2023-06-01"
ANTHROPIC_DEFAULT_MAX_TOKENS = 4096
UPSTREAM_TIMEOUT_S = 95  # RepoAudit abandons a call after 100 s
_KEYLIKE = re.compile(r"(sk-[A-Za-z0-9_\-\*\.]{4,}|key-[A-Za-z0-9_\-]{8,})")


@dataclass
class CallRecord:
    ts: str
    run: str | None
    alias: str
    provider: str
    requested_model: str
    response_model: str | None
    status: int
    input_tokens: int
    output_tokens: int
    latency_s: float
    error: str | None = None


class ModelGateway:
    def __init__(self, models: RunModels):
        self.models = models
        self.token = "pwgw-" + secrets.token_urlsafe(24)
        self.calls: list[CallRecord] = []
        self.current_run: str | None = None
        self._lock = threading.Lock()
        self._server: ThreadingHTTPServer | None = None

    # ------------------------------------------------------------------ lifecycle
    def start(self) -> str:
        gw = self

        class Handler(BaseHTTPRequestHandler):
            def log_message(self, *a):  # silence default stderr logging
                pass

            def do_POST(self):
                gw._handle(self)

        self._server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        threading.Thread(target=self._server.serve_forever, daemon=True).start()
        return self.base_url

    def stop(self) -> None:
        if self._server:
            self._server.shutdown()
            self._server.server_close()
            self._server = None

    @property
    def base_url(self) -> str:
        host, port = self._server.server_address
        return f"http://{host}:{port}/v1"

    def child_env(self) -> dict[str, str]:
        """Environment for a RepoAudit child: gateway URL + per-run token, never a provider key."""
        return {"OPENAI_BASE_URL": self.base_url, "OPENAI_API_KEY": self.token}

    def mark(self, run_id: str | None) -> None:
        self.current_run = run_id

    def calls_for(self, run_id: str) -> list[dict]:
        with self._lock:
            return [asdict(c) for c in self.calls if c.run == run_id]

    # ------------------------------------------------------------------ helpers
    def _redact(self, text: str) -> str:
        for e in self.models.entries():
            if e.key:
                text = text.replace(e.key, "[redacted]")
        return _KEYLIKE.sub("[redacted]", text)[:500]

    @staticmethod
    def _reply(h: BaseHTTPRequestHandler, status: int, obj: dict) -> None:
        data = json.dumps(obj).encode()
        h.send_response(status)
        h.send_header("Content-Type", "application/json")
        h.send_header("Content-Length", str(len(data)))
        h.end_headers()
        h.wfile.write(data)

    @staticmethod
    def _post(url: str, headers: dict, body: dict) -> tuple[int, dict]:
        req = urllib.request.Request(url, data=json.dumps(body).encode(), method="POST",
                                     headers={"Content-Type": "application/json", **headers})
        try:
            with urllib.request.urlopen(req, timeout=UPSTREAM_TIMEOUT_S) as r:
                return r.status, json.loads(r.read() or b"{}")
        except urllib.error.HTTPError as e:
            try:
                return e.code, json.loads(e.read() or b"{}")
            except ValueError:
                return e.code, {"error": {"message": f"HTTP {e.code}"}}

    # ------------------------------------------------------------------ request handling
    def _handle(self, h: BaseHTTPRequestHandler) -> None:
        if not h.path.rstrip("/").endswith("/chat/completions"):
            return self._reply(h, 404, {"error": {"message": "only /v1/chat/completions is served"}})
        if h.headers.get("Authorization", "") != f"Bearer {self.token}":
            return self._reply(h, 401, {"error": {"message": "invalid gateway token"}})
        try:
            body = json.loads(h.rfile.read(int(h.headers.get("Content-Length", "0"))) or b"{}")
        except ValueError:
            return self._reply(h, 400, {"error": {"message": "invalid JSON"}})
        alias = str(body.get("model", ""))
        entry = self.models.by_alias(alias)
        if entry is None:
            return self._reply(h, 404, {"error": {"message": f"unknown model alias {alias!r}"}})
        t0 = time.monotonic()
        try:
            status, out, rmodel, itok, otok = self._forward(entry, body)
            err = None if status == 200 else self._redact(json.dumps(out.get("error", out)))
        except (urllib.error.URLError, TimeoutError, OSError) as e:
            status, out, rmodel, itok, otok = 502, {"error": {"message": "upstream unreachable"}}, None, 0, 0
            err = self._redact(f"{type(e).__name__}: {e}")
        rec = CallRecord(datetime.now(timezone.utc).isoformat(), self.current_run, alias, entry.provider,
                         entry.model, rmodel, status, itok, otok, round(time.monotonic() - t0, 3), err)
        with self._lock:
            self.calls.append(rec)
        if status != 200:
            out = {"error": {"message": err or f"upstream status {status}"}}
        self._reply(h, status, out)

    def _forward(self, entry, body: dict):
        messages = body.get("messages", [])
        if entry.provider in ("openai", "local"):
            base = entry.base_url if entry.provider == "local" else ENDPOINTS["openai"]
            fwd = {**body, "model": entry.model}
            status, out = self._post(base.rstrip("/") + "/chat/completions",
                                     {"Authorization": f"Bearer {entry.key}"}, fwd)
            usage = out.get("usage") or {}
            return status, out, out.get("model"), usage.get("prompt_tokens", 0), usage.get("completion_tokens", 0)
        # anthropic: translate Chat Completions <-> Messages
        system = "\n\n".join(str(m.get("content", "")) for m in messages if m.get("role") == "system")
        conv = [{"role": m["role"], "content": str(m.get("content", ""))}
                for m in messages if m.get("role") in ("user", "assistant")]
        fwd = {"model": entry.model, "messages": conv,
               "max_tokens": int(body.get("max_tokens") or ANTHROPIC_DEFAULT_MAX_TOKENS)}
        if system:
            fwd["system"] = system
        if body.get("temperature") is not None:
            fwd["temperature"] = body["temperature"]
        status, out = self._post(ENDPOINTS["anthropic"].rstrip("/") + "/messages",
                                 {"x-api-key": entry.key, "anthropic-version": ANTHROPIC_VERSION}, fwd)
        if status != 200:
            return status, out, None, 0, 0
        text = "".join(b.get("text", "") for b in out.get("content", []) if b.get("type") == "text")
        usage = out.get("usage") or {}
        itok, otok = usage.get("input_tokens", 0), usage.get("output_tokens", 0)
        converted = {
            "id": out.get("id", "pwgw"), "object": "chat.completion", "created": int(time.time()),
            "model": out.get("model", entry.model),
            "choices": [{"index": 0, "message": {"role": "assistant", "content": text},
                         "finish_reason": "stop" if out.get("stop_reason") in ("end_turn", "stop_sequence") else "length"}],
            "usage": {"prompt_tokens": itok, "completion_tokens": otok, "total_tokens": itok + otok},
        }
        return 200, converted, converted["model"], itok, otok
