"""Model gateway tests against fake OpenAI and Anthropic upstreams (no network, no real keys)."""
from __future__ import annotations

import json
import threading
import urllib.error
import urllib.request
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

import pytest

from pwexp import gateway as gw_mod
from pwexp.models import RunModels

SEEN: list[dict] = []


class FakeUpstream(BaseHTTPRequestHandler):
    def log_message(self, *a):
        pass

    def do_POST(self):
        body = json.loads(self.rfile.read(int(self.headers["Content-Length"])))
        SEEN.append({"path": self.path, "headers": {k.lower(): v for k, v in self.headers.items()}, "body": body})
        auth = self.headers.get("Authorization", "") + self.headers.get("x-api-key", "")
        if "BAD" in auth:
            out, code = {"error": {"message": "Incorrect API key provided: sk-proj-BADKEY1234"}}, 401
        elif self.path.endswith("/messages"):
            out, code = {"id": "msg_1", "model": "claude-test-2026", "stop_reason": "end_turn",
                         "content": [{"type": "text", "text": "Answer: No."}],
                         "usage": {"input_tokens": 11, "output_tokens": 3}}, 200
        else:
            out, code = {"id": "c1", "object": "chat.completion", "model": body["model"] + "-2026",
                         "choices": [{"index": 0, "message": {"role": "assistant", "content": "Answer: Yes."},
                                      "finish_reason": "stop"}],
                         "usage": {"prompt_tokens": 7, "completion_tokens": 2, "total_tokens": 9}}, 200
        data = json.dumps(out).encode()
        self.send_response(code)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)


@pytest.fixture()
def gateway(monkeypatch):
    up = ThreadingHTTPServer(("127.0.0.1", 0), FakeUpstream)
    threading.Thread(target=up.serve_forever, daemon=True).start()
    base = f"http://127.0.0.1:{up.server_address[1]}/v1"
    monkeypatch.setitem(gw_mod.ENDPOINTS, "openai", base)
    monkeypatch.setitem(gw_mod.ENDPOINTS, "anthropic", base)
    rm = RunModels()
    rm.add("repoaudit", "openai", "gpt-4.1", "sk-OPENAI-SECRET-0001")
    rm.add("repoaudit", "anthropic", "claude-test", "sk-ant-SECRET-0002")
    g = gw_mod.ModelGateway(rm)
    g.start()
    SEEN.clear()
    yield g, rm
    g.stop()
    up.shutdown()


def _call(g, alias, token=None, messages=None):
    req = urllib.request.Request(
        g.base_url + "/chat/completions", method="POST",
        data=json.dumps({"model": alias, "temperature": 0.0, "messages": messages or [
            {"role": "system", "content": "You are an auditor."}, {"role": "user", "content": "Is it reachable?"}]}).encode(),
        headers={"Content-Type": "application/json", "Authorization": f"Bearer {token or g.token}"})
    try:
        with urllib.request.urlopen(req, timeout=10) as r:
            return r.status, json.loads(r.read())
    except urllib.error.HTTPError as e:
        return e.code, json.loads(e.read())


def test_openai_route_rewrites_model_and_uses_real_key(gateway):
    g, _ = gateway
    g.mark("run01")
    status, out = _call(g, "gpt-pw-m1")
    assert status == 200 and out["choices"][0]["message"]["content"] == "Answer: Yes."
    assert SEEN[-1]["body"]["model"] == "gpt-4.1"
    assert SEEN[-1]["headers"]["authorization"] == "Bearer sk-OPENAI-SECRET-0001"
    c = g.calls_for("run01")[0]
    assert c["response_model"] == "gpt-4.1-2026" and c["input_tokens"] == 7


def test_anthropic_route_translates_both_ways(gateway):
    g, _ = gateway
    status, out = _call(g, "gpt-pw-m2")
    sent = SEEN[-1]
    assert sent["path"].endswith("/messages") and sent["headers"]["x-api-key"] == "sk-ant-SECRET-0002"
    assert sent["body"]["system"] == "You are an auditor." and sent["body"]["messages"][0]["role"] == "user"
    assert sent["body"]["model"] == "claude-test" and sent["body"]["temperature"] == 0.0
    assert status == 200 and out["choices"][0]["message"]["content"] == "Answer: No."
    assert out["usage"]["total_tokens"] == 14 and out["model"] == "claude-test-2026"


def test_gateway_token_required(gateway):
    g, _ = gateway
    status, _ = _call(g, "gpt-pw-m1", token="sk-OPENAI-SECRET-0001")
    assert status == 401 and not SEEN


def test_unknown_alias(gateway):
    g, _ = gateway
    assert _call(g, "gpt-4o")[0] == 404


def test_keys_never_recorded_or_returned(gateway):
    g, rm = gateway
    bad = rm.add("repoaudit", "openai", "gpt-bad", "sk-BADKEY1234")
    g.mark("r")
    status, out = _call(g, bad.alias)
    assert status == 401
    blob = json.dumps(out) + json.dumps(g.calls_for("r"))
    for secret in ("sk-OPENAI-SECRET-0001", "sk-ant-SECRET-0002", "sk-BADKEY1234", "BADKEY1234"):
        assert secret not in blob
    assert "[redacted]" in blob


def test_child_env_carries_only_gateway_token(gateway):
    g, _ = gateway
    env = g.child_env()
    assert env["OPENAI_API_KEY"].startswith("pwgw-") and "SECRET" not in json.dumps(env)
