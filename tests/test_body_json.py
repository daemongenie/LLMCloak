# v1.5.10 regression tests: the proxy must sanitize/desanitize PARSED
# JSON string fields, never the raw JSON text. With large CSV-ingested
# vaults, raw-text replacement rewrote JSON structure (numeric literals,
# true/null tokens, quotes/escapes inside values) producing bodies that
# upstreams rejected with '400 JSON parsing failed' (and breaking
# client-side JSON on restore when a secret contained quotes).
import json
import os
import sys
import tempfile
from pathlib import Path

import pytest

_PKG_HOME = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(_PKG_HOME))

_TMPDIR = tempfile.mkdtemp(prefix="sp_body_json_")
os.environ["SECRETS_PROXY_VAULT"] = os.path.join(_TMPDIR, "vault.txt")
os.environ["SECRETS_PROXY_CONFIG"] = os.path.join(_TMPDIR, "service_config.json")
os.environ["SECRETS_PROXY_API_KEY"] = "body-json-test-admin"
os.environ["SECRETS_PROXY_UPSTREAM"] = ""
os.environ.pop("SECRETS_PROXY_KEY", None)

import service as svc          # noqa: E402
from core import Sanitizer     # noqa: E402

SALT = b"\x5a" * 16
VALUES = ["3471234567", "00123", "true", 'say "hi"', "back\\slash",
          "Mario Rossi"]


@pytest.fixture()
def loaded_san():
    old = svc.san
    s = Sanitizer(salt=SALT)
    s.load_from_lists(VALUES)
    svc.san = s
    yield s
    svc.san = old


def test_numeric_literal_untouched(loaded_san):
    body = json.dumps({"model": "gpt-x",
                       "messages": [{"role": "user",
                                     "content": "cliente 3471234567 ok"}],
                       "external_id": 3471234567,
                       "stream": False}).encode()
    out, n = svc._sanitize_body(body)
    payload = json.loads(out.decode())          # must stay valid JSON
    assert isinstance(payload["external_id"], int)
    assert payload["external_id"] == 3471234567
    assert payload["stream"] is False
    assert payload["model"] == "gpt-x"          # keys untouched
    assert n == 1
    assert "3471234567" not in payload["messages"][0]["content"]
    assert "PWD_" in payload["messages"][0]["content"]


def test_boolean_token_untouched(loaded_san):
    body = json.dumps({"flag": True,
                       "messages": [{"role": "user",
                                     "content": "abilitato: true, conferma"}]}
                      ).encode()
    out, n = svc._sanitize_body(body)
    payload = json.loads(out.decode())
    assert payload["flag"] is True
    assert n == 1
    assert "true" not in payload["messages"][0]["content"]


def test_quoted_value_roundtrip(loaded_san):
    body = json.dumps({"messages": [{"role": "user",
                                     "content": 'ha detto: say "hi" ieri'}]}
                      ).encode()
    out, n = svc._sanitize_body(body)
    payload = json.loads(out.decode())
    assert n == 1 and 'say "hi"' not in payload["messages"][0]["content"]
    tag_txt = payload["messages"][0]["content"]
    resp = json.dumps({"choices": [{"message": {
        "role": "assistant", "content": f"echo: {tag_txt}"}}]}).encode()
    restored, r, un = svc._restore_response_text(resp.decode())
    obj = json.loads(restored)                  # must stay valid JSON
    assert obj["choices"][0]["message"]["content"] == \
        'echo: ha detto: say "hi" ieri'
    assert r == 1 and un == []


def test_backslash_value_roundtrip(loaded_san):
    body = json.dumps({"messages": [{"role": "user",
                                     "content": "percorso back\\slash fine"}]}
                      ).encode()
    out, n = svc._sanitize_body(body)
    payload = json.loads(out.decode())
    assert n == 1 and "back\\slash" not in payload["messages"][0]["content"]
    tag_txt = payload["messages"][0]["content"]
    resp = json.dumps({"content": f"cco: {tag_txt}"}).encode()
    restored, r, un = svc._restore_response_text(resp.decode())
    assert json.loads(restored)["content"] == \
        "cco: percorso back\\slash fine"
    assert r == 1 and un == []


def test_multimodal_parts(loaded_san):
    body = json.dumps({"messages": [{"role": "user", "content": [
        {"type": "text", "text": "cap 00123 qui"},
        {"type": "image_url",
         "image_url": {"url": "https://x/y.png"}}]}]}).encode()
    out, n = svc._sanitize_body(body)
    payload = json.loads(out.decode())
    parts = payload["messages"][0]["content"]
    assert n == 1 and "00123" not in parts[0]["text"]
    assert parts[1]["image_url"]["url"] == "https://x/y.png"


def test_non_json_legacy_path(loaded_san):
    raw = b"plain text 3471234567"
    out, n = svc._sanitize_body(raw)
    assert n == 1 and b"3471234567" not in out


def test_no_match_byte_perfect_passthrough(loaded_san):
    raw = b'{"messages":[{"role":"user","content":"nessun segreto qui"}]}'
    out, n = svc._sanitize_body(raw)
    assert n == 0 and out == raw


def test_restore_no_tags_identity(loaded_san):
    t = json.dumps({"a": 1, "b": "plain text"})
    out, r, un = svc._restore_response_text(t)
    assert out == t and r == 0 and un == []


def test_restore_unresolved_reported(loaded_san):
    t = json.dumps({"content": "tag PWD_deadbeef ignoto"})
    out, r, un = svc._restore_response_text(t)
    assert r == 0 and len(un) == 1 and json.loads(out)["content"] == \
        "tag PWD_deadbeef ignoto"


def test_notice_injection_after_fix(loaded_san):
    body = json.dumps({"messages": [{"role": "user",
                                     "content": "num 3471234567"}]}).encode()
    out, n = svc._sanitize_body(body)
    assert n == 1
    payload = svc._inject_notice(json.loads(out.decode()), n)
    obj = json.loads(json.dumps(payload).encode().decode())
    assert obj["messages"][0]["role"] == "system"
    assert "NOTICE" in obj["messages"][0]["content"]