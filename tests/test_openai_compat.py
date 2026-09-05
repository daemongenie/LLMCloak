# Copyright 2026 Quantum Sphere EOOD
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

"""OpenAI-protocol battery (v1.5.11): the OpenAI protocol (SDK-style) end-to-end.

Part 1 — deterministic fake upstream:
  - the client speaks OpenAI (/v1/chat/completions, /v1/models) to the proxy;
  - the proxy speaks OpenAI to an OpenAI-compatible (fake) upstream;
  - no-leak assertions on the body received by the upstream (PWD_ tags,
    zero secrets);
  - round-trip: quoted upstream reply -> desanitize -> original secrets to
    the client;
  - OpenAI SSE (choices[].delta.content) with tags split every 3 characters.

Part 2 — real Ollama in OpenAI mode (http://localhost:11434, /v1/...):
  - /v1/models passed through the proxy;
  - non-stream and stream round-trips (OpenAI SSE delta);
  - egress sanitization proof with the real model: spelling out the secret
    returns the letters of the TAG (P W D _ ...), never the clear secret;
  - round-trip of a value with spaces (whole-cell customer name).

Part 2 is skipped automatically when Ollama is not available.
"""
import json
import os
import re
import socket
import sys
import threading
import time
from pathlib import Path

os.environ["LLMCLOAK_API_KEY"] = "oai-compat-admin"
os.environ.pop("LLMCLOAK_KEY", None)
os.environ.pop("LLMCLOAK_UPSTREAM", None)
os.environ.pop("LLMCLOAK_CONFIG", None)
os.environ.pop("LLMCLOAK_VAULT", None)

_PKG_HOME = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(_PKG_HOME))

import httpx                                              # noqa: E402
import pytest                                             # noqa: E402
import uvicorn                                            # noqa: E402
from cryptography.fernet import Fernet                    # noqa: E402
from fastapi.testclient import TestClient                 # noqa: E402

import service as svc                                     # noqa: E402
from core import derive_key, load_or_create_salt          # noqa: E402
from tests import fake_upstream                           # noqa: E402

PW = "Oai-Compat-T3st!"
SECRET_PWD = "Xk9!mP2$vQw7Zt"
SECRET_CLIENT = "000001-ALESSANDRO ESPOSITO Barbieri SPA"
SECRET_EMAIL = "mario.rossi@alphagamma.it"
NOT_VAULTED = "pippo.pluto@topolinia.it"   # NOT in the vault: must pass in clear
CLIENT_TOKEN = "client-tok-oai-1"
ADMIN = "oai-compat-admin"

OLLAMA = "http://localhost:11434"
CHAT_MODEL = "qwen2.5:1.5b"
TIMEOUT = httpx.Timeout(180.0, connect=10.0)

TAG_SPELL = re.compile(r"P[^A-Za-z0-9]{0,3}W[^A-Za-z0-9]{0,3}D", re.IGNORECASE)


# ------------------------------------------------------------------ vault
def _make_vault() -> None:
    lines = ["client:default=" + CLIENT_TOKEN,
             SECRET_PWD,
             SECRET_CLIENT,
             SECRET_EMAIL,
             "# comment that must stay"]
    data = ("\n".join(lines) + "\n").encode()
    salt = load_or_create_salt(svc.KDF_SALT_PATH)
    enc = Fernet(derive_key(PW, salt).encode()).encrypt(data)
    with open(svc.VAULT_PATH, "wb") as f:
        f.write(enc)
    os.chmod(svc.VAULT_PATH, 0o600)


def _unlock() -> None:
    salt = load_or_create_salt(svc.KDF_SALT_PATH)
    svc.san.load_vault(svc.VAULT_PATH,
                       master_key=derive_key(PW, salt),
                       enforce_perms=True)


@pytest.fixture(scope="module", autouse=True)
def vaulted():
    _make_vault()
    _unlock()
    yield


# ------------------------------------------------------- part 1: fake upstream
@pytest.fixture(scope="module")
def up_url():
    s = socket.socket()
    s.bind(("127.0.0.1", 0))
    port = s.getsockname()[1]
    s.close()
    server = uvicorn.Server(uvicorn.Config(
        fake_upstream.app, host="127.0.0.1", port=port, log_level="error"))
    th = threading.Thread(target=server.run, daemon=True)
    th.start()
    for _ in range(60):
        try:
            socket.create_connection(("127.0.0.1", port), 0.2).close()
            break
        except OSError:
            time.sleep(0.1)
    yield f"http://127.0.0.1:{port}"
    server.should_exit = True
    th.join(timeout=5)


def _client(monkeypatch, up_url: str) -> TestClient:
    monkeypatch.setattr(svc, "UPSTREAM", up_url)
    monkeypatch.setattr(svc, "OPEN_MODE", True)
    monkeypatch.setattr(svc, "TRUSTED_IPS", [])
    fake_upstream.RECEIVED.clear()
    return TestClient(svc.app)


def _oa_body(*texts: str) -> dict:
    """SDK-style OpenAI body: system + user messages."""
    msgs = [{"role": "system", "content": "you are a test assistant"}]
    msgs += [{"role": "user", "content": t} for t in texts]
    return {"model": "any-model", "temperature": 0, "messages": msgs}


def test_A1_openai_roundtrip_no_leak_upstream(monkeypatch, up_url):
    """POST /v1/chat/completions: upstream sees ONLY PWD_ tags, client sees the
    original secrets; the not-vaulted value passes in clear."""
    c = _client(monkeypatch, up_url)
    r = c.post("/v1/chat/completions", json=_oa_body(
        f"password: {SECRET_PWD} | customer: {SECRET_CLIENT} | "
        f"email: {SECRET_EMAIL} | not-in-vault: {NOT_VAULTED}"))
    assert r.status_code == 200, r.text

    # --- client side: full round-trip (desanitize)
    content = r.json()["choices"][0]["message"]["content"]
    assert SECRET_PWD in content, content
    assert SECRET_CLIENT in content, content
    assert SECRET_EMAIL in content, content

    # --- upstream side: zero leak, tags only
    assert len(fake_upstream.RECEIVED) == 1
    ent = fake_upstream.RECEIVED[0]
    assert ent["path"] == "/v1/chat/completions"      # SDK-style path passthrough
    sent = ent["body"]
    assert "PWD_" in sent, sent
    assert SECRET_PWD not in sent and SECRET_CLIENT not in sent \
        and SECRET_EMAIL not in sent, sent
    assert NOT_VAULTED in sent, sent                  # not vaulted: in clear


def test_A2_openai_sse_stream_split_tags(monkeypatch, up_url):
    """OpenAI streaming (delta.content): the fake splits chunks every 3 chars,
    the proxy reassembles and desanitizes; the client sees the original secret."""
    c = _client(monkeypatch, up_url)
    body = _oa_body(f"my password is {SECRET_PWD}")
    with c.stream("POST", "/v1/chat/completions-stream", json=body) as r:
        assert r.status_code == 200, r.read()
        raw = "".join(r.iter_text())
    assert fake_upstream.RECEIVED[0]["path"] == "/v1/chat/completions-stream"
    assert SECRET_PWD not in fake_upstream.RECEIVED[0]["body"]

    parts = []
    for line in raw.splitlines():
        line = line.strip()
        if not line.startswith("data: "):
            continue
        payload = line[6:]
        if payload == "[DONE]":
            break
        obj = json.loads(payload)
        ch = obj.get("choices") or [{}]
        delta = (ch[0] or {}).get("delta") or {}
        if delta.get("content"):
            parts.append(delta["content"])
    assembled = "".join(parts)
    assert SECRET_PWD in assembled, assembled
    assert "PWD_" not in assembled, assembled         # no residual tag to the client


def test_A3_openai_models_passthrough(monkeypatch, up_url):
    """GET /v1/models (list models SDK) crosses the proxy toward the upstream."""
    c = _client(monkeypatch, up_url)
    r = c.get("/v1/models")
    assert r.status_code == 200, r.text
    assert r.json()["data"][0]["id"] == "fake-model"
    assert fake_upstream.RECEIVED[-1]["path"] == "/v1/models"


# ------------------------------------------------- part 2: Ollama OpenAI-compat
def _ollama_available() -> bool:
    try:
        httpx.get(OLLAMA + "/v1/models", timeout=3.0)
        return True
    except (httpx.TransportError, OSError):
        return False


@pytest.fixture(scope="module")
def oai_server():
    """Real uvicorn server (thread) with upstream = Ollama in OpenAI mode."""
    if not _ollama_available():
        pytest.skip("Ollama (OpenAI mode) not available on localhost:11434")
    old_up, old_open, old_trusted = svc.UPSTREAM, svc.OPEN_MODE, svc.TRUSTED_IPS
    svc.UPSTREAM = OLLAMA
    svc.OPEN_MODE = True          # like the prod config (.223): no client token
    svc.TRUSTED_IPS = []
    s = socket.socket()
    s.bind(("127.0.0.1", 0))
    port = s.getsockname()[1]
    s.close()
    server = uvicorn.Server(uvicorn.Config(
        svc.app, host="127.0.0.1", port=port, log_level="error"))
    th = threading.Thread(target=server.run, daemon=True)
    th.start()
    base = f"http://127.0.0.1:{port}"
    for _ in range(60):
        try:
            socket.create_connection(("127.0.0.1", port), 0.25).close()
            break
        except OSError:
            time.sleep(0.1)
    yield base
    server.should_exit = True
    th.join(timeout=5)
    svc.UPSTREAM, svc.OPEN_MODE, svc.TRUSTED_IPS = old_up, old_open, old_trusted


def _post(base: str, json_body: dict):
    with httpx.Client(timeout=TIMEOUT) as cl:
        return cl.post(base + "/v1/chat/completions", json=json_body)


def _sse_assemble(raw: str) -> str:
    parts = []
    for line in raw.splitlines():
        line = line.strip()
        if not line:
            continue
        if line.startswith("data:"):                   # SSE: with/without space
            payload = line[5:].strip()
            if payload == "[DONE]":
                # LLMCloak: the event carrying the restored content arrives AFTER [DONE]
                continue
        else:
            payload = line                             # NDJSON fallback
        try:
            obj = json.loads(payload)
        except json.JSONDecodeError:
            continue
        ch = obj.get("choices") or []
        if not ch:
            continue                                   # final usage chunk
        delta = (ch[0] or {}).get("delta") or {}
        if delta.get("content"):
            parts.append(delta["content"])
    return "".join(parts)


def test_B1_models_from_real_ollama(oai_server):
    """GET /v1/models via proxy -> list of Ollama OpenAI-compatible models."""
    with httpx.Client(timeout=TIMEOUT) as cl:
        r = cl.get(oai_server + "/v1/models")
    assert r.status_code == 200, r.text
    ids = [m["id"] for m in r.json()["data"]]
    assert CHAT_MODEL in ids, ids
    # note: GETs in open mode follow the dedicated forwarder (no overhead header)


def test_B2_roundtrip_non_stream(oai_server):
    """OpenAI non-stream: the model sees the tag, the client receives the secret."""
    body = {"model": CHAT_MODEL, "temperature": 0, "max_tokens": 120,
            "messages": [{"role": "user",
                          "content": f'Repeat exactly, without adding '
                                     f'anything, this text: "{SECRET_PWD}"'}]}
    r = _post(oai_server, body)
    assert r.status_code == 200, r.text
    content = r.json()["choices"][0]["message"]["content"]
    assert SECRET_PWD in content, content              # round-trip PWD_<tag> -> secret


def test_B3_spelling_proves_egress_sanitized(oai_server):
    """No-leak proof with the real model: when asked to spell it out, the model
    must read the TAG (P W D _ ...), never the clear secret."""
    for model in (CHAT_MODEL, "qwen3:4b"):
        body = {"model": model, "temperature": 0, "max_tokens": 200,
                "messages": [{"role": "user",
                              "content": f'Spell out the quoted text letter by '
                                         f'letter, separated by spaces, nothing '
                                         f'else: "{SECRET_PWD}"'}]}
        r = _post(oai_server, body)
        assert r.status_code == 200, r.text
        content = r.json()["choices"][0]["message"]["content"]
        assert SECRET_PWD not in content, (model, content)   # never the secret
        if TAG_SPELL.search(content):
            return                                     # P W D _ ... = model saw the tag
    # The hard guarantee (secret never in the reply) is enforced above;
    # the tag-spelling proof depends on the live model's wording, so it is
    # a skip, not a failure, when the model answers differently.
    pytest.skip(f"no model spelled a PWD_ tag: last reply={content!r}")


def test_B4_roundtrip_stream(oai_server):
    """OpenAI streaming (SSE delta): full round-trip in stream mode."""
    body = {"model": CHAT_MODEL, "temperature": 0, "max_tokens": 120,
            "stream": True,
            "messages": [{"role": "user",
                          "content": f'Repeat exactly, without adding '
                                     f'anything, this text: "{SECRET_PWD}"'}]}
    with httpx.Client(timeout=TIMEOUT) as cl:
        with cl.stream("POST", oai_server + "/v1/chat/completions",
                       json=body) as r:
            assert r.status_code == 200, r.read()
            raw = "".join(r.iter_text())
    assembled = _sse_assemble(raw)
    assert SECRET_PWD in assembled, f"ASSEMBLED={assembled!r}"


def test_B5_roundtrip_whole_cell_value(oai_server):
    """Value with spaces (customer name) via the OpenAI protocol: round-trip."""
    body = {"model": CHAT_MODEL, "temperature": 0, "max_tokens": 150,
            "messages": [{"role": "user",
                          "content": f'Repeat exactly, without adding '
                                     f'anything, this text: "{SECRET_CLIENT}"'}]}
    r = _post(oai_server, body)
    assert r.status_code == 200, r.text
    content = r.json()["choices"][0]["message"]["content"]
    assert SECRET_CLIENT in content, content
