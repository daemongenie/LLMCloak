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

"""Test open mode (v1.2.7): optional client token on the transparent path.

Runs STANDALONE (pytest tests/test_open_mode.py): sets an isolated env
before the service import. The needed globals (UPSTREAM, OPEN_MODE,
TRUSTED_IPS, UPSTREAM_NO_AUTH) are mutated in individual tests via
monkeypatch, so the tests are independent of import order.

Coverage:
  1. open_mode=false: 401 without token, 200 with token (v1.2.6 regression)
  2. open_mode=true:  200 without token, sanitize/desanitize roundtrip ok
  3. open_mode=true + trusted_ips: 403 for foreign IP, 200 for listed IP
  4. vault locked: 503 even in open mode (fail-safe, NO forward)
  5. /sanitize (mode B) still requires authentication in open mode
  6. /admin/status exposes open_mode/trusted_ips
"""
import json
import os
import socket
import sys
import tempfile
import threading
import time
import uvicorn
from pathlib import Path

import pytest

_PKG_HOME = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(_PKG_HOME))

# ISOLATED env before the service import (if not imported yet)
_TMPDIR = tempfile.mkdtemp(prefix="sp_open_test_")
os.environ["LLMCLOAK_VAULT"] = os.path.join(_TMPDIR, "vault.txt")
os.environ["LLMCLOAK_CONFIG"] = os.path.join(_TMPDIR, "service_config.json")
os.environ["LLMCLOAK_API_KEY"] = "open-test-admin"
os.environ["LLMCLOAK_UPSTREAM"] = ""
os.environ.pop("LLMCLOAK_KEY", None)

from cryptography.fernet import Fernet                       # noqa: E402
from fastapi.testclient import TestClient                    # noqa: E402

import service as svc                     # noqa: E402
from core import derive_key, load_or_create_salt  # noqa: E402
from tests import fake_upstream                # noqa: E402
from fastapi import FastAPI as _FastAPI                      # noqa: E402

# mini-upstream with GET routes (to test forwarding without auth)
tags_app = _FastAPI()


@tags_app.get("/api/tags")
async def _tags():
    return {"models": [{"name": "fake-model"}]}

PW = "Open-T3st-Pass!"
SECRET_A = "Ex4mpl3-P@ss!42"
CLIENT_TOKEN = "agent-token-open-1"
PROVIDER_KEY = "sk-provider-real-key-open"
ADMIN = "open-test-admin"


# ------------------------------------------------------------------ helpers
def _make_vault(encrypted: bool = True, passphrase: str = PW) -> None:
    lines = [f"client:default={CLIENT_TOKEN}",
             f"provider:default={PROVIDER_KEY}",
             SECRET_A,
             "# comment that must remain"]
    data = ("\n".join(lines) + "\n").encode()
    if encrypted:
        salt = load_or_create_salt(svc.KDF_SALT_PATH)
        data = Fernet(derive_key(passphrase, salt).encode()).encrypt(data)
    with open(svc.VAULT_PATH, "wb") as f:
        f.write(data)
    os.chmod(svc.VAULT_PATH, 0o600)


def _unlock(passphrase: str = PW) -> None:
    """Loads the encrypted vault in memory (like /admin/unlock)."""
    salt = load_or_create_salt(svc.KDF_SALT_PATH)
    svc.san.load_vault(svc.VAULT_PATH, master_key=derive_key(passphrase, salt),
                       enforce_perms=True)


@pytest.fixture(scope="module")
def up_url():
    """Fake upstream in a thread (like e2e, but in-process)."""
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


def _client(monkeypatch, up_url: str, open_mode: bool,
            trusted=None, client_ip=None) -> TestClient:
    _make_vault(encrypted=True)
    _unlock()
    monkeypatch.setattr(svc, "UPSTREAM", up_url)
    monkeypatch.setattr(svc, "OPEN_MODE", open_mode)
    monkeypatch.setattr(svc, "TRUSTED_IPS", list(trusted or []))
    fake_upstream.RECEIVED.clear()
    kwargs = {"client": (client_ip, 50000)} if client_ip else {}
    return TestClient(svc.app, **kwargs)


_CHAT = {"model": "m", "messages": [{"role": "user",
                                     "content": f"my password is {SECRET_A}"}]}


# ------------------------------------------------------------------ tests
def test_01_open_off_token_required(monkeypatch, up_url):
    """open_mode=false: without token 401; with token ok + no-leak + restore."""
    c = _client(monkeypatch, up_url, open_mode=False)
    r = c.post("/v1/chat/completions", json=_CHAT)
    assert r.status_code == 401, r.text
    assert fake_upstream.RECEIVED == []          # no forward

    r = c.post("/v1/chat/completions", json=_CHAT,
               headers={"Authorization": f"Bearer {CLIENT_TOKEN}"})
    assert r.status_code == 200, r.text
    assert len(fake_upstream.RECEIVED) == 1
    sent = fake_upstream.RECEIVED[0]["body"]
    assert SECRET_A not in sent                  # no-leak verso upstream
    assert "PWD_" in sent                        # pseudonym present
    assert SECRET_A in r.json()["choices"][0]["message"]["content"]  # restore


def test_02_open_on_no_token_roundtrip(monkeypatch, up_url):
    """open_mode=true: no token -> 200 with full roundtrip."""
    c = _client(monkeypatch, up_url, open_mode=True)
    r = c.post("/v1/chat/completions", json=_CHAT)   # NO auth header
    assert r.status_code == 200, r.text
    sent = fake_upstream.RECEIVED[0]["body"]
    assert SECRET_A not in sent and "PWD_" in sent
    assert SECRET_A in r.json()["choices"][0]["message"]["content"]


def test_03_open_on_whitelist(monkeypatch, up_url):
    """open_mode=true + trusted_ips: only listed sources, without token."""
    c = _client(monkeypatch, up_url, open_mode=True,
                trusted=["10.99.99.99"], client_ip="10.0.0.66")
    r = c.post("/v1/chat/completions", json=_CHAT)
    assert r.status_code == 403, r.text
    assert fake_upstream.RECEIVED == []

    c_ok = _client(monkeypatch, up_url, open_mode=True,
                   trusted=["10.99.99.99", "10.0.0.66"], client_ip="10.0.0.66")
    r = c_ok.post("/v1/chat/completions", json=_CHAT)
    assert r.status_code == 200, r.text
    assert len(fake_upstream.RECEIVED) == 1


def test_04_locked_failsafe_in_open_mode(monkeypatch, up_url):
    """vault locked: 503 even in open mode, no forwarding in clear."""
    c = _client(monkeypatch, up_url, open_mode=True)
    svc.san.lock()                               # simulate missing unlock
    try:
        r = c.post("/v1/chat/completions", json=_CHAT)
        assert r.status_code == 503, r.text
        assert fake_upstream.RECEIVED == []
        assert SECRET_A not in r.text            # the secret must not leak
    finally:
        _unlock()                                # restore for the tests that follow


def test_05_modeB_still_needs_token(monkeypatch, up_url):
    """/sanitize and /desanitize stay authenticated even in open mode."""
    c = _client(monkeypatch, up_url, open_mode=True)
    r = c.post("/sanitize", json={"text": f"pwd {SECRET_A}"})
    assert r.status_code == 401, r.text
    r = c.post("/desanitize", json={"text": "PWD_xxxxxxxxxxxx"})
    assert r.status_code == 401, r.text


def test_06_admin_status_reports_open_mode(monkeypatch, up_url):
    # ADMIN_KEY is read at import: in the full suite the effective value
    # depends on import order -> we force it for this single test
    monkeypatch.setattr(svc, "ADMIN_KEY", ADMIN)
    c = _client(monkeypatch, up_url, open_mode=True, trusted=["10.1.1.1"])
    r = c.get("/admin/status", headers={"X-Admin-Token": ADMIN})
    assert r.status_code == 200, r.text
    d = r.json()
    assert d["open_mode"] is True
    assert d["trusted_ips"] == ["10.1.1.1"]


def test_07_open_mode_get_requests_forwarded(monkeypatch):
    """Even GETs without auth pass (e.g. /api/tags of a native WebUI)."""
    s = socket.socket()
    s.bind(("127.0.0.1", 0))
    port = s.getsockname()[1]
    s.close()
    server = uvicorn.Server(uvicorn.Config(
        tags_app, host="127.0.0.1", port=port, log_level="error"))
    th = threading.Thread(target=server.run, daemon=True)
    th.start()
    for _ in range(60):
        try:
            socket.create_connection(("127.0.0.1", port), 0.2).close()
            break
        except OSError:
            time.sleep(0.1)
    try:
        c = _client(monkeypatch, f"http://127.0.0.1:{port}", open_mode=True)
        r = c.get("/api/tags")          # no Authorization
        assert r.status_code == 200, r.text
        assert r.json()["models"][0]["name"] == "fake-model"
    finally:
        server.should_exit = True
        th.join(timeout=5)



# --------------------------------------------------------------- v1.2.8
def test_08_auth_passthrough(monkeypatch, up_url):
    """v1.2.8: the client's Authorization/x-api-key are forwarded to the
    upstream as-is; without token no auth header (no vault injection)."""
    c = _client(monkeypatch, up_url, open_mode=True)
    hdr = {"Authorization": "Bearer sk-or-v1-client-key-123",
           "x-api-key": "prov-key-xyz"}
    r = c.post("/v1/chat/completions", json=_CHAT, headers=hdr)
    assert r.status_code == 200, r.text
    rec = fake_upstream.RECEIVED[-1]
    assert rec["authorization"] == "Bearer sk-or-v1-client-key-123", rec
    assert rec["x_api_key"] == "prov-key-xyz", rec
    # without token: no injection
    r2 = c.post("/v1/chat/completions", json=_CHAT)
    assert r2.status_code == 200, r2.text
    rec2 = fake_upstream.RECEIVED[-1]
    assert rec2["authorization"] == "" and rec2["x_api_key"] == "", rec2
    print("passthrough OK:", rec["authorization"], rec["x_api_key"])


def test_09_v1_prefix_normalization(monkeypatch):
    """v1.2.9: with an upstream ending in /v1 (e.g. OpenRouter /api/v1), the
    client's v1/ prefix is stripped (a WebUI with a base URL without /v1
    calls /v1/models -> without the fix it reaches {upstream}/v1/models ->
    404 HTML -> empty model list). With an upstream without /v1 the path
    stays verbatim."""
    norm = _FastAPI()

    @norm.get("/api/v1/models")                           # like a real OpenRouter
    async def models():
        return {"data": [{"id": "normalized-model"}]}

    s = socket.socket(); s.bind(("127.0.0.1", 0)); port = s.getsockname()[1]; s.close()
    server = uvicorn.Server(uvicorn.Config(norm, host="127.0.0.1", port=port, log_level="error"))
    th = threading.Thread(target=server.run, daemon=True); th.start()
    for _ in range(60):
        try:
            socket.create_connection(("127.0.0.1", port), 0.2).close(); break
        except OSError:
            time.sleep(0.1)
    try:
        # upstream WITH trailing /v1 -> strip the prefix
        c = _client(monkeypatch, f"http://127.0.0.1:{port}/api/v1", open_mode=True)
        r = c.get("/v1/models")
        assert r.status_code == 200, r.text
        assert r.json()["data"][0]["id"] == "normalized-model", r.text
        # upstream WITHOUT /v1 -> verbatim: /v1/models does not exist on norm -> 404
        c2 = _client(monkeypatch, f"http://127.0.0.1:{port}", open_mode=True)
        r2 = c2.get("/v1/models")
        assert r2.status_code == 404, r2.text
        print("/v1 normalization OK (strip only when upstream ends with /v1)")
    finally:
        server.should_exit = True
        th.join(timeout=5)
