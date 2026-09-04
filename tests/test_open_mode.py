"""Test open mode (v1.2.7): token client opzionale sul percorso trasparente.

Esegue STANDALONE (pytest tests/test_open_mode.py): imposta env isolato
prima dell'import del servizio. I global necessari (UPSTREAM, OPEN_MODE,
TRUSTED_IPS, UPSTREAM_NO_AUTH) vengono mutati nei singoli test via
monkeypatch, cosi' i test sono indipendenti dall'ordine di import.

Copertura:
  1. open_mode=false: 401 senza token, 200 con token (regressione v1.2.6)
  2. open_mode=true:  200 senza token, roundtrip sanitize/desanitize ok
  3. open_mode=true + trusted_ips: 403 per IP estraneo, 200 per IP in lista
  4. vault locked: 503 anche in open mode (fail-safe, NESSUN forward)
  5. /sanitize (mode B) resta ad autenticazione obbligatoria in open mode
  6. /admin/status espone open_mode/trusted_ips
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

# env ISOLATO prima dell'import del servizio (se non ancora importato)
_TMPDIR = tempfile.mkdtemp(prefix="sp_open_test_")
os.environ["SECRETS_PROXY_VAULT"] = os.path.join(_TMPDIR, "vault.txt")
os.environ["SECRETS_PROXY_CONFIG"] = os.path.join(_TMPDIR, "service_config.json")
os.environ["SECRETS_PROXY_API_KEY"] = "open-test-admin"
os.environ["SECRETS_PROXY_UPSTREAM"] = ""
os.environ.pop("SECRETS_PROXY_KEY", None)

from cryptography.fernet import Fernet                       # noqa: E402
from fastapi.testclient import TestClient                    # noqa: E402

import service as svc                     # noqa: E402
from core import derive_key, load_or_create_salt  # noqa: E402
from tests import fake_upstream                # noqa: E402
from fastapi import FastAPI as _FastAPI                      # noqa: E402

# mini-upstream con rotte GET (per testare il forward senza auth)
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
             "# commento che deve restare"]
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
    """Fake upstream in un thread (come e2e, ma in-process)."""
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
                                     "content": f"mia pwd e' {SECRET_A}"}]}


# ------------------------------------------------------------------ tests
def test_01_open_off_token_required(monkeypatch, up_url):
    """open_mode=false: senza token 401; con token ok + no-leak + restore."""
    c = _client(monkeypatch, up_url, open_mode=False)
    r = c.post("/v1/chat/completions", json=_CHAT)
    assert r.status_code == 401, r.text
    assert fake_upstream.RECEIVED == []          # niente forward

    r = c.post("/v1/chat/completions", json=_CHAT,
               headers={"Authorization": f"Bearer {CLIENT_TOKEN}"})
    assert r.status_code == 200, r.text
    assert len(fake_upstream.RECEIVED) == 1
    sent = fake_upstream.RECEIVED[0]["body"]
    assert SECRET_A not in sent                  # no-leak verso upstream
    assert "PWD_" in sent                        # pseudonimo presente
    assert SECRET_A in r.json()["choices"][0]["message"]["content"]  # restore


def test_02_open_on_no_token_roundtrip(monkeypatch, up_url):
    """open_mode=true: nessun token -> 200 con roundtrip completo."""
    c = _client(monkeypatch, up_url, open_mode=True)
    r = c.post("/v1/chat/completions", json=_CHAT)   # NIENTE header auth
    assert r.status_code == 200, r.text
    sent = fake_upstream.RECEIVED[0]["body"]
    assert SECRET_A not in sent and "PWD_" in sent
    assert SECRET_A in r.json()["choices"][0]["message"]["content"]


def test_03_open_on_whitelist(monkeypatch, up_url):
    """open_mode=true + trusted_ips: solo le sorgenti in lista, senza token."""
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
    svc.san.lock()                               # simula unlock mancante
    try:
        r = c.post("/v1/chat/completions", json=_CHAT)
        assert r.status_code == 503, r.text
        assert fake_upstream.RECEIVED == []
        assert SECRET_A not in r.text            # the secret must not leak
    finally:
        _unlock()                                # restore for the tests that follow


def test_05_modeB_still_needs_token(monkeypatch, up_url):
    """/sanitize e /desanitize restano autenticati anche in open mode."""
    c = _client(monkeypatch, up_url, open_mode=True)
    r = c.post("/sanitize", json={"text": f"pwd {SECRET_A}"})
    assert r.status_code == 401, r.text
    r = c.post("/desanitize", json={"text": "PWD_xxxxxxxxxxxx"})
    assert r.status_code == 401, r.text


def test_06_admin_status_reports_open_mode(monkeypatch, up_url):
    # ADMIN_KEY e' letto all'import: con l'intera suite il valore effettivo
    # dipende dall'ordine di import -> lo forziamo per il singolo test
    monkeypatch.setattr(svc, "ADMIN_KEY", ADMIN)
    c = _client(monkeypatch, up_url, open_mode=True, trusted=["10.1.1.1"])
    r = c.get("/admin/status", headers={"X-Admin-Token": ADMIN})
    assert r.status_code == 200, r.text
    d = r.json()
    assert d["open_mode"] is True
    assert d["trusted_ips"] == ["10.1.1.1"]


def test_07_open_mode_get_requests_forwarded(monkeypatch):
    """Anche le GET senza auth passano (es. /api/tags di una WebUI nativa)."""
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
        r = c.get("/api/tags")          # niente Authorization
        assert r.status_code == 200, r.text
        assert r.json()["models"][0]["name"] == "fake-model"
    finally:
        server.should_exit = True
        th.join(timeout=5)



# --------------------------------------------------------------- v1.2.8
def test_08_auth_passthrough(monkeypatch, up_url):
    """v1.2.8: Authorization/x-api-key del client girate all'upstream cosi'
    come sono; senza token nessun header auth (niente iniezione dal vault)."""
    c = _client(monkeypatch, up_url, open_mode=True)
    hdr = {"Authorization": "Bearer sk-or-v1-client-key-123",
           "x-api-key": "prov-key-xyz"}
    r = c.post("/v1/chat/completions", json=_CHAT, headers=hdr)
    assert r.status_code == 200, r.text
    rec = fake_upstream.RECEIVED[-1]
    assert rec["authorization"] == "Bearer sk-or-v1-client-key-123", rec
    assert rec["x_api_key"] == "prov-key-xyz", rec
    # senza token: nessuna iniezione
    r2 = c.post("/v1/chat/completions", json=_CHAT)
    assert r2.status_code == 200, r2.text
    rec2 = fake_upstream.RECEIVED[-1]
    assert rec2["authorization"] == "" and rec2["x_api_key"] == "", rec2
    print("passthrough OK:", rec["authorization"], rec["x_api_key"])


def test_09_v1_prefix_normalization(monkeypatch):
    """v1.2.9: con upstream che termina con /v1 (es. OpenRouter /api/v1), il
    prefisso v1/ del client viene strippato (la WebUI con base URL senza /v1
    chiama /v1/models -> senza fix arriva {upstream}/v1/models -> 404 HTML ->
    lista modelli vuota). Con upstream senza /v1 il path resta verbatim."""
    norm = _FastAPI()

    @norm.get("/api/v1/models")                           # come openrouter reale
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
        # upstream CON /v1 in coda -> strip del prefisso
        c = _client(monkeypatch, f"http://127.0.0.1:{port}/api/v1", open_mode=True)
        r = c.get("/v1/models")
        assert r.status_code == 200, r.text
        assert r.json()["data"][0]["id"] == "normalized-model", r.text
        # upstream SENZA /v1 -> verbatim: /v1/models non esiste su norm -> 404
        c2 = _client(monkeypatch, f"http://127.0.0.1:{port}", open_mode=True)
        r2 = c2.get("/v1/models")
        assert r2.status_code == 404, r2.text
        print("normalizzazione /v1 OK (strip solo se upstream finisce con /v1)")
    finally:
        server.should_exit = True
        th.join(timeout=5)
