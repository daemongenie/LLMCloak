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

"""
Test dashboard web v1.3.2 (TestClient in-process).

Coverage:
  1.  GET /dashboard serves the UI (no-store, X-Frame-Options DENY)
  2.  API without session -> 401
  3.  wrong passphrase -> 401 (encrypted vault), no cookie
  4.  correct login -> HttpOnly cookie + service unlock (mode A)
  5.  entry list: values ONLY masked, never in clear
  6.  add named/secret/pattern -> encrypted file (Fernet), perms 0600
  7.  duplicates rejected (409): line, name, value, regex
  8.  salt preserved: tags already issued stay valid after CRUD
  9.  edit (PUT) updates the encrypted file
  10. delete removes the entry; its tag becomes unresolved
  11. plain vault -> login ok -> 'Encrypt now' -> encrypted file + service reload
  12. logout invalidates the session
  13. service lock resets sessions and service state
  14. /dashboard routes registered BEFORE the catch-all (never proxied)
  15. upstream via dashboard (persisted in config) + visible to admin
  16. invalid inputs -> 400 (malformed regex, invalid named entry name, empty)
  17. show tag: pseudonymises PWD_* without exposing the value
  18. endpoints picker: add/select/delete, exclusive selection,
      fallback on deleting the active one
"""
import json
import os
import stat
import sys
import tempfile
from pathlib import Path

import pytest

_PKG_HOME = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(_PKG_HOME))

# env ISOLATO prima dell'import del servizio (e2e_test potrebbe aver
# impostato SECRETS_PROXY_UPSTREAM durante la collection)
_TMPDIR = tempfile.mkdtemp(prefix="sp_dash_test_")
os.environ["SECRETS_PROXY_VAULT"] = os.path.join(_TMPDIR, "vault.txt")
os.environ["SECRETS_PROXY_CONFIG"] = os.path.join(_TMPDIR, "service_config.json")
os.environ["SECRETS_PROXY_API_KEY"] = "dash-test-admin"
os.environ["SECRETS_PROXY_UPSTREAM"] = ""
os.environ.pop("SECRETS_PROXY_KEY", None)

from cryptography.fernet import Fernet                      # noqa: E402
from fastapi.testclient import TestClient                   # noqa: E402

import dashboard as dash                 # noqa: E402
import service as svc                    # noqa: E402
from core import derive_key, load_or_create_salt  # noqa: E402

ADMIN = {"X-Admin-Token": "dash-test-admin"}
PW = "Dashboard-T3st-Pass!"
SECRET_A = "Ex4mpl3-P@ss!42"
SECRET_B = "s3cr3t-API-KEY-xyz"
CLIENT_TOKEN = "agent-token-dash-1"
PROVIDER_KEY = "sk-provider-real-key-dash"


# ------------------------------------------------------------------ helpers
def _make_vault(encrypted: bool, passphrase: str = PW,
                lines=None) -> None:
    """Writes svc.VAULT_PATH (plain or encrypted) + salt, perms 0600."""
    lines = lines if lines is not None else [
        f"client:default={CLIENT_TOKEN}",
        f"provider:default={PROVIDER_KEY}",
        SECRET_A,
        SECRET_B,
        "# commento che deve restare",
    ]
    data = ("\n".join(lines) + "\n").encode()
    if encrypted:
        salt = load_or_create_salt(svc.KDF_SALT_PATH)
        data = Fernet(derive_key(passphrase, salt).encode()).encrypt(data)
    with open(svc.VAULT_PATH, "wb") as f:
        f.write(data)
    os.chmod(svc.VAULT_PATH, 0o600)


def _file_is_encrypted() -> bool:
    with open(svc.VAULT_PATH, "rb") as f:
        return f.read(8).startswith(b"gAAAAA")


def _decrypt_file(passphrase: str = PW) -> str:
    salt = load_or_create_salt(svc.KDF_SALT_PATH)
    with open(svc.VAULT_PATH, "rb") as f:
        raw = f.read()
    if raw.startswith(b"gAAAAA"):
        raw = Fernet(derive_key(passphrase, salt).encode()).decrypt(raw)
    return raw.decode()


def _reset(encrypted: bool = True) -> TestClient:
    svc.san.lock()
    dash.SESSIONS.drop_all()
    _make_vault(encrypted)
    # il servizio riparte LOCKED come a un avvio reale (niente startup event
    # ripetibile: simuliamo lo stato locked esplicitamente)
    return TestClient(svc.app)


def _login(client: TestClient, passphrase: str = PW):
    return client.post("/dashboard/api/session",
                       json={"passphrase": passphrase})


# ------------------------------------------------------------------ tests
def test_01_dashboard_page_served():
    c = _reset()
    r = c.get("/dashboard")
    assert r.status_code == 200
    assert "LLMCloak" in r.text
    assert r.headers.get("x-frame-options") == "DENY"
    assert "no-store" in r.headers.get("cache-control", "")
    # UI must not contain secrets
    assert SECRET_A not in r.text and PROVIDER_KEY not in r.text


def test_02_api_requires_session():
    c = _reset()
    for path, method in [("/dashboard/api/state", "get"),
                         ("/dashboard/api/entries", "post"),
                         ("/dashboard/api/lock", "post"),
                         ("/dashboard/api/upstream", "get")]:
        r = getattr(c, method)(path, **({"json": {}} if method == "post" else {}))
        assert r.status_code == 401, (path, r.status_code)


def test_03_login_wrong_passphrase():
    c = _reset(encrypted=True)
    r = _login(c, "passphrase-sbagliata")
    assert r.status_code == 401
    assert dash.SESSION_COOKIE not in (r.headers.get("set-cookie") or "")
    assert dash.SESSIONS.count() == 0
    # il servizio resta locked
    h = c.get("/health").json()
    assert h["status"] == "locked"


def test_04_login_ok_unlocks_service():
    c = _reset(encrypted=True)
    r = _login(c)
    assert r.status_code == 200, r.text
    body = r.json()
    assert body["ok"] is True and body["unlocked_service"] is True
    sc = r.headers.get("set-cookie", "")
    assert dash.SESSION_COOKIE in sc and "HttpOnly" in sc.replace("httponly", "HttpOnly")
    st = c.get("/dashboard/api/state").json()
    assert st["service"] == "active"
    assert st["vault_encrypted"] is True
    h = c.get("/health").json()
    assert h["status"] == "active" and h["named"] == 2 and h["secrets"] == 2


def test_05_entries_never_plaintext():
    c = _reset()
    assert _login(c).status_code == 200
    st = c.get("/dashboard/api/state")
    assert st.status_code == 200
    txt = st.text
    assert SECRET_A not in txt, "plain secret leaked in response!"
    assert PROVIDER_KEY not in txt, "named value leaked in response!"
    entries = st.json()["entries"]
    kinds = {e["kind"] for e in entries}
    assert {"named", "secret"} <= kinds
    named = [e for e in entries if e["kind"] == "named"]
    assert all(e["value"] is None and e["masked"] for e in named)
    assert any(e["name"] == "client:default" for e in named)
    # maschera: primi 3 + ... + ultimi 2
    m = [e["masked"] for e in entries if e["kind"] == "secret" and SECRET_A.startswith(e["masked"][:3])]
    assert m and "…" in m[0]


def test_06_add_entries_file_encrypted():
    c = _reset()
    assert _login(c).status_code == 200
    r = c.post("/dashboard/api/entries",
               json={"kind": "named", "name": "provider:secondary",
                     "value": "sk-second-key-999"})
    assert r.status_code == 200, r.text
    r = c.post("/dashboard/api/entries",
               json={"kind": "secret", "value": "nuovo-secret-xyz"})
    assert r.status_code == 200
    r = c.post("/dashboard/api/entries",
               json={"kind": "pattern", "value": "ghp_[a-zA-Z0-9]{36}"})
    assert r.status_code == 200
    # encrypted file + perms
    assert _file_is_encrypted() is True
    mode = stat.S_IMODE(os.stat(svc.VAULT_PATH).st_mode)
    assert mode == 0o600, oct(mode)
    # content decryptable with the key derived from the passphrase
    plain = _decrypt_file()
    assert "provider:secondary=sk-second-key-999" in plain
    assert "nuovo-secret-xyz" in plain
    assert "re:ghp_[a-zA-Z0-9]{36}" in plain
    assert "# commento che deve restare" in plain
    # service reloaded: sanitize sees the new secrets
    r = c.post("/sanitize", headers={"Authorization": f"Bearer {CLIENT_TOKEN}"},
               json={"text": "key sk-second-key-999 in use"})
    assert r.status_code == 200
    assert "sk-second-key-999" not in r.json()["text"]


def test_07_duplicates_rejected():
    c = _reset()
    assert _login(c).status_code == 200
    # riga identica
    assert c.post("/dashboard/api/entries",
                  json={"kind": "secret", "value": SECRET_A}).status_code == 409
    # stesso nome nominata
    assert c.post("/dashboard/api/entries",
                  json={"kind": "named", "name": "client:default",
                        "value": "altro-token"}).status_code == 409
    # valore uguale a una nominata esistente
    assert c.post("/dashboard/api/entries",
                  json={"kind": "secret", "value": PROVIDER_KEY}).status_code == 409
    # stessa regex
    c.post("/dashboard/api/entries",
           json={"kind": "pattern", "value": "AKIA[0-9A-Z]{16}"})
    assert c.post("/dashboard/api/entries",
                  json={"kind": "pattern", "value": "AKIA[0-9A-Z]{16}"}).status_code == 409


def test_08_salt_preserved_tags_stable():
    c = _reset()
    assert _login(c).status_code == 200
    text = f"la pwd e' {SECRET_A} grazie"
    r1 = c.post("/sanitize", headers={"Authorization": f"Bearer {CLIENT_TOKEN}"},
                json={"text": text}).json()
    assert r1["replaced"] == 1 and "PWD_" in r1["text"]
    tag = r1["text"].replace("la pwd e' ", "").replace(" grazie", "")
    # CRUD: aggiunta + rimozione di una voce qualsiasi
    c.post("/dashboard/api/entries", json={"kind": "secret", "value": "tmp-vocex"})
    r2 = c.post("/sanitize", headers={"Authorization": f"Bearer {CLIENT_TOKEN}"},
                json={"text": text}).json()
    assert r2["text"] == r1["text"], "salt cambiato: tag non stabile!"
    # desanitize still restores the secret (consistent reverse-map)
    r3 = c.post("/desanitize", headers={"Authorization": f"Bearer {CLIENT_TOKEN}"},
                json={"text": r2["text"]}).json()
    assert r3["text"] == text


def test_09_edit_entry():
    c = _reset()
    assert _login(c).status_code == 200
    st = c.get("/dashboard/api/state").json()
    eid = [e["id"] for e in st["entries"]
           if e["kind"] == "secret"][0]
    r = c.put(f"/dashboard/api/entries/{eid}",
              json={"value": "secret-changed-777"})
    assert r.status_code == 200, r.text
    plain = _decrypt_file()
    assert "secret-changed-777" in plain and SECRET_A not in plain
    # edit nominata: valore sostituito
    eid_named = [e["id"] for e in c.get("/dashboard/api/state").json()["entries"]
                 if e["kind"] == "named" and e["name"] == "provider:default"][0]
    r = c.put(f"/dashboard/api/entries/{eid_named}",
              json={"value": "sk-provider-new-key"})
    assert r.status_code == 200
    assert "provider:default=sk-provider-new-key" in _decrypt_file()
    # il servizio usa il nuovo valore (iniezione provider)
    # (verifica indiretta: sanitize non deve piu' mascherare il vecchio)
    r = c.post("/sanitize", headers={"Authorization": f"Bearer {CLIENT_TOKEN}"},
               json={"text": "sk-provider-new-key"})
    assert "sk-provider-new-key" not in r.json()["text"]


def test_10_delete_entry_tag_unresolved():
    c = _reset()
    assert _login(c).status_code == 200
    tag = c.post("/sanitize", headers={"Authorization": f"Bearer {CLIENT_TOKEN}"},
                 json={"text": SECRET_A}).json()["text"]
    st = c.get("/dashboard/api/state").json()
    eid = [e["id"] for e in st["entries"]
           if e["kind"] == "secret" and e["masked"].startswith(SECRET_A[:3])][0]
    assert c.delete(f"/dashboard/api/entries/{eid}").status_code == 200
    plain = _decrypt_file()
    assert SECRET_A not in plain
    # il vecchio tag non e' piu' risolvibile (fail-safe: resta tag, audit)
    r = c.post("/desanitize", headers={"Authorization": f"Bearer {CLIENT_TOKEN}"},
               json={"text": tag}).json()
    assert r["restored"] == 0 and r["unresolved"]


def test_10b_auth_passthrough_no_provider_check():
    """v1.2.8: il check su provider:default e' RIMOSSO — auth passthrough.
    La richiesta /v1/* non fallisce piu' con 503 'provider:default mancante':
    con upstream irraggiungibile l'errore e' di connessione, non di vault."""
    from fastapi.testclient import TestClient
    c = _reset()
    assert _login(c).status_code == 200
    # nessuna voce provider:* nel vault (resta solo client:*)
    ents = c.get("/dashboard/api/state").json()["entries"]
    for e in ents:
        if e["kind"] == "named" and (e.get("name") or "").startswith("provider:"):
            assert c.delete(f"/dashboard/api/entries/{e['id']}").status_code == 200
    hdr = {"Authorization": f"Bearer {CLIENT_TOKEN}"}
    old_up = svc.UPSTREAM
    svc.UPSTREAM = "http://127.0.0.1:9"   # porta discard: irraggiungibile
    try:
        c2 = TestClient(svc.app, raise_server_exceptions=False)
        r = c2.get("/v1/models", headers=hdr)
        assert r.status_code != 503, r.text
        assert "provider:default" not in (r.text or "")
    finally:
        svc.UPSTREAM = old_up


def test_11_plain_vault_encrypt_now():
    c = _reset(encrypted=False)
    assert _file_is_encrypted() is False
    r = _login(c)   # vault plain: qualunque passphrase non vuota
    assert r.status_code == 200
    st = c.get("/dashboard/api/state").json()
    assert st["vault_encrypted"] is False
    # fino a qui il file resta plain (nessuna scrittura a sorpresa)
    assert _file_is_encrypted() is False
    r = c.post("/dashboard/api/encrypt")
    assert r.status_code == 200
    assert _file_is_encrypted() is True
    assert SECRET_A in _decrypt_file()
    st = c.get("/dashboard/api/state").json()
    assert st["vault_encrypted"] is True and st["service"] == "active"
    # encrypt doppio -> 400
    assert c.post("/dashboard/api/encrypt").status_code == 400


def test_12_logout_invalidates():
    c = _reset()
    assert _login(c).status_code == 200
    assert c.delete("/dashboard/api/session").status_code == 200
    assert c.get("/dashboard/api/state").status_code == 401


def test_13_lock_drops_sessions():
    c = _reset()
    assert _login(c).status_code == 200
    assert c.post("/dashboard/api/lock").status_code == 200
    assert c.get("/dashboard/api/state").status_code == 401
    h = c.get("/health").json()
    assert h["status"] == "locked"
    assert dash.SESSIONS.count() == 0


def test_14_dashboard_not_proxied():
    """Con upstream attivo, /dashboard e /dashboard/api/* NON finiscono nel
    catch-all proxy (sono route esplicite registrate prima); il catch-all
    resta comunque vivo per i path LLM arbitrari."""
    c = _reset()
    old = svc.UPSTREAM
    try:
        svc.UPSTREAM = "http://127.0.0.1:1"   # catch-all attivo (irraggiungibile)
        r = c.get("/dashboard")
        assert r.status_code == 200 and "LLMCloak" in r.text
        # state without session -> 401 from the DASHBOARD (session), not the proxy
        r = c.get("/dashboard/api/state")
        assert r.status_code == 401
        assert "session" in r.json()["detail"]
        # il catch-all proxy e' ancora registrato: fail-closed senza vault
        r = c.get("/some/llm/path")
        assert r.status_code == 503
        # ...e con servizio attivo chiede l'auth client (non tocca la dashboard)
        assert _login(c).status_code == 200
        r = c.get("/some/llm/path",
                  headers={"Authorization": "Bearer token-sbagliato"})
        assert r.status_code == 401
        assert r.json()["detail"] == "invalid client token"
    finally:
        svc.UPSTREAM = old


def test_15_upstream_via_dashboard():
    c = _reset()
    assert _login(c).status_code == 200
    url = "http://192.0.2.10:11434"
    r = c.post("/dashboard/api/upstream", json={"url": url})
    assert r.status_code == 200 and r.json()["persisted"] is True
    cfg = json.load(open(svc.CONFIG_PATH))
    assert cfg["upstream"] == url
    r = c.get("/admin/upstream", headers=ADMIN)
    assert r.status_code == 200 and r.json()["upstream"] == url
    # url invalido
    assert c.post("/dashboard/api/upstream",
                  json={"url": "ftp://nope"}).status_code == 400


def test_16_invalid_inputs():
    c = _reset()
    assert _login(c).status_code == 200
    assert c.post("/dashboard/api/entries",
                  json={"kind": "secret", "value": ""}).status_code == 400
    assert c.post("/dashboard/api/entries",
                  json={"kind": "pattern",
                        "value": "sk-[[[malformed"}).status_code == 400
    assert c.post("/dashboard/api/entries",
                  json={"kind": "named", "name": "badname",
                        "value": "x"}).status_code == 400
    assert c.post("/dashboard/api/entries",
                  json={"kind": "named", "name": "",
                        "value": "x"}).status_code == 400
    assert c.post("/dashboard/api/session",
                  json={"passphrase": ""}).status_code == 400
    # id inesistente
    assert c.delete("/dashboard/api/entries/deadbeefdead").status_code == 404
    assert c.put("/dashboard/api/entries/deadbeefdead",
                 json={"value": "x"}).status_code == 404


def test_17_show_tag_without_plaintext():
    c = _reset()
    assert _login(c).status_code == 200
    st = c.get("/dashboard/api/state").json()
    eid = [e["id"] for e in st["entries"]
           if e["kind"] == "named" and e["name"] == "client:default"][0]
    r = c.post(f"/dashboard/api/entries/{eid}/tag")
    assert r.status_code == 200
    tag = r.json()["tag"]
    assert tag.startswith("PWD_") and len(tag) > len("PWD_")
    assert CLIENT_TOKEN not in r.text
    # pattern: nessun tag fisso
    eid_p = [e["id"] for e in st["entries"] if e["kind"] == "pattern"]
    assert not eid_p   # il vault di default non ha pattern
    c.post("/dashboard/api/entries", json={"kind": "pattern", "value": "x[0-9]+"})
    st = c.get("/dashboard/api/state").json()
    eid_p = [e["id"] for e in st["entries"] if e["kind"] == "pattern"][0]
    assert c.post(f"/dashboard/api/entries/{eid_p}/tag").status_code == 400


def test_18_plain_vault_auto_encrypt_on_first_write():
    """Vault PLAIN + login + add -> the file is encrypted automatically
    with the session passphrase (fail-safe upgrade)."""
    c = _reset(encrypted=False)
    assert _login(c).status_code == 200
    assert _file_is_encrypted() is False
    r = c.post("/dashboard/api/entries",
               json={"kind": "secret", "value": "prima-scrittura-cifra"})
    assert r.status_code == 200, r.text
    assert _file_is_encrypted() is True, "la prima scrittura deve cifrare"
    plain = _decrypt_file()
    assert "prima-scrittura-cifra" in plain and SECRET_A in plain
    # the session passphrase is now the permanent unlock passphrase
    c2 = _reset(encrypted=True)   # file already encrypted: correct passphrase needed
    assert _login(c2).status_code == 200
    wrong = _reset(encrypted=True)
    assert _login(wrong, "altra-passphrase").status_code == 401
    # delete su vault plain cifra anch'esso
    c3 = _reset(encrypted=False)
    assert _login(c3).status_code == 200
    st = c3.get("/dashboard/api/state").json()
    eid = [e["id"] for e in st["entries"]
           if e["kind"] == "secret" and SECRET_A.startswith(e["masked"][:3])][0]
    assert c3.delete(f"/dashboard/api/entries/{eid}").status_code == 200
    assert _file_is_encrypted() is True
    assert SECRET_A not in _decrypt_file()
    c = _reset()
    assert _login(c).status_code == 200
    st = c.get("/dashboard/api/state").json()
    eid = [e["id"] for e in st["entries"]
           if e["kind"] == "named" and e["name"] == "client:default"][0]
    r = c.post(f"/dashboard/api/entries/{eid}/tag")
    assert r.status_code == 200
    tag = r.json()["tag"]
    assert tag.startswith("PWD_") and len(tag) > len("PWD_")
    assert CLIENT_TOKEN not in r.text
    # pattern: nessun tag fisso
    eid_p = [e["id"] for e in st["entries"] if e["kind"] == "pattern"]
    assert not eid_p   # il vault di default non ha pattern
    c.post("/dashboard/api/entries", json={"kind": "pattern", "value": "x[0-9]+"})
    st = c.get("/dashboard/api/state").json()
    eid_p = [e["id"] for e in st["entries"] if e["kind"] == "pattern"][0]
    assert c.post(f"/dashboard/api/entries/{eid_p}/tag").status_code == 400


# ---------------------------------------------- v1.2.1: primo utilizzo
NEWPW = "FirstUse-NewP@ss-99"


def _wipe_vault() -> None:
    """Simula il PRIMO utilizzo: nessun vault su disco."""
    svc.san.lock()
    dash.SESSIONS.drop_all()
    for f in (svc.VAULT_PATH, svc.KDF_SALT_PATH):
        if os.path.exists(f):
            os.remove(f)


def test_19_mode_endpoint():
    # vault assente -> setup
    _wipe_vault()
    c = TestClient(svc.app)
    m = c.get("/dashboard/api/mode").json()
    assert m["mode"] == "setup" and m["vault_exists"] is False
    # login su vault assente -> 409 con invito al setup
    r = c.post("/dashboard/api/session", json={"passphrase": PW})
    assert r.status_code == 409 and "setup" in r.json()["detail"]  # first-run invite kept EN
    # encrypted vault locked -> locked
    _make_vault(encrypted=True)
    m = c.get("/dashboard/api/mode").json()
    assert m["mode"] == "locked" and m["vault_encrypted"] is True
    # dopo login -> active
    assert _login(c).status_code == 200
    assert c.get("/dashboard/api/mode").json()["mode"] == "active"


def test_20_setup_fresh_vault():
    _wipe_vault()
    c = TestClient(svc.app)
    r = c.post("/dashboard/api/setup",
               json={"passphrase": NEWPW, "confirm": NEWPW})
    assert r.status_code == 200
    j = r.json()
    assert j["ok"] and j["setup"] and j["unlocked_service"] is True
    assert j["entries"] == 0
    # file created, encrypted, perms 0600, salt created
    assert os.path.exists(svc.VAULT_PATH) and _file_is_encrypted()
    assert stat.S_IMODE(os.stat(svc.VAULT_PATH).st_mode) == 0o600
    assert os.path.exists(svc.KDF_SALT_PATH)
    assert NEWPW not in open(svc.VAULT_PATH, "rb").read().decode("latin-1")
    # service active and session valid (cookie set)
    assert c.get("/health").json()["status"] == "active"
    st = c.get("/dashboard/api/state")
    assert st.status_code == 200 and st.json()["entries"] == []
    # mode ora active; ri-login con la NUOVA passphrase dopo lock
    assert c.get("/dashboard/api/mode").json()["mode"] == "active"
    assert c.post("/dashboard/api/lock").status_code == 200
    assert _login(c, NEWPW).status_code == 200
    assert _login(c, PW).status_code == 401   # la vecchia non vale


def test_21_setup_validations():
    _make_vault(encrypted=True)
    c = _reset()
    # vault already encrypted -> 409
    r = c.post("/dashboard/api/setup",
               json={"passphrase": NEWPW, "confirm": NEWPW})
    assert r.status_code == 409
    # conferma errata -> 400
    _wipe_vault()
    c = TestClient(svc.app)
    r = c.post("/dashboard/api/setup",
               json={"passphrase": NEWPW, "confirm": "diversa-12345"})
    assert r.status_code == 400 and "do not match" in r.json()["detail"]
    assert not os.path.exists(svc.VAULT_PATH)   # niente scritto
    # troppo corta -> 400
    r = c.post("/dashboard/api/setup",
               json={"passphrase": "corta", "confirm": "corta"})
    assert r.status_code == 400 and "8" in r.json()["detail"]
    assert not os.path.exists(svc.VAULT_PATH)


def test_22_setup_preserves_plain_entries():
    # vault plain esistente (caso legacy): setup conserva le voci
    _wipe_vault()
    plain = ["client:default=tok-setup-1", "provider:default=sk-setup",
             "segreto-a-1", "# comment"]
    with open(svc.VAULT_PATH, "w") as f:
        f.write("\n".join(plain) + "\n")
    os.chmod(svc.VAULT_PATH, 0o600)
    c = TestClient(svc.app)
    m = c.get("/dashboard/api/mode").json()
    assert m["mode"] == "plain" and m["existing_entries"] == 3
    r = c.post("/dashboard/api/setup",
               json={"passphrase": NEWPW, "confirm": NEWPW})
    assert r.status_code == 200 and r.json()["entries"] == 3
    assert _file_is_encrypted() is True
    content = _decrypt_file(NEWPW)
    for ln in ("client:default=tok-setup-1", "provider:default=sk-setup",
               "segreto-a-1", "# comment"):
        assert ln in content
    # servizio caricato con le voci conservate
    h = c.get("/health").json()
    assert h["status"] == "active" and h["secrets"] == 1 and h["named"] == 2


# ------------------------------------------------------------------ v1.3.0 auto-unlock
AU = svc.VAULT_PATH + ".autounlock"


def _master_key() -> str:
    return derive_key(PW, load_or_create_salt(svc.KDF_SALT_PATH))


def test_30_auto_unlock_enable_disable_api():
    c = _reset(encrypted=True)
    assert _login(c).status_code == 200
    st = c.get("/dashboard/api/state").json()
    assert st["auto_unlock"] is False
    # enable
    r = c.post("/dashboard/api/auto-unlock", json={"enable": True})
    assert r.status_code == 200 and r.json()["enabled"] is True
    assert os.path.exists(AU)
    assert stat.S_IMODE(os.stat(AU).st_mode) == 0o600
    blob = open(AU, "rb").read()
    mk = _master_key()
    assert PW.encode() not in blob, "passphrase su disco!"
    assert mk.encode() not in blob, "master key in plaintext on disk!"
    assert dash.auto_unlock_key(svc.VAULT_PATH) == mk, "roundtrip wrap"
    st = c.get("/dashboard/api/state").json()
    assert st["auto_unlock"] is True
    assert c.get("/dashboard/api/auto-unlock").json()["enabled"] is True
    # disable + idempotente
    r = c.post("/dashboard/api/auto-unlock", json={"enable": False})
    assert r.status_code == 200 and r.json()["enabled"] is False
    assert not os.path.exists(AU)
    assert c.post("/dashboard/api/auto-unlock",
                  json={"enable": False}).json()["enabled"] is False


def test_31_auto_unlock_enable_needs_encrypted_vault():
    c = _reset(encrypted=False)
    assert _login(c).status_code == 200
    r = c.post("/dashboard/api/auto-unlock", json={"enable": True})
    assert r.status_code == 409
    assert not dash.auto_unlock_enabled(svc.VAULT_PATH)


def test_32_auto_unlock_machine_guard_and_corruption(monkeypatch):
    c = _reset(encrypted=True)
    assert _login(c).status_code == 200
    assert c.post("/dashboard/api/auto-unlock",
                  json={"enable": True}).status_code == 200
    mk = _master_key()
    monkeypatch.setattr(dash, "_machine_secret", lambda: b"altra-macchina")
    assert dash.auto_unlock_key(svc.VAULT_PATH) is None, "macchina diversa"
    monkeypatch.undo()
    open(AU, "w").write(
        '{"v":1,"wrap_salt":"AAAA","wrapped":"gAAAAA-broken","machine_sha":"x"}')
    assert dash.auto_unlock_key(svc.VAULT_PATH) is None, "file corrotto"
    assert c.post("/dashboard/api/auto-unlock",
                  json={"enable": True}).status_code == 200
    assert dash.auto_unlock_key(svc.VAULT_PATH) == mk


def test_33_auto_unlock_startup_simulation():
    c = _reset(encrypted=True)
    assert _login(c).status_code == 200
    assert c.post("/dashboard/api/auto-unlock",
                  json={"enable": True}).status_code == 200
    c.delete("/dashboard/api/session")
    # simulazione riavvio: RAM scartata, poi percorso identico a _startup
    svc.san.lock()
    dash.SESSIONS.drop_all()
    assert not svc.san.is_loaded()
    svc._try_auto_unlock()
    assert svc.san.is_loaded(), "auto-unlock all'avvio"
    lines, _ = dash.vault_lines(svc.VAULT_PATH, _master_key())
    assert SECRET_A in "\n".join(lines), "voci integre dopo auto-unlock"
    svc.san.lock()


def test_34_auto_unlock_invalidated_by_reset():
    c = _reset(encrypted=True)
    assert _login(c).status_code == 200
    assert c.post("/dashboard/api/auto-unlock",
                  json={"enable": True}).status_code == 200
    assert dash.auto_unlock_enabled(svc.VAULT_PATH)
    assert c.post("/dashboard/api/reset",
                  json={"confirm": "RESET"}).status_code == 200
    assert not dash.auto_unlock_enabled(svc.VAULT_PATH), \
        "reset must invalidate the wrap (new vault/new key)"


# ------------------------------------------------------------------ v1.3.1 whitelist IP
from types import SimpleNamespace as _NS


def _req(ip):
    return _NS(client=_NS(host=ip))


def test_35_whitelist_ip_enforce():
    saved = list(svc.TRUSTED_IPS)
    try:
        svc.TRUSTED_IPS = []
        # vuota: tutte le sorgenti
        svc._ip_allowed(_req("8.8.8.8"))
        svc._ip_allowed(_req(""))
        svc.TRUSTED_IPS = ["192.0.2.0/24", "10.0.0.5"]
        svc._ip_allowed(_req("192.0.2.55"))    # dentro CIDR
        svc._ip_allowed(_req("10.0.0.5"))        # IP singolo
        with pytest.raises(Exception):
            svc._ip_allowed(_req("10.0.0.6"))    # fuori
        with pytest.raises(Exception):
            svc._ip_allowed(_req(""))            # sorgente sconosciuta: fail-closed
        with pytest.raises(Exception):
            svc._ip_allowed(_req("non-e-un-ip"))
    finally:
        svc.TRUSTED_IPS = saved


def test_36_whitelist_ip_api_and_persist():
    c = _reset(encrypted=True)
    assert _login(c).status_code == 200
    st = c.get("/dashboard/api/state").json()
    assert st["trusted_ips"] == []
    # IP non valido -> 400
    r = c.post("/dashboard/api/trusted-ips",
               json={"ips": ["127.0.0.1", "pippo"]})
    assert r.status_code == 400
    # lista valida -> persistita nel file config isolato del test
    r = c.post("/dashboard/api/trusted-ips",
               json={"ips": ["192.0.2.10", "10.0.0.0/8"]})
    assert r.status_code == 200 and r.json()["persisted"] is True
    assert r.json()["trusted_ips"] == ["192.0.2.10", "10.0.0.0/8"]
    cfg = json.load(open(svc.CONFIG_PATH))
    assert cfg["trusted_ips"] == ["192.0.2.10", "10.0.0.0/8"]
    # GET coerente + svuotamento
    assert c.get("/dashboard/api/trusted-ips").json()["trusted_ips"] == \
        ["192.0.2.10", "10.0.0.0/8"]
    r = c.post("/dashboard/api/trusted-ips", json={"ips": []})
    assert r.json()["trusted_ips"] == []
    cfg = json.load(open(svc.CONFIG_PATH))
    assert cfg["trusted_ips"] == []


def test_18_endpoints_picker():
    c = _reset()
    # without session -> 401
    assert c.get("/dashboard/api/endpoints").status_code == 401
    assert _login(c).status_code == 200

    r = c.get("/dashboard/api/endpoints")
    assert r.status_code == 200
    eps0 = r.json()["endpoints"]
    assert isinstance(eps0, list)

    # add: ok, duplicato -> 400, schema invalido -> 400
    r = c.post("/dashboard/api/endpoints/add", json={"url": "http://x:1"})
    assert r.status_code == 200 and "http://x:1" in r.json()["endpoints"]
    assert c.post("/dashboard/api/endpoints/add",
                  json={"url": "http://x:1/"}).status_code == 400  # dup (norm)
    assert c.post("/dashboard/api/endpoints/add",
                  json={"url": "ftp://nope"}).status_code == 400
    eps = c.get("/dashboard/api/endpoints").json()["endpoints"]
    assert eps.count("http://x:1") == 1

    # select: attivo aggiornato + visibile da /dashboard/api/upstream
    r = c.post("/dashboard/api/endpoints/select", json={"url": "http://x:1"})
    assert r.status_code == 200 and r.json()["upstream"] == "http://x:1"
    assert c.get("/dashboard/api/upstream").json()["upstream"] == "http://x:1"
    assert c.post("/dashboard/api/endpoints/select",
                  json={"url": "http://assente:9"}).status_code == 404

    # delete dell'attivo -> fallback al primo rimasto (o nessuno)
    r = c.post("/dashboard/api/endpoints/delete", json={"url": "http://x:1"})
    assert r.status_code == 200
    body = r.json()
    assert "http://x:1" not in body["endpoints"]
    if body["endpoints"]:
        assert body["upstream"] == body["endpoints"][0]
        assert body["note"]
    else:
        assert body["upstream"] == ""
    assert c.post("/dashboard/api/endpoints/delete",
                  json={"url": "http://x:1"}).status_code == 404

    # persistenza nel config
    cfg = json.load(open(svc.CONFIG_PATH))
    assert "http://x:1" not in (cfg.get("endpoints") or [])
    if cfg.get("upstream"):
        assert cfg["upstream"] in (cfg.get("endpoints") or [])
