"""
dashboard.py — Vault management web UI (v1.2.8).

Design (Roby's request):
- the passphrase is asked from the user at EVERY app start (login form);
- it is used ONLY to derive the Fernet key that encrypts the password list;
- it is NEVER stored anywhere: no disk, no cookies,
  no localStorage, no logs. Only the DERIVED key stays in RAM
  (needed to encrypt on every save), bound to the session;
- every new dashboard session requires the passphrase again;
- secret values never go back to the browser in clear form (masked only);
- edits are written to the vault file (Fernet, 0600, atomic write) and
  reloaded in memory PRESERVING the session salt: PWD_* tags already
  issued stay valid after a CRUD operation.

Sessions: HttpOnly cookie + random token; store is IN-MEMORY ONLY
(service restart = no sessions = passphrase prompt again).
"""

from __future__ import annotations

import base64
import hashlib
import hmac
import json
import os
import secrets as _pysecrets
import socket
import threading
import time
from typing import Dict, List, Optional, Tuple

from cryptography.fernet import Fernet, InvalidToken

from core import NAMED_RE, derive_key, load_or_create_salt

SESSION_COOKIE = "sp_dash"
SESSION_TTL_IDLE = 15 * 60        # idle expiry (15 min)
SESSION_TTL_ABS = 8 * 60 * 60     # absolute session lifetime (8 h)

FERNET_MAGIC = b"gAAAAA"

BRUTE_DELAY_S = 0.4               # slows down wrong passphrase attempts


# -------------------------------------------------------------------------- #
#  Session store (RAM only)                                                  #
# -------------------------------------------------------------------------- #
class DashSessions:
    """In-memory session store: token -> derived Fernet key.

    The passphrase is NEVER kept: at login the key is derived and the
    reference to the passphrase is let die right after.
    """

    def __init__(self) -> None:
        self._lock = threading.Lock()
        self._s: Dict[str, dict] = {}

    def create(self, fernet_key: str) -> str:
        token = _pysecrets.token_urlsafe(32)
        now = time.time()
        with self._lock:
            self._s[token] = {"key": fernet_key, "created": now, "last": now}
        return token

    def get(self, token: str) -> Optional[dict]:
        if not token:
            return None
        now = time.time()
        with self._lock:
            s = self._s.get(token)
            if s is None:
                return None
            if now - s["last"] > SESSION_TTL_IDLE or \
               now - s["created"] > SESSION_TTL_ABS:
                del self._s[token]
                return None
            s["last"] = now
            return dict(s)

    def drop(self, token: str) -> None:
        with self._lock:
            self._s.pop(token, None)

    def drop_all(self) -> int:
        with self._lock:
            n = len(self._s)
            self._s.clear()
            return n

    def count(self) -> int:
        with self._lock:
            return len(self._s)


SESSIONS = DashSessions()


# -------------------------------------------------------------------------- #
#  Vault helpers                                                             #
# -------------------------------------------------------------------------- #
def vault_is_encrypted(path: str) -> bool:
    try:
        with open(path, "rb") as f:
            return f.read(8).startswith(FERNET_MAGIC)
    except OSError:
        return False


def _mask(v: str) -> str:
    return (v[:3] + "…" + v[-2:]) if len(v) > 7 else "…"


def _entry_id(raw_line: str) -> str:
    return hashlib.sha256(raw_line.strip().encode("utf-8")).hexdigest()[:12]


entry_id = _entry_id   # public alias (row stability -> CRUD id)


# ---------- v1.3.0: AUTO-UNLOCK (machine-bound wrapped key) ----------
# The passphrase is NEVER stored anywhere. When the user enables
# auto-unlock we save ONLY the already-derived master key (the one held
# in RAM), encrypted with a wrap key = SHA256(machine-id + random salt).
# File is 0600, next to the vault. Can be disabled from the UI anytime.

AUTO_UNLOCK_VERSION = 1


def _machine_secret() -> bytes:
    """Stable machine identifier. Best-effort fallback to hostname
    when machine-id files do not exist."""
    for p in ("/etc/machine-id", "/var/lib/dbus/machine-id"):
        try:
            with open(p, "rb") as f:
                data = f.read().strip()
            if data:
                return data
        except OSError:
            continue
    return socket.gethostname().encode("utf-8")


def auto_unlock_path(vault_path: str) -> str:
    return vault_path + ".autounlock"


def auto_unlock_enabled(vault_path: str) -> bool:
    return os.path.exists(auto_unlock_path(vault_path))


def auto_unlock_enable(vault_path: str, master_key_b64: str) -> dict:
    """Wraps (encrypts) the master key with a machine-bound secret.
    Only the Fernet blob hits the disk, never any clear material."""
    wrap_salt = os.urandom(32)
    machine = _machine_secret()
    wrap_key = hashlib.sha256(machine + wrap_salt).digest()
    wrapped = Fernet(base64.urlsafe_b64encode(wrap_key)).encrypt(
        master_key_b64.encode("ascii"))
    data = {"v": AUTO_UNLOCK_VERSION,
            "wrap_salt": base64.b64encode(wrap_salt).decode("ascii"),
            "wrapped": wrapped.decode("ascii"),
            "machine_sha": hashlib.sha256(machine).hexdigest()[:16],
            "created_ts": round(time.time(), 1)}
    path = auto_unlock_path(vault_path)
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    try:
        os.write(fd, json.dumps(data, indent=2).encode("utf-8"))
    finally:
        os.close(fd)
    os.chmod(path, 0o600)
    return {"enabled": True, "path": path}


def auto_unlock_disable(vault_path: str) -> bool:
    try:
        os.unlink(auto_unlock_path(vault_path))
        return True
    except FileNotFoundError:
        return False


def auto_unlock_key(vault_path: str) -> Optional[str]:
    """Unwraps the master key. Returns None when absent/other machine/
    corrupted file: the service stays LOCKED (fail-safe)."""
    path = auto_unlock_path(vault_path)
    if not os.path.exists(path):
        return None
    try:
        with open(path, "r", encoding="utf-8") as f:
            data = json.load(f)
        wrap_salt = base64.b64decode(data["wrap_salt"])
        machine = _machine_secret()
        if data.get("machine_sha") != hashlib.sha256(machine).hexdigest()[:16]:
            return None
        wrap_key = hashlib.sha256(machine + wrap_salt).digest()
        key = Fernet(base64.urlsafe_b64encode(wrap_key)).decrypt(
            data["wrapped"].encode("ascii")).decode("ascii")
        Fernet(key.encode("ascii"))   # validate the shape of the key
        return key
    except (InvalidToken, KeyError, ValueError, OSError):
        return None



def parse_entries(plain_text: str) -> List[dict]:
    """Vault lines -> structured entries. VALUES are never returned in
    clear form: masked only (regex patterns are not secrets)."""
    out: List[dict] = []
    for raw in plain_text.splitlines():
        ln = raw.strip()
        if not ln or ln.startswith("#"):
            continue
        if ln.startswith("re:"):
            out.append({"id": _entry_id(ln), "kind": "pattern",
                        "name": None, "value": ln[3:], "masked": None})
            continue
        if "=" in ln:
            cand, val = ln.split("=", 1)
            if NAMED_RE.match(cand.strip()):
                out.append({"id": _entry_id(ln), "kind": "named",
                            "name": cand.strip(), "value": None,
                            "masked": _mask(val)})
                continue
        out.append({"id": _entry_id(ln), "kind": "secret",
                    "name": None, "value": None, "masked": _mask(ln)})
    return out


def parse_entry_input(kind: str, name: Optional[str], value: str) -> str:
    """UI input -> vault line. Validates and raises ValueError."""
    if "\n" in value or "\r" in value:
        raise ValueError("value cannot contain newlines: "
                         "one vault entry = one line")
    value = value.strip()
    if not value:
        raise ValueError("empty value")
    if kind == "pattern":
        if value.startswith("re:"):
            value = value[3:]
        try:
            import re as _re
            _re.compile(value)
        except _re.error as e:
            raise ValueError(f"invalid regex: {e}")
        return f"re:{value}"
    if kind == "named":
        if not name or not name.strip():
            raise ValueError("missing name for named entry")
        name = name.strip()
        if not NAMED_RE.match(name):
            raise ValueError("name must be 'client:<id>' or 'provider:<id>' "
                             "(id: letters, digits, _ . -)")
        return f"{name}={value}"
    # plain secret
    if "=" in value:
        cand = value.split("=", 1)[0].strip()
        if NAMED_RE.match(cand):
            raise ValueError("looks like a named entry: pick the "
                             "'client/provider' type or change the format")
    return value


def vault_lines(path: str, fernet_key: str) -> Tuple[List[str], bool]:
    """Reads the vault and returns (lines, was_encrypted). Requires the
    session key when the file is encrypted."""
    if not os.path.exists(path):
        raise FileNotFoundError(path)
    with open(path, "rb") as f:
        raw = f.read()
    enc = raw.startswith(FERNET_MAGIC)
    if enc:
        raw = Fernet(fernet_key.encode()).decrypt(raw)
    return raw.decode("utf-8").splitlines(), enc


def persist_vault(path: str, lines: List[str], fernet_key: str,
                  encrypt: bool) -> None:
    """Writes the vault atomically (tmp 0600 + rename), encrypting it
    with the session key when requested."""
    data = ("\n".join(lines) + "\n").encode("utf-8")
    if encrypt:
        data = Fernet(fernet_key.encode()).encrypt(data)
    tmp = path + ".tmp"
    fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    try:
        os.write(fd, data)
    finally:
        os.close(fd)
    os.replace(tmp, path)
    os.chmod(path, 0o600)


def verify_passphrase(vault_path: str, salt_path: str,
                      passphrase: str) -> Tuple[bool, str, bool]:
    """Verifies the passphrase against the vault file.

    Returns (ok, fernet_key, vault_encrypted).
    - encrypted vault: the passphrase must decrypt the file (else ok=False)
    - plain vault: any non-empty passphrase is accepted; the key will be
      used to ENCRYPT it on first save (or via 'Encrypt now')
    """
    salt = load_or_create_salt(salt_path)
    key = derive_key(passphrase, salt)
    enc = vault_is_encrypted(vault_path)
    if not enc:
        return True, key, False
    try:
        with open(vault_path, "rb") as f:
            Fernet(key.encode()).decrypt(f.read())
        return True, key, True
    except InvalidToken:
        return False, key, True


# -------------------------------------------------------------------------- #
#  UI HTML (self-contained: zero dipendenze esterne, nessun CDN)             #
# -------------------------------------------------------------------------- #
_HTML = r"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Secrets Proxy — Dashboard</title>
<style>
 :root{--bg:#0f1420;--card:#171e2e;--card2:#1d2639;--fg:#e8ecf4;--mut:#93a0b8;
       --acc:#4f8cff;--ok:#3ecf8e;--warn:#f5b544;--err:#ff6b6b;--line:#28324a}
 *{box-sizing:border-box;margin:0;padding:0}
 body{background:var(--bg);color:var(--fg);font:14px/1.5 system-ui,Segoe UI,Roboto,sans-serif}
 .wrap{max-width:980px;margin:0 auto;padding:24px 16px}
 h1{font-size:20px;margin-bottom:4px}
 .sub{color:var(--mut);font-size:13px;margin-bottom:20px}
 .card{background:var(--card);border:1px solid var(--line);border-radius:10px;padding:18px;margin-bottom:16px}
 .row{display:flex;gap:10px;flex-wrap:wrap;align-items:center}
 input,select{background:var(--card2);border:1px solid var(--line);color:var(--fg);
   border-radius:7px;padding:9px 11px;font-size:14px}
 input:focus,select:focus{outline:1px solid var(--acc)}
 input[type=password],input[type=text]{min-width:240px}
 button{background:var(--acc);border:0;color:#fff;border-radius:7px;padding:9px 15px;
   font-size:14px;cursor:pointer}
 button.sec{background:var(--card2);border:1px solid var(--line);color:var(--fg)}
 button.danger{background:var(--err)}
 button:disabled{opacity:.5;cursor:default}
 .msg{margin-top:10px;font-size:13px;min-height:18px}
 .msg.err{color:var(--err)} .msg.ok{color:var(--ok)}
 .pill{display:inline-block;border-radius:20px;padding:2px 10px;font-size:12px;font-weight:600}
 .pill.active{background:rgba(62,207,142,.15);color:var(--ok)}
 .pill.locked{background:rgba(245,181,68,.15);color:var(--warn)}
 .pill.encrypted{background:rgba(79,140,255,.15);color:var(--acc)}
 .pill.plain{background:rgba(255,107,107,.15);color:var(--err)}
 table{width:100%;border-collapse:collapse;margin-top:12px}
 th,td{text-align:left;padding:8px 10px;border-bottom:1px solid var(--line);font-size:13px}
 th{color:var(--mut);font-weight:600;text-transform:uppercase;font-size:11px;letter-spacing:.05em}
 td.warn{color:var(--warn)}
 td.mut{color:var(--mut)}
 td.mono,code{font-family:ui-monospace,Menlo,Consolas,monospace}
 .tag-kind{font-size:11px;border:1px solid var(--line);border-radius:5px;padding:1px 6px;color:var(--mut)}
 .note{color:var(--mut);font-size:12.5px;margin-top:8px}
 .banner{border:1px solid var(--line);background:var(--card2);border-radius:8px;
   padding:10px 12px;font-size:13px;margin-bottom:14px}
 .banner.warn{border-color:rgba(245,181,68,.4)}
 .hidden{display:none}
 .tabs{display:flex;gap:6px;margin-bottom:14px}
 .tabs button{background:transparent;border:1px solid transparent;color:var(--mut)}
 .tabs button.on{color:var(--fg);background:var(--card);border-color:var(--line)}
 .grid2{display:grid;grid-template-columns:1fr 1fr;gap:14px}
 .stat{background:var(--card2);border:1px solid var(--line);border-radius:8px;padding:12px}
 .stat b{font-size:18px;display:block}
 .stat span{color:var(--mut);font-size:12px}
 .logo{width:34px;height:34px;border-radius:8px;background:linear-gradient(135deg,#4f8cff,#3ecf8e);
   display:inline-flex;align-items:center;justify-content:center;font-weight:800;color:#08101f;margin-right:10px}
 .center{max-width:430px;margin:8vh auto 0}
 a{color:var(--acc)}
</style>
</head>
<body>

<!-- ============ LOGIN (always at every app start) ============ -->
<div id="login" class="wrap center">
  <div class="card">
    <div class="row"><span class="logo">SP</span><div><h1>Secrets Proxy</h1>
      <div class="sub" style="margin:0">Vault management dashboard</div></div></div>
    <div style="margin-top:18px">
      <label style="color:var(--mut);font-size:13px">Passphrase</label><br>
      <input type="password" id="pw" autofocus style="width:100%;margin-top:6px"
             placeholder="vault passphrase">
    </div>
    <div class="row" style="margin-top:14px">
      <button id="btn-login">Unlock</button>
      <span id="login-state" class="sub" style="margin:0"></span>
    </div>
    <div id="login-msg" class="msg"></div>
    <div class="note">Your passphrase is never stored anywhere:
      it only derives the key that encrypts the list, and it is asked
      again every time the app starts. If the vault is not encrypted yet,
      the first change will encrypt it with this passphrase.</div>
  </div>
</div>

<!-- ====== SETUP FIRST RUN (vault absent) ====== -->
<div id="setup" class="wrap center hidden">
  <div class="card">
    <div class="row"><span class="logo">SP</span><div><h1>Secrets Proxy</h1>
      <div class="sub" style="margin:0">First run — create your passphrase</div></div></div>
    <div style="margin-top:18px">
      <label style="color:var(--mut);font-size:13px">New passphrase</label><br>
      <input type="password" id="sp1" autofocus style="width:100%;margin-top:6px"
             placeholder="at least 8 characters">
      <label style="color:var(--mut);font-size:13px;display:block;margin-top:12px">Confirm passphrase</label>
      <input type="password" id="sp2" style="width:100%;margin-top:6px"
             placeholder="repeat the passphrase">
    </div>
    <div id="setup-existing" class="note hidden" style="margin-top:10px"></div>
    <div class="row" style="margin-top:14px">
      <button id="btn-setup">Create vault and sign in</button>
    </div>
    <div id="setup-msg" class="msg"></div>
    <div class="note">Your passphrase is never stored anywhere:
      it only derives the key that encrypts the vault, and it is asked
      again at every app start. If you lose it, the vault cannot be
      recovered.</div>
    <div class="sub"><a href="#" id="setup-tologin">Vault already encrypted? Back to login</a></div>
  </div>
</div>

<!-- ============ APP ============ -->
<div id="app" class="wrap hidden">
  <div class="row" style="justify-content:space-between">
    <div class="row"><span class="logo">SP</span>
      <div><h1 style="margin:0">Secrets Proxy</h1>
      <div class="sub" style="margin:0" id="hdr-sub"></div></div>
    </div>
    <div class="row">
      <span id="hdr-pills"></span>
      <button class="sec" id="btn-refresh">Refresh</button>
      <button class="sec" id="btn-logout">Sign out</button>
      <button class="danger" id="btn-lock">Lock service</button>
    </div>
  </div>

  <div id="banner-plain" class="banner warn hidden" style="margin-top:14px">
    ⚠️ The vault file is currently <b>NOT encrypted</b>. With the next change
    (or via "Encrypt now") it will be encrypted with the key derived from your passphrase.
    <button class="sec" id="btn-encrypt" style="margin-left:8px">Encrypt now</button>
  </div>

  <div class="tabs" style="margin-top:16px">
    <button data-tab="pwd" class="on">Passwords</button>
    <button data-tab="status">Status</button>
    <button data-tab="endpoint">Service endpoints</button>
    <button data-tab="audit">Audit</button>
    <button data-tab="csv">CSV</button>
  </div>

  <!-- ---- TAB PASSWORD ---- -->
  <div id="tab-pwd">
    <div class="card">
      <b>Add entry</b>
      <div class="row" style="margin-top:10px">
        <select id="add-kind">
          <option value="secret">Plain secret</option>
          <option value="named">Named (client:/provider:)</option>
          <option value="pattern">Regex pattern (re:)</option>
        </select>
        <select id="add-prefix" class="hidden">
          <option value="client">client:</option>
          <option value="provider">provider:</option>
        </select>
        <input type="text" id="add-name" class="hidden" placeholder="ollama">
        <input type="text" id="add-value" placeholder="secret value or regex">
        <button id="btn-gen" class="hidden" type="button"
          title="Generate a strong random token (32 chars)">Generate token</button>
        <button id="btn-add">Add</button>
      </div>
      <div id="add-msg" class="msg"></div>
      <div id="one-time" class="hidden" style="margin-top:10px;padding:10px;
        border:1px dashed #b8860b;border-radius:6px;background:#fffbe6">
        <b>Token generated.</b> Copy it NOW into your client (e.g. the Ollama API key):
        <code id="one-time-val" style="word-break:break-all"></code>
        <button id="btn-copy" type="button">Copia</button>
        <div class="note">It will not be shown again: only the encrypted form
        is kept in the vault. If you lose it, delete the entry and generate a new one.</div>
      </div>
    </div>
    <div class="card">
      <div class="row" style="justify-content:space-between">
        <b>Password list</b><span class="sub" style="margin:0" id="count-line"></span>
      </div>
      <table>
        <thead><tr><th style="width:90px">Type</th><th style="width:180px">Name</th>
          <th>Value</th><th style="width:150px"></th></tr></thead>
        <tbody id="rows"></tbody>
      </table>
      <div class="note">Values are never sent to the browser in clear form:
      masked shape only. "Edit" replaces the value; "Show tag" displays the
      PWD_* pseudonym used towards the upstream.</div>
    </div>
  </div>

  <!-- ---- TAB STATE ---- -->
  <div id="tab-status" class="hidden">
    <div class="card">
      <b>Service status</b>
      <div class="grid2" style="margin-top:12px">
        <div class="stat"><b id="st-state">—</b><span>state</span></div>
        <div class="stat"><b id="st-uptime">—</b><span>uptime (s)</span></div>
        <div class="stat"><b id="st-secrets">—</b><span>secrets</span></div>
        <div class="stat"><b id="st-named">—</b><span>named entries</span></div>
        <div class="stat"><b id="st-patterns">—</b><span>regex patterns</span></div>
        <div class="stat"><b id="st-req">—</b><span>proxied requests</span></div>
        <div class="stat"><b id="st-out">—</b><span>tags sent out</span></div>
        <div class="stat"><b id="st-in">—</b><span>restorations (responses)</span></div>
      </div>
      <div class="note" id="st-sessions"></div>
    </div>

    <!-- ---- v1.3.0 AUTO-UNLOCK ---- -->
    <div class="card" style="margin-top:14px">
      <b>AUTO-UNLOCK at startup</b>
      <div class="note" style="margin-top:6px">
        When active, the vault unlocks by itself on service restart.
        The passphrase is never stored: only the derived key is saved,
        encrypted with a machine-bound secret (0600 file). When disabled,
        every startup requires the passphrase.</div>
      <div class="row" style="margin-top:10px;align-items:center">
        <span id="au-state" style="font-weight:700;color:#93a0b8">—</span>
        <button id="btn-au-on">Enable auto-unlock</button>
        <button id="btn-au-off" class="sec">Disable</button>
      </div>
    </div>

    <!-- ---- v1.2.5 RECUPERO E RESET ---- -->
    <div class="card" style="margin-top:14px">
      <b>Vault recovery and reset</b>
      <div class="row" style="margin-top:10px">
        <button id="btn-rec">Recover previous vault</button>
        <button id="btn-reset" class="danger">Reset / re-initialize</button>
      </div>
      <div id="rec-box" class="hidden" style="margin-top:12px;padding:10px;
        border:1px dashed #888;border-radius:6px">
        <b>Import entries from a vault archive</b>
        <div class="row" style="margin-top:8px">
          <select id="rec-file" style="flex:1;min-width:240px"></select>
          <input type="password" id="rec-pw"
            placeholder="passphrase of that vault (if different)">
          <button id="btn-rec-go">Import</button>
          <button id="btn-rec-cancel" class="sec">Cancel</button>
        </div>
        <div id="rec-msg" class="msg"></div>
        <div class="note">"Orphan" archives are previous vaults kept
        automatically. Entries already present are skipped. If the archive
        was encrypted with a different passphrase than the current one,
        enter it in the field (its paired salt is picked automatically).</div>
      </div>
      <div id="reset-box" class="hidden" style="margin-top:12px;padding:10px;
        border:1px dashed #b33;border-radius:6px;background:#fff5f5">
        <b>Full vault reset</b>
        <div class="note">The current vault is archived as an "orphan"
        file (nothing is lost) and the system goes back to first run:
        you will set a NEW passphrase. The service goes to LOCK.</div>
        <div class="row" style="margin-top:8px">
          <input type="text" id="reset-confirm"
            placeholder="type RESET to confirm">
          <button id="btn-reset-go" class="danger">Delete and
            re-initialize</button>
          <button id="btn-reset-cancel" class="sec">Cancel</button>
        </div>
        <div id="reset-msg" class="msg"></div>
      </div>
      <div class="note" style="margin-top:10px">The passphrase is not
      recoverable by design: if you forget it, do a Reset and then use
      "Recover" importing the archive with the OLD passphrase.</div>
    </div>
  </div>

  <!-- ---- TAB ENDPOINT ---- -->
    <!-- ---- TAB CSV (v1.5.0: preview + column selection + custom prefix) ---- -->
  <div id="tab-csv" class="hidden">
    <div class="card">
      <b>CSV anonymizer</b>
      <p class="muted" style="margin:6px 0 10px">Step 1: pick a file — a small
        preview is built <b>in your browser only</b> (nothing is uploaded yet).
        Step 2: pick the columns to anonymize and run. <b>Sanitize</b> replaces
        the selected columns with opaque tags (safe to send to an LLM);
        <b>Restore</b> converts tags back to the original values; <b>Ingest</b>
        seeds the vault from every cell. Exact-secret matching always applies
        everywhere. Uses the same vault as the proxy.</p>
      <div class="row" style="flex-wrap:wrap;gap:10px">
        <input type="file" id="csv-file" accept=".csv,.tsv,.txt" style="max-width:320px">
        <label style="display:flex;align-items:center;gap:4px">
          <input type="checkbox" id="csv-header" checked> first row = header</label>
        <select id="csv-delim">
          <option value="auto">delimiter: auto</option>
          <option value=",">comma ,</option>
          <option value=";">semicolon ;</option>
          <option value="\t">tab</option>
          <option value="|">pipe |</option>
        </select>
      </div>
      <div id="csv-step2" class="hidden" style="margin-top:12px">
        <b>Step 2 — columns to anonymize</b>
        <div class="muted" style="font-size:12px;margin:4px 0 8px">Untick a
          column to leave it in clear. Optionally set a custom tag prefix
          (uppercase letters/digits, single trailing underscore, e.g.
          <code>EMAIL_</code>, <code>NOME_</code>). Empty = default
          <code>PWD_</code>.</div>
        <div class="row" style="gap:8px;margin:6px 0">
          <button id="btn-csv-selall" class="sec" style="font-size:11px;padding:2px 10px">Select all</button>
          <button id="btn-csv-deselall" class="sec" style="font-size:11px;padding:2px 10px">Deselect all</button>
        </div>
        <div id="csv-cols" style="display:flex;flex-wrap:wrap;gap:8px;margin:6px 0"></div>
        <div class="row" style="flex-wrap:wrap;gap:10px;margin-top:8px">
          <label style="display:flex;align-items:center;gap:4px">prefix
            <input id="csv-prefix" placeholder="PWD_ (or set per column below)" maxlength="17"
              style="width:120px;text-transform:uppercase"></label>
          <label style="display:flex;align-items:center;gap:4px">
            <input type="checkbox" id="csv-persist" checked> persist to vault</label>
          <button id="btn-csv-run" class="sec">Sanitize</button>
          <button id="btn-csv-restore" class="sec">Restore</button>
          <button id="btn-csv-ingest" class="sec">Ingest</button>
          <button id="btn-csv-purge" class="sec">Purge</button>
          <button id="btn-csv-reset" class="sec">Reset</button>
        </div>
      </div>
      <div class="msg" id="csv-msg"></div>
      <div id="csv-stats" class="muted" style="margin-top:6px"></div>
      <pre id="csv-preview" class="muted" style="margin-top:8px;max-height:260px;
        overflow:auto;font-size:12px;background:#111;border-radius:6px;padding:8px;
        white-space:pre"></pre>
      <div id="csv-result" class="hidden" style="margin-top:10px">
        <a id="csv-dl" class="sec" download="anonymized.csv">Download result</a>
      </div>
      <div class="card" style="margin-top:14px">
        <div class="row" style="justify-content:space-between">
          <b>Import history</b>
          <button id="btn-csv-hrefresh" style="font-size:11px">Refresh</button>
        </div>
        <div id="csv-history" class="muted" style="margin-top:8px">No imports yet.</div>
        <p class="muted" style="font-size:11px;margin-top:6px">The &#10005; button
          rolls back a single import: the values it added are removed from the
          vault (values that earlier imports added too stay until their last
          importer is deleted). Entries, patterns and named entries are never
          touched.</p>
      </div>
      <p class="muted" style="margin-top:8px;font-size:12px">Limits: max 20 MB,
        200k rows. The original file is never stored: processing is in-memory
        only. Restore leaves unknown tags verbatim and lists them.
        <b>Purge</b> removes from the vault every value that exactly matches
        a cell of the uploaded CSV (whole-cell match, same parsing as
        Ingest). Entries, patterns and named entries are never touched.</p>
    </div>
  </div>

<div id="tab-audit" class="hidden">
    <div class="card">
      <div class="row" style="justify-content:space-between">
        <b>Audit log</b>
        <button id="btn-audit-refresh" type="button" class="sec">Refresh</button>
      </div>
      <div class="note">Redacted security events, newest first. Entries carry
timestamps and truncated tags only &mdash; secret values are never logged.</div>
      <div class="grid2" id="audit-summary" style="margin-top:10px"></div>
      <table style="margin-top:10px">
        <thead><tr><th style="width:90px">Time</th><th>Event</th></tr></thead>
        <tbody id="audit-rows"></tbody>
      </table>
    </div>
  </div>

  <div id="tab-endpoint" class="hidden">
    <div class="card">
      <b>Endpoints upstream</b>
      <div id="eps-list" style="margin-top:10px"></div>
      <div class="row" style="margin-top:10px">
        <input type="text" id="ep-new" style="flex:1;min-width:320px"
               placeholder="https://openrouter.ai/api/v1 (http:// or https://)">
        <button id="btn-ep-add">Add</button>
      </div>
      <div id="up-msg" class="msg"></div>
      <div class="note">Select the active endpoint with the radio: the only one
      used by the proxy (the LLM service requests are forwarded to after
      pseudonymization, e.g. https://openrouter.ai/api/v1 or
      http://192.0.2.1:11434 for Ollama). Only one endpoint can be
      active at a time; adding/removing entries is free. Removing the
      active one auto-selects the first remaining endpoint.</div>
    </div>

    <!-- ---- v1.3.1 IP allowlist ---- -->
    <div class="card" style="margin-top:14px">
      <b>IP allowlist (trusted_ips)</b>
      <div class="row" style="margin-top:10px">
        <textarea id="ips-list" rows="4" style="flex:1"
          placeholder="One IP or CIDR per line, e.g.&#10;192.0.2.10&#10;192.0.2.0/24"></textarea>
      </div>
      <div class="row" style="margin-top:8px">
        <button id="btn-ips">Save allowlist</button>
      </div>
      <div id="ips-msg" class="msg"></div>
      <div class="note">Empty = accept all sources. When set, only the
      listed IPs/CIDRs can use the proxy (also applies in token mode).
      Dashboard and admin endpoints are not filtered (they have their own auth).</div>
    </div>
  </div>
</div>

<script>
"use strict";
const $ = id => document.getElementById(id);
let STATE = null;

async function api(path, opts = {}) {
  const r = await fetch(path, Object.assign({credentials: "same-origin",
    headers: {"Content-Type": "application/json"}}, opts));
  let body = null;
  try { body = await r.json(); } catch (e) {}
  if (r.status === 401) { showLogin(); throw {status: 401, body}; }
  if (!r.ok) throw {status: r.status, body};
  return body;
}

function showLogin() {
  $("app").classList.add("hidden");
  $("setup").classList.add("hidden");
  $("login").classList.remove("hidden");
  $("pw").value = ""; $("pw").focus();
}
function showSetup(nExisting) {
  $("login").classList.add("hidden");
  $("app").classList.add("hidden");
  $("setup").classList.remove("hidden");
  const ex = $("setup-existing");
  if (nExisting > 0) {
    ex.textContent = "Found " + nExisting + " entries in the existing vault "
      + "(not encrypted): they will be kept.";
    ex.classList.remove("hidden");
  } else { ex.classList.add("hidden"); }
  $("sp1").value = ""; $("sp2").value = ""; $("sp1").focus();
}
function showApp() {
  $("login").classList.add("hidden");
  $("app").classList.remove("hidden");
}
function msg(id, text, ok) {
  const el = $(id); el.textContent = text || "";
  el.className = "msg" + (text ? (ok ? " ok" : " err") : "");
}

/* ---------- login ---------- */
$("btn-login").onclick = async () => {
  const pw = $("pw").value;
  if (!pw) { msg("login-msg", "Enter the passphrase"); return; }
  $("btn-login").disabled = true;
  try {
    await api("/dashboard/api/session", {method: "POST",
      body: JSON.stringify({passphrase: pw})});
    showApp(); await refresh();   /* v1.2.6: the FULL state comes from /state */

  } catch (e) {
    msg("login-msg", (e.body && e.body.detail) || "Login failed");
  } finally { $("btn-login").disabled = false; }
};
$("pw").addEventListener("keydown", e => { if (e.key === "Enter") $("btn-login").click(); });

/* ---------- logout / lock ---------- */
$("btn-logout").onclick = async () => {
  try { await api("/dashboard/api/session", {method: "DELETE"}); } catch (e) {}
  showLogin();
};
$("btn-lock").onclick = async () => {
  if (!confirm("Lock the service? All sessions will be invalidated and "
    + "the passphrase will be asked again.")) return;
  try { await api("/dashboard/api/lock", {method: "POST"}); } catch (e) {}
  showLogin();
};

/* ---------- audit (v1.3.2 #22) ---------- */
async function loadAudit() {
  try {
    const d = await api("/dashboard/api/audit");
    const rows = $("audit-rows");
    rows.innerHTML = "";
    const evs = d.events || [];
    let unresolved = 0, lock = 0, other = 0;
    for (const ev of evs) {
      const tr = document.createElement("tr");
      const td1 = document.createElement("td");
      const td2 = document.createElement("td");
      const sp = ev.indexOf(" ");
      td1.textContent = ev.slice(0, sp);
      td2.textContent = ev.slice(sp + 1);
      if (ev.indexOf("unresolved tag") >= 0) {
        td2.className = "warn"; unresolved++;
      } else if (ev.indexOf("lock") >= 0) { lock++; }
      else { other++; }
      tr.appendChild(td1); tr.appendChild(td2);
      rows.appendChild(tr);
    }
    $("audit-summary").innerHTML =
      '<div class="stat"><b>' + evs.length + '</b><span>recent events</span></div>' +
      '<div class="stat"><b>' + unresolved + '</b><span>unresolved tags</span></div>' +
      '<div class="stat"><b>' + lock + '</b><span>lock/vault</span></div>' +
      '<div class="stat"><b>' + other + '</b><span>other</span></div>';
    if (!evs.length)
      rows.innerHTML = '<tr><td colspan="2" class="mut">no events yet</td></tr>';
  } catch (e) {
    $("audit-summary").textContent = "audit unavailable: " +
      ((e.body && e.body.detail) || e.message);
  }
}
$("btn-audit-refresh").onclick = loadAudit;

/* ---------- tabs ---------- */
document.querySelectorAll(".tabs button").forEach(b => {
  b.onclick = () => {
    document.querySelectorAll(".tabs button").forEach(x => x.classList.remove("on"));
    b.classList.add("on");
    ["pwd", "status", "endpoint", "audit", "csv"].forEach(t =>
      $("tab-" + t).classList.toggle("hidden", t !== b.dataset.tab));
    if (b.dataset.tab === "audit") loadAudit();
    if (b.dataset.tab === "csv") loadImportHistory();
  };
});

/* ---------- CSV workbench (v1.5.0): browser-side preview + column
   selection + custom tag prefix. The file NEVER leaves the browser until
   the user presses Sanitize/Restore/Ingest. ---------- */
const CSV_WORK = {file: null, rows: null, delim: ",", hasHeader: true};
const CSV_PREVIEW_ROWS = 8;

function csvDetectDelim(text) {
  const line = (text.split(/\r?\n/, 1)[0] || "");
  const cand = [",", ";", "\t", "|"];
  let best = ",", bestN = -1;
  for (const c of cand) {
    const n = line.split(c).length - 1;
    if (n > bestN) { best = c; bestN = n; }
  }
  return best;
}
function csvParse(text, delim) {
  const rows = [];
  let row = [], cur = "", q = false;
  for (let i = 0; i < text.length; i++) {
    const ch = text[i];
    if (q) {
      if (ch === '"') {
        if (text[i + 1] === '"') { cur += '"'; i++; } else { q = false; }
      } else { cur += ch; }
    } else if (ch === '"') { q = true; }
    else if (ch === delim) { row.push(cur); cur = ""; }
    else if (ch === "\n") { row.push(cur); rows.push(row); row = []; cur = ""; }
    else if (ch === "\r") { /* skip */ }
    else { cur += ch; }
  }
  if (cur !== "" || row.length) { row.push(cur); rows.push(row); }
  return rows.filter(r => !(r.length === 1 && r[0] === ""));
}
function renderColPicker() {
  const box = $("csv-cols");
  box.innerHTML = "";
  const header = CSV_WORK.hasHeader && CSV_WORK.rows.length ? CSV_WORK.rows[0] : null;
  CSV_WORK.rows[0] && header && header.forEach((h, j) => {
    const id = "csv-col-" + j;
    const lab = document.createElement("label");
    lab.style.cssText = "display:flex;align-items:center;gap:4px;background:#181818;padding:4px 8px;border-radius:6px";
    const name = String(h || ("col " + j)).slice(0, 28);
    let auto = (String(h || "").toUpperCase().replace(/[^A-Z0-9]+/g, "_")
      .replace(/^_+|_+$/g, "").slice(0, 14) + "_");
    if (!/^[A-Z][A-Z0-9_]{0,15}_$/.test(auto)) auto = "";
    lab.innerHTML = '<input type="checkbox" id="' + id + '" data-col="' + j + '" checked> ' +
      esc(name) + ' <input type="text" class="csv-colprefix" data-col="' + j +
      '" placeholder="PREFIX_" maxlength="17" value="' + auto + '"' +
      ' style="width:88px;text-transform:uppercase;font-size:11px;padding:1px 4px" title="Tag prefix for this column">';
    box.appendChild(lab);
  });
  $("csv-step2").classList.remove("hidden");
}
async function csvLoadPreview() {
  const f = $("csv-file").files[0];
  $("csv-step2").classList.add("hidden");
  $("csv-result").classList.add("hidden");
  $("csv-stats").textContent = "";
  $("csv-preview").textContent = "";
  if (!f) { CSV_WORK.file = null; return; }
  if (f.size > 20 * 1024 * 1024) { msg("csv-msg", "File too large (max 20 MB)"); $("csv-file").value = ""; return; }
  const dSel = $("csv-delim").value;
  try {
    const text = await f.text();
    CSV_WORK.file = f;
    CSV_WORK.delim = dSel === "auto" ? csvDetectDelim(text) : (dSel === "\t" ? "\t" : dSel);
    CSV_WORK.hasHeader = $("csv-header").checked;
    CSV_WORK.rows = csvParse(text.slice(0, 512 * 1024), CSV_WORK.delim).slice(0, CSV_PREVIEW_ROWS);
    if (!CSV_WORK.rows.length) { msg("csv-msg", "Empty file"); return; }
    $("csv-preview").textContent = "Preview (first " + CSV_WORK.rows.length + " rows, delimiter '" +
      (CSV_WORK.delim === "\t" ? "TAB" : CSV_WORK.delim) + "'):\n\n" +
      CSV_WORK.rows.map(r => r.join(" | ")).join("\n");
    renderColPicker();
    msg("csv-msg", "File loaded: " + f.name + " (" + Math.round(f.size / 1024) + " KB). Pick the columns, then run.");
  } catch (e) { msg("csv-msg", "Could not read file: " + e); }
}
$("csv-file").onchange = csvLoadPreview;
$("csv-header").onchange = () => { if (CSV_WORK.file) csvLoadPreview(); };
$("csv-delim").onchange = () => { if (CSV_WORK.file) csvLoadPreview(); };

function csvSetAllCols(on) {
  let n = 0;
  document.querySelectorAll("#csv-cols input[type=checkbox]").forEach(cb => { cb.checked = on; n++; });
  if (!n) { msg("csv-msg", "Load a CSV first."); return; }
  msg("csv-msg", on ? ("Selected all " + n + " columns.") : ("Deselected all " + n + " columns."));
}
$("btn-csv-selall").onclick = () => csvSetAllCols(true);
$("btn-csv-deselall").onclick = () => csvSetAllCols(false);
function selectedCols() {
  const sel = [];
  document.querySelectorAll("#csv-cols input[type=checkbox]").forEach(cb => {
    if (cb.checked) sel.push(cb.dataset.col);
  });
  // NOTE: prefix text inputs inside #csv-cols are ignored here on purpose
  return sel.join(",");
}
function validPrefix(p) {
  return p === "" || /^[A-Z][A-Z0-9_]{0,15}_$/.test(p);
}
function columnPrefixes() {
  const out = [];
  document.querySelectorAll("#csv-cols input.csv-colprefix").forEach(inp => {
    const v = (inp.value || "").toUpperCase().trim();
    if (v && inp.offsetParent !== null) out.push(inp.dataset.col + ":" + v);
  });
  return out.join(",");
}
async function csvRun(mode) {
  if (!CSV_WORK.file) { msg("csv-msg", "Choose a CSV file first"); return; }
  if (mode === "purge" && !confirm("Purge: remove from the vault every value " +
      "that exactly matches a cell of this CSV?")) return;
  if (mode !== "restore" && mode !== "purge") {
    const sel = selectedCols();
    if (!sel) { msg("csv-msg", "Select at least one column to anonymize (or use Ingest)"); return; }
  }
  const prefix = ($("csv-prefix").value || "").toUpperCase().trim();
  if (mode !== "purge" && !validPrefix(prefix)) {
    msg("csv-msg", "Invalid prefix: use uppercase letters/digits/underscores, must end with ONE underscore (e.g. EMAIL_)");
    return;
  }
  const colPfx = (mode === "restore" || mode === "purge") ? "" : columnPrefixes();
  {
    let bad = false;
    colPfx.split(",").filter(Boolean).forEach(p => {
      if (!validPrefix(p.split(":")[1] || "")) bad = true;
    });
    if (bad) {
      msg("csv-msg", "Invalid column prefix: uppercase letters/digits/underscores, must end with ONE underscore (e.g. NOME_)");
      return;
    }
  }
  const fd = new FormData();
  fd.append("file", CSV_WORK.file);
  fd.append("mode", mode);
  fd.append("header", $("csv-header").checked ? "true" : "false");
  if (prefix) fd.append("prefix", prefix);
  if (mode !== "restore" && mode !== "purge") fd.append("columns", selectedCols());
  if (mode === "sanitize") fd.append("on_missing", "tag");
  if (colPfx) fd.append("column_prefixes", colPfx);
  if (mode === "sanitize") fd.append("persist", $("csv-persist").checked ? "true" : "false");
  const d = $("csv-delim").value;
  if (d && d !== "auto") fd.append("delimiter", d === "\t" ? "\t" : d);
  msg("csv-msg", "Running " + mode + " on " + CSV_WORK.file.name + " ...");
  ["btn-csv-run", "btn-csv-restore", "btn-csv-ingest", "btn-csv-purge"].forEach(b => $(b).disabled = true);
  try {
    const r = await fetch("/dashboard/api/csv", {method: "POST",
      credentials: "same-origin", body: fd});
    let body = null;
    try { body = await r.json(); } catch (e) {}
    if (r.status === 401) { showLogin(); throw "expired session"; }
    if (!r.ok) throw (body && body.detail) || ("HTTP " + r.status);
    if (mode === "ingest") {
      $("csv-stats").textContent = body.rows + " data rows — " + body.added +
        " values added" + (body.skipped ? ", " + body.skipped + " already present" : "") +
        " — vault now filters them in & out";
      $("csv-preview").textContent = "(no output file: values were stored in the vault)";
      msg("csv-msg", "Done: " + body.added + " values added", true);
    } else if (mode === "purge") {
      $("csv-stats").textContent = body.rows + " data rows — " + body.purged +
        " values purged" + (body.kept != null ? ", vault now has " +
        body.kept + " entries" : "");
      $("csv-preview").textContent =
        "(no output file: matching values were removed from the vault)";
      msg("csv-msg", "Done: " + body.purged + " values purged", true);
    } else {
      const out = body.csv || "";
      const blob = new Blob([out], {type: "text/csv"});
      $("csv-dl").href = URL.createObjectURL(blob);
      {
        const cp = (typeof colPfx !== "undefined" && colPfx) ? colPfx.split(",")[0].split(":")[1] : "";
        $("csv-dl").download = (cp || (mode === "restore" ? "restored_" : mode + "_")) +
          (CSV_WORK.file.name || "result.csv");
      }
      $("csv-result").classList.remove("hidden");
      $("csv-preview").textContent =
        "Result (" + mode + "):\n\n" + out.split(/\r?\n/).slice(0, 12).join("\n") +
        (out.split(/\r?\n/).length > 12 ? "\n... (download for the full file)" : "");
      $("csv-stats").textContent = mode === "sanitize"
        ? body.rows + " rows, " + body.tagged_cells + " cells tagged, " +
          body.replaced + " secret hits, prefix " + body.prefix +
          (body.columns ? ", columns " + body.columns.join(",") : "") +
          (body.column_prefixes ? ", prefixes " + Object.entries(body.column_prefixes).map(e => e[1]).join(",") : "")
        : body.rows + " rows, " + body.restored + " tags restored" +
          (body.unresolved && body.unresolved.length
            ? ", unresolved: " + body.unresolved.slice(0, 5).join(", ") : "");
      msg("csv-msg", "Done: " + mode + " completed", true);
      if (mode === "ingest" ||
          (mode === "sanitize" && body.persisted)) loadImportHistory();
    }
  } catch (e) {
    msg("csv-msg", "Failed: " + e);
  } finally {
    ["btn-csv-run", "btn-csv-restore", "btn-csv-ingest", "btn-csv-purge"].forEach(b => $(b).disabled = false);
  }
}
$("btn-csv-run").onclick = () => csvRun("sanitize");
$("btn-csv-restore").onclick = () => csvRun("restore");
$("btn-csv-ingest").onclick = () => csvRun("ingest");
$("btn-csv-purge").onclick = () => csvRun("purge");
$("btn-csv-reset").onclick = () => {
  $("csv-file").value = "";
  $("csv-prefix").value = "";
  document.querySelectorAll("#csv-cols input.csv-colprefix").forEach(i => i.value = "");
  CSV_WORK.file = null; CSV_WORK.rows = null;
  $("csv-step2").classList.add("hidden");
  $("csv-result").classList.add("hidden");
  $("csv-stats").textContent = ""; $("csv-preview").textContent = "";
  msg("csv-msg", "");
  loadImportHistory();
};

/* ---------- render ---------- */
function pill(cls, text) { return '<span class="pill ' + cls + '">' + text + "</span> "; }

function render() {
  if (!STATE) return;
  /* v1.2.6: defensive defaults — a partial state must never produce
     a phantom "VAULT IN CLEAR" or an empty list */
  STATE.counts = STATE.counts || {secrets: 0, named: 0, patterns: 0};
  STATE.stats = STATE.stats ||
    {requests: 0, sanitized_out: 0, restored_in: 0, unresolved: 0};
  STATE.entries = STATE.entries || [];
  const active = STATE.service === "active";
  $("hdr-pills").innerHTML =
    pill(active ? "active" : "locked", active ? "ACTIVE" : "LOCKED") +
    pill(STATE.vault_encrypted ? "encrypted" : "plain",
         STATE.vault_encrypted ? "VAULT ENCRYPTED" : "VAULT IN CLEAR");
  $("hdr-sub").textContent = "secrets_proxy v" + (STATE.version || "?") +
    " — " + (STATE.upstream || "upstream not set");
  $("banner-plain").classList.toggle("hidden", !!STATE.vault_encrypted);
  $("count-line").textContent = STATE.counts.secrets + " secrets, " +
    STATE.counts.named + " named, " + STATE.counts.patterns + " patterns";

  $("st-state").textContent = active ? "ACTIVE" : "LOCKED";
  $("st-uptime").textContent = Math.round(STATE.uptime_s || 0);
  $("st-secrets").textContent = STATE.counts.secrets;
  $("st-named").textContent = STATE.counts.named;
  $("st-patterns").textContent = STATE.counts.patterns;
  $("st-req").textContent = STATE.stats.requests;
  $("st-out").textContent = STATE.stats.sanitized_out;
  $("st-in").textContent = STATE.stats.restored_in;
  $("st-sessions").textContent = "Active dashboard sessions: " + (STATE.sessions || 0) +
    " (idle expiry after " + (STATE.ttl_idle_s || 0) + "s; the derived key lives "
    + "in RAM only while a dashboard session is open)";
  renderEndpoints();
  $("au-state").textContent = STATE.auto_unlock ? "ON" : "OFF";
  $("au-state").style.color = STATE.auto_unlock ? "#7dd3a0" : "#93a0b8";
  $("ips-list").value = (STATE.trusted_ips || []).join("\n");

  const rows = $("rows"); rows.innerHTML = "";
  for (const en of STATE.entries) {
    const tr = document.createElement("tr");
    const kind = en.kind === "named" ? "named" : en.kind === "pattern" ? "regex" : "secret";
    const valCell = en.kind === "pattern"
      ? '<code>re:' + esc(en.value) + "</code>"
      : '<span class="mono">' + esc(en.masked || "") + "</span>";
    tr.innerHTML = '<td><span class="tag-kind">' + kind + "</span></td>" +
      "<td>" + esc(en.name || "—") + "</td>" + "<td>" + valCell + "</td>" +
      '<td class="row" style="gap:6px">' +
      '<button class="sec" onclick="showTag(\'' + en.id + '\')">Show tag</button>' +
      '<button class="sec" onclick="editEntry(\'' + en.id + '\')">Edit</button>' +
      '<button class="danger" onclick="delEntry(\'' + en.id + '\')">✕</button></td>';
    rows.appendChild(tr);
  }
}

function esc(s) {
  return String(s == null ? "" : s).replace(/[&<>"']/g,
    c => ({"&":"&amp;","<":"&lt;",">":"&gt;",'"':"&quot;","'":"&#39;"}[c]));
}

/* ---------- CRUD ---------- */
$("add-kind").onchange = () => {
  const k = $("add-kind").value;
  const named = k === "named";
  $("add-prefix").classList.toggle("hidden", !named);
  $("add-name").classList.toggle("hidden", !named);
  $("btn-gen").classList.toggle("hidden", !named);
  $("add-value").placeholder = k === "pattern" ? "e.g. sk-[a-zA-Z0-9]{20,}"
    : named ? "token (or press Generate token)" : "secret value";
};
function genToken() {
  const b = new Uint8Array(24);
  crypto.getRandomValues(b);
  let s = "";
  for (const x of b) s += String.fromCharCode(x);
  return btoa(s).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
}
let GEN = null;
$("btn-gen").onclick = () => {
  GEN = genToken();
  $("add-value").value = GEN;
};
$("btn-copy").onclick = () => {
  const v = $("one-time-val").textContent;
  const done = () => { $("btn-copy").textContent = "Copied!"; };
  if (navigator.clipboard && navigator.clipboard.writeText)
    navigator.clipboard.writeText(v).then(done, () => {});
  else {
    const t = document.createElement("textarea");
    t.value = v; document.body.appendChild(t); t.select();
    try { document.execCommand("copy"); done(); } finally { t.remove(); }
  }
};
function showOneTime(v) {
  $("one-time-val").textContent = v;
  $("one-time").classList.remove("hidden");
  $("btn-copy").textContent = "Copy";
}
$("btn-add").onclick = async () => {
  const k = $("add-kind").value;
  let name = $("add-name").value.trim();
  if (k === "named" && name && !name.startsWith("client:") &&
      !name.startsWith("provider:"))
    name = $("add-prefix").value + ":" + name;
  const val = $("add-value").value;
  try {
    await api("/dashboard/api/entries", {method: "POST", body: JSON.stringify({
      kind: k, name: name, value: val})});
    if (k === "named" && GEN && val === GEN) showOneTime(GEN);
    msg("add-msg", "Entry added and encrypted into the vault", true);
    $("add-name").value = ""; $("add-value").value = ""; GEN = null;
    await refresh();
  } catch (e) { msg("add-msg", (e.body && e.body.detail) || "Error"); }
};

let EDIT = null;
function editEntry(id) {
  const en = STATE.entries.find(x => x.id === id);
  if (!en) return;
  const val = prompt("New " + (en.kind === "named" ? "value for " + en.name : "value") +
    " (the current value is never shown, for safety):");
  if (val === null) return;
  api("/dashboard/api/entries/" + id, {method: "PUT",
    body: JSON.stringify({value: val})})
    .then(() => refresh())
    .catch(e => alert((e.body && e.body.detail) || "Error"));
}
function delEntry(id) {
  const en = STATE.entries.find(x => x.id === id);
  if (!confirm("Remove entry " + (en && (en.name || en.kind)) + "?")) return;
  api("/dashboard/api/entries/" + id, {method: "DELETE"})
    .then(() => refresh())
    .catch(e => alert((e.body && e.body.detail) || "Error"));
}

/* ---------- v1.5.6: import history (per-import rollback) ---------- */
function loadImportHistory() {
  api("/dashboard/api/csv/history")
    .then(j => {
      const box = $("csv-history");
      const items = j.imports || [];
      if (!items.length) { box.textContent = "No imports yet."; return; }
      box.innerHTML = items.map(it =>
        '<div class="row" style="margin:2px 0;justify-content:space-between">' +
        '<span class="muted" style="min-width:0;overflow:hidden;' +
        'text-overflow:ellipsis;white-space:nowrap;max-width:75%">' +
        esc(it.file) + ' <span style="opacity:.7">— ' + esc(it.ts) +
        ' — ' + it.added + ' values</span></span>' +
        '<button class="danger" title="Delete this import (rollback)" ' +
        'onclick="delImport(\'' + esc(it.id) + '\')">✕</button></div>'
      ).join("");
    })
    .catch(e => { $("csv-history").textContent = "history unavailable"; });
}
function delImport(id) {
  if (!confirm("Delete this import? All values it added will be removed " +
               "from the vault.")) return;
  api("/dashboard/api/csv/history/" + id, {method: "DELETE"})
    .then(j => {
      msg("csv-msg", "Import deleted: " + j.removed + " values removed", true);
      loadImportHistory();
    })
    .catch(e => alert((e.body && e.body.detail) || "Error"));
}
$("btn-csv-hrefresh").onclick = () => loadImportHistory();
function showTag(id) {
  const en = STATE.entries.find(x => x.id === id);
  if (!en) return;
  api("/dashboard/api/entries/" + id + "/tag", {method: "POST"})
    .then(r => alert("Tag sent to upstream:\n" + r.tag +
      (r.already_known ? "" : "\n(new: not issued yet in this session)")))
    .catch(e => alert((e.body && e.body.detail) || "Error"));
}

/* ---------- encrypt / upstream / refresh ---------- */
$("btn-encrypt").onclick = async () => {
  try { await api("/dashboard/api/encrypt", {method: "POST"}); await refresh(); }
  catch (e) { alert((e.body && e.body.detail) || "Error"); }
};
function renderEndpoints() {
  const box = $("eps-list"); box.innerHTML = "";
  const eps = STATE.endpoints || [];
  if (!eps.length) {
    const d = document.createElement("div");
    d.className = "note"; d.textContent = "No endpoints in the list.";
    box.appendChild(d);
  }
  for (const ep of eps) {
    const row = document.createElement("div");
    row.className = "row"; row.style.marginBottom = "6px";
    const lab = document.createElement("label");
    lab.style.cssText =
      "flex:1;display:flex;align-items:center;gap:8px;min-width:0";
    const rad = document.createElement("input");
    rad.type = "radio"; rad.name = "ep-active"; rad.value = ep;
    rad.checked = (ep === STATE.upstream);
    rad.onchange = () => selectEndpoint(ep);
    const span = document.createElement("span");
    span.className = "mono"; span.textContent = ep;
    span.style.overflowWrap = "anywhere";
    lab.appendChild(rad); lab.appendChild(span);
    const del = document.createElement("button");
    del.className = "danger"; del.textContent = "\u2715";
    del.title = "Delete endpoint";
    del.onclick = () => delEndpoint(ep);
    row.appendChild(lab); row.appendChild(del);
    box.appendChild(row);
  }
  const cur = document.createElement("div");
  cur.className = "note";
  cur.textContent = "Active: " + (STATE.upstream || "none");
  box.appendChild(cur);
}
async function selectEndpoint(ep) {
  try {
    await api("/dashboard/api/endpoints/select",
      {method: "POST", body: JSON.stringify({url: ep})});
    msg("up-msg", "Active endpoint: " + ep, true); await refresh();
  } catch (e) { msg("up-msg", errText(e)); await refresh(); }
}
async function delEndpoint(ep) {
  if (!confirm("Remove " + ep + " from the list?")) return;
  try {
    const r = await api("/dashboard/api/endpoints/delete",
      {method: "POST", body: JSON.stringify({url: ep})});
    msg("up-msg", "Endpoint removed." + (r.note ? " " + r.note : ""), true);
    await refresh();
  } catch (e) { msg("up-msg", errText(e)); }
}
$("btn-ep-add").onclick = async () => {
  const u = $("ep-new").value.trim();
  if (!u) { msg("up-msg", "Enter a URL (http:// or https://)"); return; }
  try {
    await api("/dashboard/api/endpoints/add",
      {method: "POST", body: JSON.stringify({url: u})});
    $("ep-new").value = ""; msg("up-msg", "Endpoint added.", true);
    await refresh();
  } catch (e) { msg("up-msg", errText(e)); }
};
$("ep-new").addEventListener("keydown",
  e => { if (e.key === "Enter") $("btn-ep-add").click(); });
$("btn-ips").onclick = async () => {
  try {
    const ips = $("ips-list").value.split("\n").map(s => s.trim())
      .filter(Boolean);
    await api("/dashboard/api/trusted-ips", {method: "POST",
      body: JSON.stringify({ips})});
    msg("ips-msg", "Allowlist saved.", true);
    await refresh();
  } catch (e) { msg("ips-msg", (e.body && e.body.detail) || "Error", true); }
};
$("btn-refresh").onclick = () => refresh();

/* ---------- v1.3.0 auto-unlock ---------- */
$("btn-au-on").onclick = async () => {
  try { await api("/dashboard/api/auto-unlock",
    {method: "POST", body: JSON.stringify({enable: true})});
    await refresh(); }
  catch (e) { alert((e.body && e.body.detail) || "Error"); }
};
$("btn-au-off").onclick = async () => {
  try { await api("/dashboard/api/auto-unlock",
    {method: "POST", body: JSON.stringify({enable: false})});
    await refresh(); }
  catch (e) { alert((e.body && e.body.detail) || "Error"); }
};

async function refresh() {
  try { STATE = await api("/dashboard/api/state"); render(); }
  catch (e) { if (e.status !== 401) alert("Network error"); }
}

/* ---------- setup (first run) ---------- */
$("btn-setup").onclick = async () => {
  const p1 = $("sp1").value, p2 = $("sp2").value;
  if (p1.length < 8) { msg("setup-msg", "Passphrase too short: minimum 8 characters"); return; }
  if (p1 !== p2) { msg("setup-msg", "Passphrases do not match"); return; }
  $("btn-setup").disabled = true;
  try {
    await api("/dashboard/api/setup", {method: "POST",
      body: JSON.stringify({passphrase: p1, confirm: p2})});
    showApp(); await refresh();
  } catch (e) {
    msg("setup-msg", (e.body && e.body.detail) || "Setup failed");
  } finally { $("btn-setup").disabled = false; }
};
[$("sp1"), $("sp2")].forEach(el =>
  el.addEventListener("keydown", e => { if (e.key === "Enter") $("btn-setup").click(); }));
$("setup-tologin").onclick = e => { e.preventDefault(); showLogin(); };


/* ---------- v1.2.5: archive recovery + reset ---------- */
function errText(e) {
  return (e && e.body && (e.body.detail || e.body.message)) ||
    (e && e.message) || "Error";
}
$("btn-rec").onclick = async () => {
  $("rec-msg").textContent = ""; $("rec-pw").value = "";
  try {
    const o = await api("/dashboard/api/orphans");
    const sel = $("rec-file"); sel.innerHTML = "";
    if (!o.orphans.length)
      sel.innerHTML = '<option value="">no archive found</option>';
    for (const f of o.orphans) {
      const dt = new Date(f.mtime * 1000).toLocaleString();
      const opt = document.createElement("option");
      opt.value = f.file;
      opt.textContent = f.file + " — " + f.bytes + " byte — " + dt +
        (f.encrypted ? " (encrypted)" : "");
      sel.appendChild(opt);
    }
    $("rec-box").classList.remove("hidden");
  } catch (e) { $("rec-msg").textContent = errText(e); }
};
$("btn-rec-cancel").onclick = () => $("rec-box").classList.add("hidden");
$("btn-rec-go").onclick = async () => {
  const file = $("rec-file").value;
  if (!file) return;
  $("rec-msg").textContent = "importing...";
  try {
    const r = await api("/dashboard/api/import", {method: "POST",
      body: JSON.stringify({file: file, passphrase: $("rec-pw").value})});
    $("rec-msg").textContent = "OK: " + r.added + " entries imported, " +
      r.skipped + " already present.";
    STATE = await api("/dashboard/api/state"); render();
  } catch (e) { $("rec-msg").textContent = errText(e); }
};
$("btn-reset").onclick = () => {
  $("reset-msg").textContent = ""; $("reset-confirm").value = "";
  $("reset-box").classList.remove("hidden");
};
$("btn-reset-cancel").onclick = () => $("reset-box").classList.add("hidden");
$("btn-reset-go").onclick = async () => {
  if ($("reset-confirm").value !== "RESET") {
    $("reset-msg").textContent = "type RESET in the field to confirm";
    return;
  }
  try {
    await api("/dashboard/api/reset", {method: "POST",
      body: JSON.stringify({confirm: $("reset-confirm").value})});
    location.reload();   // boot() -> setup mode -> new passphrase
  } catch (e) { $("reset-msg").textContent = errText(e); }
};

/* ---------- boot: setup on first run, else login ---------- */
async function boot() {
  try {
    const m = await fetch("/dashboard/api/mode",
      {credentials: "same-origin"}).then(r => r.json());
    if (m && m.mode === "setup") { showSetup(m.existing_entries || 0); return; }
    if (m) {
      $("login-state").textContent = m.vault_encrypted
        ? "vault is encrypted: enter your passphrase"
        : "WARNING: vault is NOT encrypted";
    }
  } catch (e) { /* fallback: login */ }
  showLogin();
}
boot();
</script>
</body>
</html>
"""


def get_html() -> str:
    return _HTML
