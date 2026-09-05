#!/usr/bin/env python3
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
vaultctl.py — headless management CLI for LLMCloak (v1.1.0).

Service control (HTTP against /admin/*, default http://127.0.0.1:8917):
  status                      service state (locked/active, counters)
  unlock [--passphrase P]     mode A: unlock the vault (key kept in RAM only)
  lock                        wipe state (503 until the next unlock)
  upstream [URL]              show/set the upstream (persistent config)
  reload [--admin-token T]    reload the vault from disk (after edits)

Vault file management (offline; asks for the passphrase when encrypted):
  list [--reveal]             entries (masked by default)
  add <ENTRY>                 ENTRY = 'name=value' (client:*/provider:*)
                              or a plain secret string
  remove <NAME_OR_VALUE>      remove by name (client:default) or exact value
  encrypt --yes               encrypt the vault in place (plaintext -> Fernet)
  decrypt --yes               decrypt in place (maintenance only; be careful)

Examples:
  python3 vaultctl.py unlock
  python3 vaultctl.py add 'client:default=agent-token-1'
  python3 vaultctl.py add 'provider:default=sk-real-key'
  python3 vaultctl.py encrypt --yes
"""
from __future__ import annotations

import argparse
import getpass
import json
import os
import stat
import sys
import urllib.error
import urllib.request
from pathlib import Path

def _env(name: str, default=None):
    """Read LLMCLOAK_* first; legacy SECRETS_PROXY_* kept as fallback."""
    v = os.environ.get("LLMCLOAK_" + name)
    if v not in (None, ""):
        return v
    return os.environ.get("SECRETS_PROXY_" + name, default)


BASE = Path(_env("HOME", Path(__file__).resolve().parent))
sys.path.insert(0, str(BASE))
from core import NAMED_RE, derive_key, load_or_create_salt  # noqa: E402

VAULT = Path(_env("VAULT", BASE / "vault.txt"))
SALT_PATH = Path(str(VAULT) + ".salt")
BASE_URL = _env("BASE_URL", "http://127.0.0.1:8917")


# ---------- vault file helpers ----------
FERNET_MAGIC = b"gAAAAA"   # stable Fernet token prefix (v0x80 + BE timestamp)


def _is_encrypted(raw: bytes) -> bool:
    """NOTE: Fernet(raw) would treat the bytes as a KEY, not as a token.
    Detection uses the Fernet prefix: a legitimate plain vault almost never
    starts with 'gAAAAA' (documented behavior in the README)."""
    return raw.strip().startswith(FERNET_MAGIC)


def _ask_passphrase(args) -> str:
    if getattr(args, "passphrase", None):
        return args.passphrase
    return getpass.getpass(f"Vault passphrase [{VAULT}]: ")


def _read_vault(args) -> tuple[list, bool, bytes]:
    """Returns (lines, was_encrypted, original_raw)."""
    if not VAULT.exists():
        sys.exit(f"vault not found: {VAULT}")
    st = VAULT.stat()
    if st.st_mode & 0o077:
        sys.exit(f"unsafe vault permissions: {oct(st.st_mode & 0o777)} — fix "
                 f"with chmod 600 {VAULT}")
    raw = VAULT.read_bytes()
    if _is_encrypted(raw):
        pw = _ask_passphrase(args)
        from cryptography.fernet import Fernet, InvalidToken
        salt = load_or_create_salt(str(SALT_PATH))
        try:
            plain = Fernet(derive_key(pw, salt).encode()).decrypt(raw)
        except InvalidToken:
            sys.exit("wrong passphrase (or salt changed)")
        return plain.decode("utf-8").splitlines(), True, raw
    return raw.decode("utf-8").splitlines(), False, raw


def _write_vault(lines: list, encrypted: bool, args) -> None:
    data = ("\n".join(lines) + "\n").encode("utf-8")
    if encrypted:
        pw = _ask_passphrase(args)
        from cryptography.fernet import Fernet
        salt = load_or_create_salt(str(SALT_PATH))
        data = Fernet(derive_key(pw, salt).encode()).encrypt(data)
    tmp = str(VAULT) + ".tmp"
    fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    os.write(fd, data)
    os.close(fd)
    os.replace(tmp, VAULT)
    os.chmod(VAULT, 0o600)


def _parse_entry(line: str) -> tuple[str | None, str]:
    line = line.strip()
    if not line or line.startswith("#"):
        sys.exit("empty entry or comment")
    if line.startswith("re:"):
        return None, line                      # regex pattern
    if "=" in line:
        cand, val = line.split("=", 1)
        if NAMED_RE.match(cand.strip()):
            return cand.strip(), val           # named entry
    return None, line                          # plain secret


# ---------- HTTP helpers ----------
def _http(method: str, path: str, token: str = "",
          payload: dict | None = None) -> dict:
    req = urllib.request.Request(BASE_URL + path, method=method)
    if token:
        req.add_header("X-Admin-Token", token)
    data = None
    if payload is not None:
        data = json.dumps(payload).encode()
        req.add_header("Content-Type", "application/json")
    try:
        with urllib.request.urlopen(req, data=data, timeout=15) as r:
            return json.loads(r.read().decode())
    except urllib.error.HTTPError as e:
        try:
            detail = json.loads(e.read().decode()).get("detail", e.reason)
        except Exception:
            detail = e.reason
        sys.exit(f"HTTP {e.code}: {detail}")
    except Exception as e:
        sys.exit(f"service unreachable on {BASE_URL}: {e!r}")


# ---------- service commands ----------
def cmd_status(args):
    print(json.dumps(_http("GET", "/admin/status", args.admin_token), indent=1))


def cmd_unlock(args):
    pw = args.passphrase or getpass.getpass("Vault passphrase: ")
    out = _http("POST", "/admin/unlock", args.admin_token, {"passphrase": pw})
    rep = out.get("report", {})
    print(f"UNLOCK ok: {rep.get('secrets', '?')} secrets, "
          f"{rep.get('named', '?')} named, {rep.get('patterns', '?')} patterns")


def cmd_lock(args):
    _http("POST", "/admin/lock", args.admin_token, {})
    print("LOCK ok: service returns 503 until the next unlock")


def cmd_upstream(args):
    if args.url:
        out = _http("POST", "/admin/upstream", args.admin_token, {"url": args.url})
        print(f"upstream = {out['upstream']} "
              f"({'persisted' if out.get('persisted') else 'env (not persisted)'})")
    else:
        print(_http("GET", "/admin/upstream", args.admin_token)["upstream"] or "(not set)")


def cmd_reload(args):
    out = _http("POST", "/vault/reload", args.admin_token, {})
    rep = out["report"]
    print(f"reload ok: {rep['secrets']} secrets, {rep['named']} named, "
          f"{rep['patterns']} patterns")


# ---------- file commands ----------
def cmd_list(args):
    lines, enc, _ = _read_vault(args)
    named, plain, pats = [], [], 0
    for ln in lines:
        ln = ln.strip()
        if not ln or ln.startswith("#"):
            continue
        name, val = _parse_entry(ln)
        if ln.startswith("re:"):
            pats += 1
        elif name:
            named.append((name, val))
        else:
            plain.append(val)
    print(f"vault: {VAULT} ({'ENCRYPTED' if enc else 'PLAIN'}) — "
          f"{len(named)} named, {len(plain)} secrets, {pats} patterns")
    for name, val in named:
        print(f"  [named]   {name} = {val if args.reveal else _mask(val)}")
    for val in plain:
        print(f"  [secret]  {val if args.reveal else _mask(val)}")
    if args.reveal:
        print("WARNING: plaintext values shown on screen", file=sys.stderr)


def _mask(v: str) -> str:
    return (v[:3] + "…" + v[-2:]) if len(v) > 7 else "…"


def cmd_add(args):
    if not VAULT.exists():
        # bootstrap: create an empty (plain) vault — run 'encrypt' afterwards
        VAULT.write_text("# secrets_proxy vault\n")
        os.chmod(VAULT, 0o600)
        print(f"vault created: {VAULT} — run 'encrypt --yes' when done")
    lines, enc, _ = _read_vault(args)
    name, val = _parse_entry(args.entry)
    new_line = f"{name}={val}" if name else val
    for ln in lines:
        if ln.strip() == new_line or (name and ln.strip().startswith(name + "=")):
            sys.exit(f"entry already present: {name or val[:3]}… (remove it first)")
    lines.append(new_line)
    _write_vault(lines, enc, args)
    print(f"added: {name or 'plain secret'} "
          f"({enc and 'encrypted' or 'plain'}) — run 'reload' if the service is up")


def cmd_remove(args):
    lines, enc, _ = _read_vault(args)
    target = args.name_or_value.strip()
    kept, removed = [], 0
    for ln in lines:
        s = ln.strip()
        name, val = _parse_entry(s) if s and not s.startswith("#") else (None, s)
        if s and not s.startswith("#") and (
                (name and name == target) or val == target
                or (s.startswith("re:") and s == target)):
            removed += 1
            continue
        kept.append(ln)
    if not removed:
        sys.exit(f"entry not found: {target}")
    _write_vault(kept, enc, args)
    print(f"removed {removed} entrie(s) — run 'reload' if the service is up")


def cmd_encrypt(args):
    if not args.yes:
        sys.exit("destructive operation (in place): confirm with --yes")
    lines, enc, _ = _read_vault(args)
    if enc:
        sys.exit("vault is already encrypted")
    _write_vault(lines, True, args)
    print(f"vault encrypted in place ({VAULT}); KDF salt: {SALT_PATH} "
          f"(not secret, permissions 0600)")


def cmd_decrypt(args):
    if not args.yes:
        sys.exit("destructive operation (in place): confirm with --yes")
    lines, enc, _ = _read_vault(args)
    if not enc:
        sys.exit("vault is not encrypted")
    _write_vault(lines, False, args)
    print("vault decrypted in place — remember to RE-ENCRYPT after "
          "maintenance and do NOT leave it in plain")


def main(argv=None):
    p = argparse.ArgumentParser(prog="vaultctl",
                                description="LLMCloak management CLI")
    p.add_argument("--admin-token", default=_env("API_KEY", ""),
                   help="admin token (default: env LLMCLOAK_API_KEY)")
    p.add_argument("--passphrase", default=None,
                   help="vault passphrase (non-interactive; otherwise prompts)")
    sub = p.add_subparsers(dest="cmd", required=True)
    sub.add_parser("status").set_defaults(fn=cmd_status)
    sub.add_parser("unlock").set_defaults(fn=cmd_unlock)
    sub.add_parser("lock").set_defaults(fn=cmd_lock)
    sp = sub.add_parser("upstream"); sp.add_argument("url", nargs="?", default=None)
    sp.set_defaults(fn=cmd_upstream)
    sub.add_parser("reload").set_defaults(fn=cmd_reload)
    sp = sub.add_parser("list"); sp.add_argument("--reveal", action="store_true")
    sp.set_defaults(fn=cmd_list)
    sp = sub.add_parser("add"); sp.add_argument("entry")
    sp.set_defaults(fn=cmd_add)
    sp = sub.add_parser("remove"); sp.add_argument("name_or_value")
    sp.set_defaults(fn=cmd_remove)
    sp = sub.add_parser("encrypt"); sp.add_argument("--yes", action="store_true")
    sp.set_defaults(fn=cmd_encrypt)
    sp = sub.add_parser("decrypt"); sp.add_argument("--yes", action="store_true")
    sp.set_defaults(fn=cmd_decrypt)
    args = p.parse_args(argv)
    args.fn(args)


if __name__ == "__main__":
    main()