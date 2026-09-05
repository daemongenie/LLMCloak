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
service.py — LLMCloak (spec v1, v1.1.0).

Mode A: transparent proxy towards an UPSTREAM (e.g. api.openai.com).
  - client auth inbound: Authorization: Bearer <client-token>
    (validated against the 'client:*' entries of the vault; not required
    in open mode)
  - request body: sanitize (secrets -> tags, INCLUDING named entries)
  - upstream auth: PASSTHROUGH (v1.2.8) — Authorization/x-api-key headers
    sent by the client are forwarded as-is, when present; otherwise no
    header. The vault does NOT inject provider keys (no 'provider:default').
  - response: desanitize (tag -> secret), buffered JSON or SSE streaming.
Mode B: POST /sanitize and /desanitize for programmatic use (same auth).

Vault key handling (v1.1.0):
  Mode B: LLMCLOAK_KEY env (Fernet key) -> vault loaded at startup.
  Mode A: no key at startup -> service LOCKED (503 on everything);
          unlock via POST /admin/unlock {"passphrase": ...} — the derived
          key lives ONLY in memory, never on disk.

Env:
  LLMCLOAK_VAULT=<vault path>   (default: vault.txt next to the package)
  LLMCLOAK_KEY=...        Fernet key for an encrypted vault (mode B)
  LLMCLOAK_API_KEY=...    admin token (X-Admin-Token / X-Proxy-Key);
                               empty: admin only from loopback
  LLMCLOAK_UPSTREAM=https://api.openai.com   (overrides config file)
  LLMCLOAK_CONFIG=<json>  persistent config (default service_config.json
                               next to the package; key is not secret)
  LLMCLOAK_PORT=8917

  Legacy SECRETS_PROXY_* variable names are still honoured as fallback
  (deprecated). Prefer the LLMCLOAK_* names.

Logs are ALWAYS redacted: never bodies, only counts. Mapping in memory only.

v1.2.0 — Web dashboard:
  GET  /dashboard                     UI (passphrase login at every start)
  POST /dashboard/api/session         create session (derived key in RAM ONLY)
  GET  /dashboard/api/state           state + entry list (masked values ONLY)
  POST/PUT/DELETE /dashboard/api/entries[...]   vault CRUD (encryption with
                                      the session key, salt preserved)
  POST /dashboard/api/encrypt         encrypts the plain vault in place
  POST /dashboard/api/lock            locks the service and drops sessions
  The passphrase is never saved (no disk/cookie/log): every app start
  asks it to the user again.

v1.2.1 — FIRST-RUN flow:
  GET  /dashboard/api/mode            mode: setup (vault absent) | locked |
                                      active — used by the UI at startup
  POST /dashboard/api/setup           first run: {passphrase, confirm} ->
                                      creates/encrypts the vault, loads the
                                      service, opens the session. 409 if the
                                      vault is already encrypted (use login).
                                      Min 8 chars, confirmation required.
"""
from __future__ import annotations

import re
import hmac
import ipaddress
import json
import os
import time
import threading

import httpx
import traceback
from fastapi import FastAPI, Request, Response, HTTPException, Header
from fastapi.responses import StreamingResponse

from core import (Sanitizer, StreamDesanitizer, VaultNotLoaded,
                   sse_feed_chunk, sse_flush,
                   derive_key, load_or_create_salt)
import dashboard as dash
from cryptography.fernet import Fernet, InvalidToken

_envdef = os.path.join(os.path.dirname(os.path.abspath(__file__)))


def _env(name: str, default=None):
    """Read LLMCLOAK_* first; legacy SECRETS_PROXY_* kept as fallback."""
    v = os.environ.get("LLMCLOAK_" + name)
    if v not in (None, ""):
        return v
    return os.environ.get("SECRETS_PROXY_" + name, default)


VAULT_PATH = _env("VAULT",
                  os.path.join(_envdef, "vault.txt"))
MASTER_KEY = _env("KEY") or None
ADMIN_KEY = _env("API_KEY", "")
CONFIG_PATH = _env("CONFIG",
                   os.path.join(_envdef, "service_config.json"))
ENV_UPSTREAM = _env("UPSTREAM", "").rstrip("/")
KDF_SALT_PATH = VAULT_PATH + ".salt"

START_TS = time.time()
HOP_HEADERS = {"host", "content-length", "connection", "keep-alive",
               "transfer-encoding", "upgrade", "proxy-authorization",
               "proxy-authenticate", "te", "trailer"}
LOOPBACK = {"127.0.0.1", "::1"}


def _load_config() -> dict:
    try:
        with open(CONFIG_PATH) as f:
            return json.load(f)
    except Exception:
        return {}


_CFG = _load_config()
UPSTREAM = ENV_UPSTREAM or str(_CFG.get("upstream", "")).rstrip("/")
# v1.2.7 — open mode: client token NOT required on the transparent path.
# v1.2.8 — auth passthrough: the client's Authorization/x-api-key headers are
#           forwarded to the upstream as they are; removed upstream_no_auth
#           and the provider:default vault entry (the client owns auth).
#   open_mode=false                     -> token required (as in v1.2.6)
#   open_mode=true, trusted_ips=[]      -> anyone can use the proxy
#   open_mode=true, trusted_ips=[ip,..] -> only those sources, no token
# INVARIANTS: dashboard/admin and /sanitize,/desanitize always authenticated.
# Fail-safe unchanged: vault locked -> 503 (never forward unfiltered).
OPEN_MODE = bool(_CFG.get("open_mode", False))
TRUSTED_IPS = [str(x).strip() for x in (_CFG.get("trusted_ips") or [])
               if str(x).strip()]
# v1.4.0 - model notice (default ON): when the sanitizer replaces content,
# a read-only system note is prepended to the chat payload so the model
# knows it is seeing pseudonymized tokens and must echo them verbatim
# (no translation, no completion, no invention). Turn it off any time with
# {"notice": false}. Roby's proposal: LLMs handle tokenized data better
# when they are TOLD that the data is tokenized.
NOTICE_ENABLED = bool(_CFG.get("notice", True))
# v1.5.7: sanitized-payload log (OFF by default). When enabled, every
# proxied request dumps the SANITIZED body actually forwarded upstream
# (tags only, never the plaintext) to the service log (journalctl).
# Toggle: config "log_sanitized": true  or  POST /admin/log-sanitized.
LOG_SANITIZED = bool(_CFG.get("log_sanitized", False))
LOG_SANITIZED_MAX = int(_CFG.get("log_sanitized_max", 4000))

# v1.5.7: per-request proxy-overhead telemetry. The header
# X-Proxy-Overhead-ms reports time spent INSIDE the proxy (sanitize in +
# desanitize out; the upstream LLM wait is excluded). Optional per-request
# log line, togglable via config "overhead_log", env
# LLMCLOAK_OVERHEAD_LOG, or POST /admin/overhead-log.
OVERHEAD_LOG = (bool(_CFG.get("overhead_log", False)) or
                _env("OVERHEAD_LOG", "").lower()
                in ("1", "true", "yes"))


def _log_sanitized_payload(method: str, path: str, body: bytes, n: int):
    """v1.5.7: dump the sanitized upstream payload for debugging.

    INVARIANT: this MUST only ever see the already-sanitized body
    (output of _sanitize_body). Fail-safe: hard truncation to
    LOG_SANITIZED_MAX chars; errors never break the proxy."""
    try:
        txt = body.decode("utf-8", "replace")
        if len(txt) > LOG_SANITIZED_MAX:
            txt = (txt[:LOG_SANITIZED_MAX] +
                   f" ...[truncated: {len(txt)} -> {LOG_SANITIZED_MAX} chars]")
        tag = f" ({n} tags)" if n else " (no tags)"
        print(f"[secrets-proxy] SANITIZED-OUT {method} /{path}{tag}:\n"
              f"{txt}", flush=True)
    except Exception as e:  # logging must never break the proxy
        print(f"[secrets-proxy] SANITIZED-OUT error: {e}", flush=True)

NOTICE_TEXT = (
    "NOTICE: Some values in this conversation are pseudonymized as short "
    "opaque tokens (like PWD_ab12cd34). Treat every such token as an "
    "atom: echo, copy and quote them EXACTLY as they appear, character "
    "for character. Never translate, complete, guess or modify them, and "
    "do not comment about this notice or the tokens.")

app = FastAPI(title="LLMCloak", version="1.5.11")
san = Sanitizer()
_stats = {"sanitized_out": 0, "restored_in": 0, "unresolved": 0,
          "requests": 0, "bytes_in": 0, "ingested": 0, "purged": 0}
_stats_lock = threading.Lock()
N_AUDIT_EVENTS = 200   # audit events served to the dashboard
_admin_lock = threading.Lock()


FERNET_MAGIC = b"gAAAAA"   # stable prefix of Fernet tokens (v0x80 + ts)


def _vault_is_encrypted(path: str) -> bool:
    with open(path, "rb") as f:
        head = f.read(8)
    return head.startswith(FERNET_MAGIC)


def _load_or_fail() -> None:
    if VAULT_PATH and os.path.exists(VAULT_PATH):
        if MASTER_KEY is None and _vault_is_encrypted(VAULT_PATH):
            raise VaultNotLoaded(
                "vault encrypted but no key: LOCKED (mode A — unlock via "
                "POST /admin/unlock, or set LLMCLOAK_KEY)")
        san.load_vault(VAULT_PATH, master_key=MASTER_KEY, enforce_perms=True)
        print(f"[secrets-proxy] vault loaded: {len(san.secrets)} secrets, "
              f"{len(san.named)} named, {len(san.patterns)} patterns", flush=True)


@app.on_event("startup")
def _startup() -> None:
    try:
        _load_or_fail()
    except Exception as e:
        # fail-safe: starts without vault -> LOCKED (503), never in clear.
        # If the vault is encrypted and LLMCLOAK_KEY is missing: mode A,
        # unlock via POST /admin/unlock.
        print(f"[secrets-proxy] VAULT NOT LOADED ({e!r}): LOCKED — "
              f"unlock via POST /admin/unlock", flush=True)
    _try_auto_unlock()


# ---------- v1.3.0: AUTO-UNLOCK at startup ----------
def _try_auto_unlock() -> None:
    """When the user enabled AUTO-UNLOCK (dashboard), the encrypted vault
    unlocks by itself at startup: the derived master key is on disk ONLY
    in encrypted form, wrapped with a secret bound to this machine. The
    passphrase is never saved. Any problem -> LOCKED (fail-safe)."""
    if san.is_loaded() or not os.path.exists(VAULT_PATH):
        return
    try:
        if not dash.vault_is_encrypted(VAULT_PATH):
            return   # plain vault: loads without a key, nothing to unlock
        if not dash.auto_unlock_enabled(VAULT_PATH):
            return
        key = dash.auto_unlock_key(VAULT_PATH)
        if key is None:
            print("[secrets-proxy] AUTO-UNLOCK enabled but NOT usable "
                  "(different machine or corrupted file): LOCKED", flush=True)
            return
        with _admin_lock:
            rep = san.load_vault(VAULT_PATH, master_key=key,
                                 enforce_perms=True)
        print(f"[secrets-proxy] AUTO-UNLOCK: vault unlocked automatically "
              f"({rep['secrets']} secrets, {rep['named']} named)",
              flush=True)
    except Exception as e:
        print(f"[secrets-proxy] AUTO-UNLOCK failed ({e!r}): LOCKED",
              flush=True)


# ---------- auth helpers ----------
def _admin_ok(request: Request, token: str) -> bool:
    if ADMIN_KEY:
        return hmac.compare_digest(token, ADMIN_KEY)
    # no admin token configured: allow loopback only
    host = request.client.host if request.client else ""
    return host in LOOPBACK


def _require_admin(request: Request, x_admin_token: str,
                   x_proxy_key: str = "") -> None:
    tok = x_admin_token or x_proxy_key
    if not _admin_ok(request, tok):
        raise HTTPException(403, "invalid admin token")


def _require_client(request: Request) -> str:
    """Inbound auth: Bearer token or X-Api-Key against the client:* entries.
    Fail-closed: without client:* entries in the vault every request is
    rejected."""
    _ip_allowed(request)
    if not san.is_loaded():
        raise HTTPException(503, "vault not loaded/locked (fail-safe)")
    clients = san.named_clients()
    if not clients:
        raise HTTPException(503, "no 'client:*' entry in the vault "
                                 "(fail-closed: configure one before using the proxy)")
    auth = request.headers.get("authorization", "")
    token = auth[7:].strip() if auth.lower().startswith("bearer ") else ""
    token = token or request.headers.get("x-api-key", "")
    for value, name in clients.items():
        if token and hmac.compare_digest(token, value):
            return name
    raise HTTPException(401, "invalid client token")


# ---------- v1.3.1: IP allowlist (trusted_ips) ----------
def _ip_allowed(request) -> None:
    """IP allowlist: empty list = all sources accepted. Each entry can be a
    single IP or a CIDR network (e.g. 192.168.1.0/24).
    Fail-closed: with a non-empty list, missing/unknown source -> 403.
    Dashboard and admin are NOT filtered (they have their own auth)."""
    if not TRUSTED_IPS:
        return
    ip = request.client.host if getattr(request, "client", None) else ""
    if ip:
        try:
            addr = ipaddress.ip_address(ip)
        except ValueError:
            addr = None
        if addr is not None:
            for entry in TRUSTED_IPS:
                try:
                    if addr in ipaddress.ip_network(entry, strict=False):
                        return
                except ValueError:
                    continue
    raise HTTPException(403, f"source {ip or '?'} not in the IP allowlist "
                             "(trusted_ips)")


def _gate_proxy(request: Request) -> str:
    """Gate of the transparent path ONLY (catch-all proxy).
    open_mode=false: client token required (v1.2.6 behaviour).
    open_mode=true:  no token; with trusted_ips set, only those IP sources
    are accepted (otherwise everyone). The fail-safe holds either way:
    vault locked -> 503, never forward without filtering the secrets."""
    if not san.is_loaded():
        raise HTTPException(503, "vault not loaded/locked (fail-safe)")
    if OPEN_MODE:
        _ip_allowed(request)
        return "open"
    _ip_allowed(request)   # allowlist applies in token mode too
    return _require_client(request)


# ---------- Mode B ----------
@app.get("/health")
def health():
    state = "active" if san.is_loaded() else "locked"
    return {"status": state, "loaded": san.is_loaded(),
            "secrets": len(san.secrets), "named": len(san.named),
            "patterns": len(san.patterns),
            "upstream": bool(UPSTREAM),
            "uptime_s": round(time.time() - START_TS, 1), "stats": _stats}


@app.post("/sanitize")
def sanitize_ep(request: Request, body: dict):
    client = _require_client(request)
    out, n = san.sanitize(body.get("text", ""))
    with _stats_lock:
        _stats["sanitized_out"] += n
    return {"text": out, "replaced": n, "client": client}


@app.post("/desanitize")
def desanitize_ep(request: Request, body: dict):
    client = _require_client(request)
    out, r, un = san.desanitize(body.get("text", ""))
    with _stats_lock:
        _stats["restored_in"] += r
        _stats["unresolved"] += len(un)
    return {"text": out, "restored": r, "unresolved": un}


# ---------- CSV ingestion (v1.4.0-dev) ----------
# Whole-list anonymization (e.g. a customer table extracted from Oracle).
# Same engine and invariants as the chat path: deterministic tags,
# verbatim round-trip, fail-safe when locked, logs/never content.
CSV_MAX_BYTES = 20 * 1024 * 1024     # 20 MB per request
CSV_MAX_ROWS = 200_000


# v1.5.4: delimiter auto-detection. The dashboard offers delimiter
# "auto" but (pre-1.5.3) sent no delimiter field, so every core fell
# back to "," -> a semicolon CSV parsed as ONE cell per row and ingest
# stored whole rows as single secrets (single-cell pastes then never
# matched in egress -> clear-text leak). Auto is now resolved HERE.
_CANDIDATE_DELIMS = (",", ";", "\t", "|")


def _detect_delimiter(text: str) -> str:
    """Pick the most plausible delimiter from a sample of the CSV."""
    sample = text[:256 * 1024]
    lines = [ln for ln in sample.splitlines()[:400] if ln.strip()]
    if len(lines) < 2:
        return ","
    best, best_score = ",", 0.0
    for cand in _CANDIDATE_DELIMS:
        counts = [ln.count(cand) for ln in lines]
        nz = [c for c in counts if c > 0]
        # delimiter must appear on most parsed lines
        if len(nz) < max(1, len(lines) // 2):
            continue
        avg = sum(nz) / len(nz)
        score = avg
        if max(nz) == min(nz):
            score += 5.0            # perfectly consistent column count
        if score > best_score:
            best, best_score = cand, score
    return best


def _csv_to_rows(text: str, delimiter: str = ",") -> list:
    import csv as _csv
    # v1.5.4: resolve 'auto'/empty here so ALL callers (sanitize/restore/
    # ingest, client + dashboard) accept the symbolic value consistently.
    if not delimiter or delimiter == "auto":
        delimiter = _detect_delimiter(text)
    if len(delimiter) != 1:
        raise HTTPException(400, "delimiter must be a single character")
    try:
        return list(_csv.reader(text.splitlines(), delimiter=delimiter))
    except _csv.Error as e:
        raise HTTPException(400, f"invalid CSV: {e!r}")


def _rows_to_csv(rows: list, delimiter: str = ",") -> str:
    import csv as _csv
    import io
    buf = io.StringIO()
    try:
        w = _csv.writer(buf, delimiter=delimiter, lineterminator="\n")
        w.writerows(rows)
        return buf.getvalue()
    finally:
        buf.close()


async def _csv_request_payload(request: Request) -> tuple:
    """Accepts multipart/form-data (file upload) or JSON {"csv": ...}.
    Returns (csv_text, options dict, filename or None)."""
    ctype = request.headers.get("content-type", "")
    if "multipart/form-data" in ctype:
        form = await request.form()
        up = None
        csv_text = None
        for k, v in form.items():
            if hasattr(v, "read"):
                if up is not None:
                    raise HTTPException(400, "only one file per request")
                up = v
            elif k == "csv" and isinstance(v, str) and v.strip():
                if csv_text is not None:
                    raise HTTPException(400, "only one csv field allowed")
                csv_text = v
        if up is None and csv_text is None:
            raise HTTPException(400, "missing csv file or field")
        if up is not None:
            filename = getattr(up, "filename", "upload.csv")
            raw = await up.read()
            if len(raw) > CSV_MAX_BYTES:
                raise HTTPException(413, f"CSV too large: {len(raw)} bytes "
                                         f"(max {CSV_MAX_BYTES})")
            csv_text = raw.decode("utf-8-sig", "replace")
        else:
            filename = None
            if len(csv_text) > CSV_MAX_BYTES:
                raise HTTPException(413, "CSV too large")
        opts = {}
        for k in ("on_missing", "header", "delimiter", "prefix", "columns",
                 "column_prefixes"):
            if k in form:
                opts[k] = form[k]
        return csv_text, opts, filename
    try:
        body = await request.json()
    except Exception:
        raise HTTPException(400, "JSON body or multipart upload required")
    csv_text = body.get("csv", "")
    if not isinstance(csv_text, str) or not csv_text.strip():
        raise HTTPException(400, "CSV text required in the 'csv' field")
    if len(csv_text) > CSV_MAX_BYTES:
        raise HTTPException(413, "CSV too large")
    return csv_text, body, None


# ---------- v1.4.1: shared CSV core (API endpoints + dashboard reuse) ----------
def _csv_sanitize_core(client: str, csv_text: str, opts: dict) -> dict:
    """Shared sanitize logic: dictionary+heuristics -> tag family.
    prefix (v1.5.0): custom tag prefix for the untyped mode (default PWD_);
    must match [A-Z][A-Z0-9_]{0,15}_ with a single trailing underscore
    (the vault core raises ValueError on a bad shape -> mapped to 400).
    column_prefixes (v1.5.2): "IDX:PREFIX,..." per-column override
    (e.g. "0:NOME_,2:EMAIL_"); each prefix validated like prefix; wins
    over prefix for those columns (typed mode: namespace only)."""
    _delim_opt = str(opts.get("delimiter") or "") or ""
    delimiter = _delim_opt if _delim_opt == "auto" else \
        (_delim_opt or _detect_delimiter(csv_text))

    # v1.5.6 fix: 'auto' is a UI-level selector, never a valid csv writer
    # delimiter -> resolve it for the output payload as well.
    out_delimiter = _detect_delimiter(csv_text) if _delim_opt == "auto" \
        else delimiter
    rows = _csv_to_rows(csv_text, delimiter)
    if len(rows) > CSV_MAX_ROWS:
        raise HTTPException(413, f"too many rows: {len(rows)} (max {CSV_MAX_ROWS})")
    if not isinstance(rows, list) or not rows:
        raise HTTPException(400, "CSV contains no rows")
    header = True if not isinstance(opts.get("header"), str) else \
        str(opts.get("header")).lower() != "false"
    typed_opt = opts.get("typed", False)
    typed = (typed_opt is True) if not isinstance(typed_opt, str) else \
        str(typed_opt).lower() in ("1", "true", "yes", "on")
    on_missing = opts.get("on_missing") or "keep"
    if on_missing not in ("keep", "tag"):
        raise HTTPException(400, "on_missing must be 'keep' or 'tag'")
    prefix_opt = opts.get("prefix")
    prefix = "PWD_" if prefix_opt in (None, "", "PWD_") else str(prefix_opt)
    from core import _PREFIX_RE as _prefix_rx
    if prefix != "PWD_" and not _prefix_rx.fullmatch(prefix):
        raise HTTPException(400, "prefix must match [A-Z][A-Z0-9_]{0,15}_ "
                                 "(trailing underscore, no '__')")
    # v1.5.2 per-column prefixes: "IDX:PREFIX,IDX:PREFIX" (e.g. "0:NOME_")
    # v1.5.7: shared parser (also used by ingest/restore).
    column_prefixes = _parse_column_prefixes(opts)
    # v1.5.0 column selection: comma-separated 0-based indices, empty = all.
    # Non-int or negative -> 400 (never silently ignored).
    columns = None
    if opts.get("columns") not in (None, ""):
        try:
            columns = {int(x.strip()) for x in str(opts["columns"]).split(",")
                       if x.strip() != ""}
        except ValueError:
            raise HTTPException(400, "columns must be comma-separated "
                                     "0-based integers, e.g. '1,3,4'")
        if not columns or any(x < 0 for x in columns):
            raise HTTPException(400, "columns must be non-negative integers")
    out_rows, replaced, tagged = san.sanitize_rows(rows, on_missing=on_missing,
                                                   header=header, typed=typed,
                                                   columns=columns,
                                                   prefix=prefix,
                                                   column_prefixes=column_prefixes)

    # v1.5.2: collect minted tag->secret pairs (typed + untyped whole-cell
    # mints). The dashboard "persist to vault" path needs them so the tags
    # issued in this batch stay restorable across restarts (the vault keeps
    # the original values; tags are re-derivable via the preserved salt).
    replacements = []
    _seen_tags = set()
    for row in out_rows:
        for cell in row:
            c = str(cell)
            if c in _seen_tags or c not in san.tag2secret:
                continue
            if re.fullmatch(r"[A-Z][A-Z0-9]*(?:_[A-Z0-9][A-Z0-9]*)*_"
                            r"[0-9a-f]{8,12}", c):
                _seen_tags.add(c)
                replacements.append((c, san.tag2secret[c]))

    with _stats_lock:
        _stats["sanitized_out"] += replaced + tagged
    resp = {"csv": _rows_to_csv(out_rows, out_delimiter), "rows": len(out_rows),
            "replaced": replaced, "tagged_cells": tagged,
            "unresolved": [], "client": client, "prefix": prefix,
            "columns": sorted(columns) if columns is not None else None,
            "column_prefixes": ({str(k): v for k, v in
                                 sorted(column_prefixes.items())}
                                if column_prefixes else None)}
    if str(opts.get("return_map") or "").lower() in ("1", "true", "yes", "on"):
        resp["replacements"] = replacements
    if typed:
        # redacted per-namespace tag types present in the output (no content)
        import re as _re
        kinds = sorted(set(
            m.group(1) for row in out_rows for cell in row
            for m in [_re.match(r"([A-Z][A-Z0-9]*(?:_[A-Z][A-Z0-9]*)*)_[0-9a-f]{8,12}$",
                               str(cell))] if m))
        resp["tag_types"] = kinds
    return resp


def _csv_restore_core(client: str, csv_text: str, opts: dict) -> dict:
    """Shared restore logic: PWD_*/<TYPE>_*/custom-prefix tags -> original
    cells. prefix (v1.5.0): tag family to restore; must mirror the prefix
    used at sanitize time. Unresolved tags stay verbatim and are reported."""
    _delim_opt = str(opts.get("delimiter") or "") or ""
    delimiter = _delim_opt if _delim_opt == "auto" else \
        (_delim_opt or _detect_delimiter(csv_text))

    # v1.5.6 fix: resolve 'auto' for the output payload (see sanitize).
    out_delimiter = _detect_delimiter(csv_text) if _delim_opt == "auto" \
        else delimiter
    rows = _csv_to_rows(csv_text, delimiter)
    if len(rows) > CSV_MAX_ROWS:
        raise HTTPException(413, f"too many rows: {len(rows)} (max {CSV_MAX_ROWS})")
    prefix_opt = opts.get("prefix")
    prefix = "PWD_" if prefix_opt in (None, "", "PWD_") else str(prefix_opt)
    from core import _PREFIX_RE as _prefix_rx
    if prefix != "PWD_" and not _prefix_rx.fullmatch(prefix):
        raise HTTPException(400, "prefix must match [A-Z][A-Z0-9_]{0,15}_ "
                                 "(trailing underscore, no trailing '__')")
    # v1.5.7: try every family of the original prefix spec, so tags
    # minted with per-column prefixes restore even when the caller only
    # passes the global prefix (restore mirrors sanitize-time families).
    fams = [prefix]
    for p in (_parse_column_prefixes(opts) or {}).values():
        if p not in fams:
            fams.append(p)
    out_rows, restored, unresolved = san.restore_rows(rows, prefix=prefix,
                                                      families=fams)
    with _stats_lock:
        _stats["restored_in"] += restored
        _stats["unresolved"] += len(unresolved)
    return {"csv": _rows_to_csv(out_rows, out_delimiter), "rows": len(out_rows),
            "restored": restored, "unresolved": unresolved,
            "client": client, "prefix": prefix}



def _csv_ingest_core(s, csv_text: str, opts: dict) -> dict:
    """'Ingest' mode (v1.4.1): seed the vault from a CSV. Every distinct
    data cell becomes a filterable value (exact, whole-cell match): the
    proxy will then replace those values with PWD_* tags in requests and
    restore them verbatim in LLM responses. NOTHING is emitted here --
    the response carries counts only (no content, no tags).
    Fail-safe: refuses when the vault is locked (caller checks first).
    Values are appended to the vault file and the RAM state reloaded with
    the preserved salt, so tags issued earlier stay valid (v1.2.0 rule).
    A value containing '=' is stored as the namespaced line 'ing:<value>'
    so the one-line-per-entry parser keeps treating it as a single value.
    """
    _delim_opt = str(opts.get("delimiter") or "") or ""
    delimiter = _delim_opt if _delim_opt == "auto" else \
        (_delim_opt or _detect_delimiter(csv_text))

    header = str(opts.get("header") or "true").lower() not in \
        ("0", "false", "no")
    rows = _csv_to_rows(csv_text, delimiter)
    if len(rows) > CSV_MAX_ROWS:
        raise HTTPException(413, f"too many rows: {len(rows)} (max {CSV_MAX_ROWS})")
    start = 1 if (header and rows) else 0
    # v1.5.7: ingest honours the per-column prefix spec: every value in a
    # prefixed column gets mapped value -> prefix so the chat-time tags
    # match the import family (R07_RAGIONE_SO_* instead of PWD_*).
    column_prefixes = _parse_column_prefixes(opts) or {}
    v2p: dict = {}
    seen, covered = {}, 0
    for row in rows[start:]:
        for j, cell in enumerate(row):
            c = cell.strip() if isinstance(cell, str) else str(cell)
            if not c:
                continue
            covered += 1
            seen[c] = True
            if column_prefixes and j in column_prefixes and c not in v2p:
                v2p[c] = column_prefixes[j]
    with _admin_lock:
        from cryptography.fernet import InvalidToken
        try:
            lines, _enc = dash.vault_lines(VAULT_PATH, s["key"])
        except InvalidToken:
            raise HTTPException(503, "session key not aligned with the "
                                     "vault: log in again")
        except FileNotFoundError:
            raise HTTPException(503, f"vault missing: {VAULT_PATH}")
        known = set()
        for ln in lines:
            t = ln.strip()
            if not t or t.startswith("#") or t.startswith("re:"):
                continue
            if t.startswith("ing:") and "=" in t:
                known.add(t[4:])          # legacy ingest line -> its value
            elif "=" in t and dash.NAMED_RE.match(t.split("=", 1)[0].strip()):
                known.add(t.split("=", 1)[1])
            else:
                known.add(t)
        # v1.4.1: ingested values are stored as PLAIN vault lines.
        # Guards: never let a CSV cell become a parser-active line
        # (regex injection, named-entry injection e.g. provider:default=...,
        # or legacy "ing:"-prefixed ambiguity).
        def _ingest_ok(v: str) -> bool:
            if v.startswith("re:") or v.startswith("#"):
                return False
            if "=" in v:
                cand = v.split("=", 1)[0].strip()
                if dash.NAMED_RE.match(cand) or cand.startswith("ing:"):
                    return False
            return True
        new_values = sorted(v for v in seen
                            if v not in known and _ingest_ok(v))
        before = set(san.tag2secret.values())
        if new_values:
            lines.extend(new_values)
            # DELIBERATE TRADE (as in dash_add): every write encrypts the
            # vault; the reload preserves the session salt so already
            # issued PWD_* tags remain resolvable.
            dash.persist_vault(VAULT_PATH, lines, s["key"], encrypt=True)
            # == _reload_after_change semantics (helpers are nested in
            #    dash_csv, so the equivalent logic lives here) ==
            if san.is_loaded():
                enc2 = dash.vault_is_encrypted(VAULT_PATH)
                salt2 = san.salt            # captured BEFORE the reload
                san.load_vault(VAULT_PATH, master_key=(s["key"] if enc2
                                                       else None),
                               enforce_perms=True, salt=salt2)
        added = len([v for v in san.tag2secret.values() if v not in before])
    with _stats_lock:
        _stats["ingested"] += added
    # v1.5.6: register the import in the encrypted history (filename, ts,
    # count and the exact lines appended) so a single import can be undone.
    if new_values:
        _import_record_add(s, str(opts.get("_filename") or "upload.csv"),
                           added, new_values, v2p=v2p)
    if v2p:
        san.set_value_prefix(v2p)   # immediate RAM effect (no reload)
    resp = {"ok": True, "rows": len(rows) - start, "cells": covered,
            "added": added, "skipped": len(seen) - len(new_values),
            "vault_entries": len(san.secrets) + len(san.named),
            "client": "dashboard",
            "delimiter": delimiter}
    san.audit_log(f"vault ingest: +{added} values from CSV "
                  f"({resp['rows']} rows, {covered} cells, "
                  f"delim {delimiter!r})")
    return resp


def _csv_purge_core(s, csv_text: str, opts: dict) -> dict:
    """Purge mode (v1.5.5): remove previously ingested values from the
    vault by uploading a CSV. Parsing is IDENTICAL to _csv_ingest_core
    (same delimiter resolution, same header handling) and the match is
    EXACT WHOLE-CELL: a vault line is removed only when its text equals a
    CSV cell verbatim (no substring, no partials). PROTECTED LINES are
    never touched: comments ("#..."), regex patterns ("re:...") and named
    entries (client:/provider:...). If a CSV cell exactly matches a
    protected line the request is refused with 400 (explicit guard, not a
    silent skip). Dashboard-only by design (destructive: no client-token
    endpoint). The vault is rewritten atomically and the RAM state
    reloaded with the salt captured BEFORE the reload (v1.2.0 rule:
    already issued PWD_* tags stay resolvable). NOTHING is emitted:
    counts only; the audit line carries a redacted sample only.
    """
    _delim_opt = str(opts.get("delimiter") or "") or ""
    delimiter = _delim_opt if _delim_opt == "auto" else \
        (_delim_opt or _detect_delimiter(csv_text))

    header = str(opts.get("header") or "true").lower() not in \
        ("0", "false", "no")
    rows = _csv_to_rows(csv_text, delimiter)
    if len(rows) > CSV_MAX_ROWS:
        raise HTTPException(413, f"too many rows: {len(rows)} (max {CSV_MAX_ROWS})")
    start = 1 if (header and rows) else 0
    seen, covered = {}, 0
    for row in rows[start:]:
        for cell in row:
            c = cell.strip() if isinstance(cell, str) else str(cell)
            if not c:
                continue
            covered += 1
            seen[c] = True

    with _admin_lock:
        from cryptography.fernet import InvalidToken
        try:
            lines, _enc = dash.vault_lines(VAULT_PATH, s["key"])
        except InvalidToken:
            raise HTTPException(503, "session key not aligned with the "
                                     "vault: log in again")
        except FileNotFoundError:
            raise HTTPException(503, f"vault missing: {VAULT_PATH}")
        if not san.is_loaded():
            raise HTTPException(503, "vault not loaded")

        # classify the vault lines exactly like the one-line-per-entry
        # parser does: named entries (client:/provider:...) and regex
        # patterns are PROTECTED; everything else is a purgeable value.
        protected, purgeable = set(), set()
        for ln in lines:
            t = ln.strip()
            if not t or t.startswith("#"):
                continue
            if t.startswith("re:") or dash.NAMED_RE.match(
                    t.split("=", 1)[0].strip()):
                protected.add(t)
            else:
                purgeable.add(t)
        if seen.keys() & protected:
            raise HTTPException(400, "refusing to purge: the CSV matches "
                                     "named/regex entries (manage them "
                                     "from the Entries tab)")
        removed = seen.keys() & purgeable
        if removed:
            kept = [ln for ln in lines if ln.strip() not in removed]
            # DELIBERATE TRADE (as in ingest/dash_add): every write
            # encrypts the vault; the reload preserves the session salt
            # so already issued PWD_* tags remain resolvable.
            dash.persist_vault(VAULT_PATH, kept, s["key"], encrypt=True)
            if san.is_loaded():
                enc2 = dash.vault_is_encrypted(VAULT_PATH)
                salt2 = san.salt        # captured BEFORE the reload
                san.load_vault(VAULT_PATH, master_key=(s["key"] if enc2
                                                       else None),
                               enforce_perms=True, salt=salt2)
        else:
            kept = lines
        after = sum(1 for ln in kept
                    if ln.strip() and not ln.strip().startswith("#"))
        resp = {"ok": True, "rows": len(rows) - start, "cells": covered,
                "purged": len(removed), "kept": after,
                "vault_entries": len(san.secrets) + len(san.named),
                "client": "dashboard",
                "delimiter": delimiter}
        if removed:
            sample = ", ".join(((v[:2] + "...") if len(v) > 2 else "...")
                               for v in sorted(removed)[:3])
            with _stats_lock:
                _stats["purged"] += len(removed)
            san.audit_log(f"vault purge: -{len(removed)} values via CSV "
                          f"({resp['rows']} rows, {covered} cells, "
                          f"delim {delimiter!r}; {sample})")
        else:
            san.audit_log(f"vault purge: no match ({resp['rows']} rows, "
                          f"{covered} cells, delim {delimiter!r})")
        return resp


@app.post("/csv/sanitize")
async def csv_sanitize(request: Request):
    """OUT (list -> LLM): every sensitive cell becomes an opaque PWD_* tag.
    Same client auth as /sanitize; fail-safe (locked -> 503)."""
    client = _require_client(request)
    csv_text, opts, _fname = await _csv_request_payload(request)
    return _csv_sanitize_core(client, csv_text, opts)


@app.post("/csv/restore")
async def csv_restore(request: Request):
    """IN (LLM -> list): PWD_* tags back to the original cells."""
    client = _require_client(request)
    csv_text, opts, _fname = await _csv_request_payload(request)
    return _csv_restore_core(client, csv_text, opts)


# ---------- Admin (v1.1.0) ----------
@app.get("/admin/status")
def admin_status(request: Request, x_admin_token: str = Header(default="")):
    _require_admin(request, x_admin_token)
    state = "active" if san.is_loaded() else "locked"
    return {"state": state, "upstream": UPSTREAM,
            "secrets": len(san.secrets), "named": len(san.named),
            "patterns": len(san.patterns), "stats": _stats,
            "uptime_s": round(time.time() - START_TS, 1),
            "client_entries": sorted(k for k in san.named
                                     if k.startswith("client:")),
            "provider_entries": sorted(k for k in san.named
                                       if k.startswith("provider:")),
            "open_mode": OPEN_MODE,
            "trusted_ips": TRUSTED_IPS}


@app.post("/admin/unlock")
async def admin_unlock(request: Request, x_admin_token: str = Header(default="")):
    """Mode A: passphrase -> KDF -> vault in memory. Key never on disk."""
    _require_admin(request, x_admin_token)
    if san.is_loaded():
        return {"unlocked": True, "already": True,
                "report": {"secrets": len(san.secrets), "named": len(san.named),
                           "patterns": len(san.patterns)}}
    try:
        body = await request.json()
        passphrase = str(body.get("passphrase", ""))
    except Exception:
        raise HTTPException(400, "JSON body with a 'passphrase' field required")
    if not passphrase:
        raise HTTPException(400, "empty passphrase")
    if not os.path.exists(VAULT_PATH):
        raise HTTPException(503, f"vault missing: {VAULT_PATH}")
    with _admin_lock:
        try:
            salt = load_or_create_salt(KDF_SALT_PATH)
            key = derive_key(passphrase, salt)
            rep = san.load_vault(VAULT_PATH, master_key=key, enforce_perms=True)
        except Exception as e:
            time.sleep(0.5)   # slows down brute-force
            name = type(e).__name__
            if name == "InvalidToken":
                raise HTTPException(401, "wrong passphrase")
            raise HTTPException(503, f"vault cannot be loaded: {name}")
    print(f"[secrets-proxy] UNLOCK ok: {rep['secrets']} secrets, "
          f"{rep['named']} named", flush=True)
    return {"unlocked": True, "report": rep}


@app.post("/admin/lock")
def admin_lock(request: Request, x_admin_token: str = Header(default="")):
    _require_admin(request, x_admin_token)
    san.lock()
    print("[secrets-proxy] LOCK: state wiped (503 until unlock)", flush=True)
    return {"locked": True}


@app.get("/admin/upstream")
def admin_upstream_get(request: Request, x_admin_token: str = Header(default="")):
    _require_admin(request, x_admin_token)
    return {"upstream": UPSTREAM, "source": "env" if ENV_UPSTREAM else "config"}


@app.post("/admin/upstream")
async def admin_upstream_set(request: Request,
                             x_admin_token: str = Header(default="")):
    _require_admin(request, x_admin_token)
    global UPSTREAM
    try:
        body = await request.json()
    except Exception:
        raise HTTPException(400, "JSON body required")
    url = str(body.get("url", "")).strip().rstrip("/")
    if not (url.startswith("https://") or url.startswith("http://")):
        raise HTTPException(400, "url must start with https:// or http://")
    UPSTREAM = url
    if not ENV_UPSTREAM:   # persist only if not overridden by env
        tmp = CONFIG_PATH + ".tmp"
        try:
            cfg = _load_config()
            cfg["upstream"] = url
            with open(tmp, "w") as f:
                json.dump(cfg, f, indent=1)
            os.replace(tmp, CONFIG_PATH)
            os.chmod(CONFIG_PATH, 0o600)
        except Exception as e:
            raise HTTPException(500, f"upstream updated in memory but "
                                     f"not persisted: {e!r}")
    return {"upstream": UPSTREAM, "persisted": not ENV_UPSTREAM}


@app.get("/admin/log-sanitized")
def admin_log_sanitized_get(request: Request,
                            x_admin_token: str = Header(default="")):
    """v1.5.7: state of the sanitized-payload log."""
    _require_admin(request, x_admin_token)
    return {"enabled": LOG_SANITIZED, "max_chars": LOG_SANITIZED_MAX}


@app.post("/admin/log-sanitized")
async def admin_log_sanitized_set(request: Request,
                                  x_admin_token: str = Header(default="")):
    """v1.5.7: toggle the sanitized-output log at runtime.
    Body: {"enabled": true|false, "max_chars": 4000 (optional)}."""
    global LOG_SANITIZED, LOG_SANITIZED_MAX
    _require_admin(request, x_admin_token)
    try:
        body = await request.json()
    except Exception:
        raise HTTPException(400, "JSON body required")
    if "enabled" in body:
        LOG_SANITIZED = bool(body.get("enabled"))
    if "max_chars" in body:
        try:
            LOG_SANITIZED_MAX = max(200, min(100000, int(body["max_chars"])))
        except Exception:
            raise HTTPException(400, "max_chars must be an integer")
    print(f"[secrets-proxy] log-sanitized -> {LOG_SANITIZED} "
          f"(max {LOG_SANITIZED_MAX} chars)", flush=True)
    return {"enabled": LOG_SANITIZED, "max_chars": LOG_SANITIZED_MAX}


@app.get("/admin/overhead-log")
async def admin_overhead_log_get(request: Request,
                                 x_admin_token: str = Header(default="")):
    """v1.5.7: state of the per-request overhead log."""
    _require_admin(request, x_admin_token)
    return {"enabled": OVERHEAD_LOG}


@app.post("/admin/overhead-log")
async def admin_overhead_log_set(request: Request,
                                 x_admin_token: str = Header(default="")):
    """v1.5.7: toggle the per-request overhead log at runtime.
    Body: {"enabled": true|false}."""
    global OVERHEAD_LOG
    _require_admin(request, x_admin_token)
    try:
        body = await request.json()
    except Exception:
        raise HTTPException(400, "JSON body required")
    OVERHEAD_LOG = bool(body.get("enabled"))
    print(f"[secrets-proxy] overhead-log -> {OVERHEAD_LOG}", flush=True)
    return {"enabled": OVERHEAD_LOG}


@app.post("/vault/reload")
def vault_reload(request: Request, x_proxy_key: str = Header(default=""),
                 x_admin_token: str = Header(default="")):
    """v1.5.1 fix: previously used only MASTER_KEY (env). When the vault was
    unlocked at startup via AUTO-UNLOCK (key wrapped on disk, env var absent),
    MASTER_KEY stayed None -> load_vault failed -> bare HTTP 500.
    Now: env key, else auto-unlock key, else a structured 503 (never a bare
    500). The key material lives only in RAM, as before."""
    _require_admin(request, x_admin_token, x_proxy_key)
    if not (VAULT_PATH and os.path.exists(VAULT_PATH)):
        raise HTTPException(404, "vault file not found")
    key = MASTER_KEY
    if key is None and _vault_is_encrypted(VAULT_PATH):
        # fallback: same machine-bound unwrap used at startup
        key = dash.auto_unlock_key(VAULT_PATH)
    if key is None and _vault_is_encrypted(VAULT_PATH):
        raise HTTPException(
            503, "vault is encrypted but no key is available (set "
                 "LLMCLOAK_KEY, enable AUTO-UNLOCK, or unlock via "
                 "POST /admin/unlock)")
    try:
        with _admin_lock:
            rep = san.load_vault(VAULT_PATH, master_key=key,
                                 enforce_perms=True)
    except VaultNotLoaded as e:
        raise HTTPException(503, f"vault cannot be loaded: {e!r}")
    except InvalidToken:
        raise HTTPException(401, "wrong key for vault (InvalidToken)")
    except Exception as e:
        raise HTTPException(503, f"vault cannot be loaded: {type(e).__name__}")
    print(f"[secrets-proxy] RELOAD ok: {rep['secrets']} secrets, "
          f"{rep['named']} named", flush=True)
    return {"reloaded": True, "report": rep}


# ---------- Web dashboard (v1.2.0, registered BEFORE the catch-all) ----------

def _save_config(cfg: dict) -> None:
    """Atomic config write with 0600 permissions."""
    tmp = CONFIG_PATH + ".tmp"
    with open(tmp, "w") as f:
        json.dump(cfg, f, indent=1)
    os.replace(tmp, CONFIG_PATH)
    os.chmod(CONFIG_PATH, 0o600)


def _norm_endpoint(url: str) -> str:
    return str(url).strip().rstrip("/")


def _endpoints_list() -> list:
    """v1.3.2 - list of selectable endpoints (dashboard picker).
    Normalized, deduplicated, valid http(s); always includes the active
    upstream even when absent from the config (e.g. upstream from env)."""
    cfg = _load_config()
    out: list = []
    for u in (cfg.get("endpoints") or []):
        u = _norm_endpoint(u)
        if ((u.startswith("https://") or u.startswith("http://"))
                and u not in out):
            out.append(u)
    if UPSTREAM and UPSTREAM not in out:
        out.insert(0, UPSTREAM)
    return out


def _set_upstream_url(url: str) -> dict:
    """Sets (and persists, unless overridden by env) the upstream.
    Shared by /admin/upstream and the dashboard. Guarantees the endpoint is
    present in the config 'endpoints' list (automatic migration)."""
    global UPSTREAM
    url = _norm_endpoint(url)
    if not (url.startswith("https://") or url.startswith("http://")):
        raise HTTPException(400, "url must start with https:// or http://")
    UPSTREAM = url
    if not ENV_UPSTREAM:   # persist only if not overridden by env
        try:
            cfg = _load_config()
            cfg["upstream"] = url
            eps = _endpoints_list()
            if url not in eps:
                eps.append(url)
            cfg["endpoints"] = eps
            _save_config(cfg)
        except Exception as e:
            raise HTTPException(500, f"upstream updated in memory but "
                                     f"not persisted: {e!r}")
    return {"upstream": UPSTREAM, "persisted": not ENV_UPSTREAM,
            "endpoints": _endpoints_list()}


def _add_endpoint_url(url: str) -> dict:
    """v1.3.2 - adds an endpoint to the list (without selecting it)."""
    url = _norm_endpoint(url)
    if not (url.startswith("https://") or url.startswith("http://")):
        raise HTTPException(400, "url must start with https:// or http://")
    eps = _endpoints_list()
    if url in eps:
        raise HTTPException(400, "endpoint already in the list")
    eps.append(url)
    persisted = not ENV_UPSTREAM
    if persisted:
        try:
            cfg = _load_config()
            cfg["endpoints"] = eps
            _save_config(cfg)
        except Exception as e:
            raise HTTPException(500, f"endpoint added in memory but "
                                     f"not persisted: {e!r}")
    return {"endpoints": eps, "upstream": UPSTREAM, "persisted": persisted}


def _remove_endpoint_url(url: str) -> dict:
    """v1.3.2 - removes an endpoint from the list. If it was the active one,
    the first remaining endpoint is selected automatically (or none)."""
    global UPSTREAM
    url = _norm_endpoint(url)
    eps = _endpoints_list()
    if url not in eps:
        raise HTTPException(404, "endpoint not in the list")
    eps.remove(url)
    note = None
    if url == UPSTREAM:
        UPSTREAM = eps[0] if eps else ""
        note = ("active endpoint deleted: automatically selected "
                + (UPSTREAM or "no upstream"))
    persisted = not ENV_UPSTREAM
    if persisted:
        try:
            cfg = _load_config()
            cfg["endpoints"] = eps
            cfg["upstream"] = UPSTREAM
            _save_config(cfg)
        except Exception as e:
            raise HTTPException(500, f"endpoint removed in memory but "
                                     f"not persisted: {e!r}")
    return {"endpoints": eps, "upstream": UPSTREAM, "persisted": persisted,
            "note": note}


def _select_endpoint_url(url: str) -> dict:
    """v1.3.2 - selects (activates) an endpoint present in the list."""
    url = _norm_endpoint(url)
    if url not in _endpoints_list():
        raise HTTPException(404, "endpoint not in the list")
    r = _set_upstream_url(url)
    return {"endpoints": r["endpoints"], "upstream": r["upstream"],
            "persisted": r["persisted"]}


def _register_dashboard(app) -> None:
    """Web dashboard routes (v1.2.0). Registered BEFORE the catch-all
    proxy. Sessions in RAM: the passphrase is never saved, the derived
    Fernet key lives only in the session (to encrypt on every write).
    """
    from fastapi.responses import HTMLResponse

    def _sess(request: Request) -> dict:
        tok = request.cookies.get(dash.SESSION_COOKIE, "")
        s = dash.SESSIONS.get(tok)
        if s is None:
            raise HTTPException(401, "session missing or expired: log in again")
        return s

    @app.middleware("http")
    async def _dash_no_store(request: Request, call_next):
        resp = await call_next(request)
        if request.url.path.startswith("/dashboard"):
            resp.headers["Cache-Control"] = "no-store"
            resp.headers["X-Frame-Options"] = "DENY"
            # v1.3.2 #22: hardening headers (task blockers 4)
            resp.headers["X-Content-Type-Options"] = "nosniff"
            resp.headers["Content-Security-Policy"] = (
                "default-src 'self'; script-src 'unsafe-inline'; "
                "style-src 'unsafe-inline'; img-src 'self' data:; "
                "connect-src 'self'; frame-ancestors 'none'; "
                "form-action 'self'; base-uri 'none'")
        return resp

    @app.get("/dashboard", response_class=HTMLResponse)
    def dashboard_page():
        return HTMLResponse(dash.get_html(),
                            headers={"Cache-Control": "no-store",
                                     "X-Frame-Options": "DENY"})

    @app.post("/dashboard/api/session")
    async def dash_login(request: Request, response: Response):
        """Login: the passphrase verifies/decrypts the vault and (mode A)
        unlocks the service. Only the derived key stays, in RAM."""
        try:
            body = await request.json()
        except Exception:
            raise HTTPException(400, "JSON body required")
        pw = str(body.get("passphrase", ""))
        if not pw:
            raise HTTPException(400, "empty passphrase")
        if not os.path.exists(VAULT_PATH):
            raise HTTPException(409, "vault missing: first use — set the "
                                     "passphrase (POST /dashboard/api/setup)")
        try:
            ok, key, enc = dash.verify_passphrase(VAULT_PATH, KDF_SALT_PATH, pw)
        except Exception as e:
            raise HTTPException(503, f"unreadable vault: {type(e).__name__}")
        if not ok:
            time.sleep(dash.BRUTE_DELAY_S)   # slows down brute-force
            san.audit_log("dashboard login failed")
            raise HTTPException(401, "wrong passphrase")
        unlocked_now = False
        if not san.is_loaded():
            try:
                with _admin_lock:
                    rep = san.load_vault(VAULT_PATH,
                                         master_key=(key if enc else None),
                                         enforce_perms=True)
                unlocked_now = True
                print(f"[secrets-proxy] UNLOCK (dashboard): "
                      f"{rep['secrets']} secrets, {rep['named']} named",
                      flush=True)
            except Exception as e:
                time.sleep(dash.BRUTE_DELAY_S)
                raise HTTPException(503,
                                    f"vault cannot be loaded: {type(e).__name__}")
        token = dash.SESSIONS.create(key)
        response.set_cookie(
            dash.SESSION_COOKIE, token, httponly=True, samesite="lax",
            max_age=dash.SESSION_TTL_ABS, path="/",
            secure=request.url.scheme == "https")
        return {"ok": True, "unlocked_service": unlocked_now}

    @app.delete("/dashboard/api/session")
    async def dash_logout(request: Request):
        dash.SESSIONS.drop(request.cookies.get(dash.SESSION_COOKIE, ""))
        return {"ok": True}

    @app.get("/dashboard/api/mode")
    def dash_mode():
        """First-run state (public, no sensitive data):
        setup = vault absent -> the UI shows the passphrase creation."""
        if not os.path.exists(VAULT_PATH):
            return {"mode": "setup", "vault_exists": False,
                    "vault_encrypted": False, "existing_entries": 0}
        enc = dash.vault_is_encrypted(VAULT_PATH)
        if not enc:
            try:
                lines, _ = dash.vault_lines(VAULT_PATH, None)
                n = len([l for l in lines
                         if l.strip() and not l.strip().startswith("#")])
            except Exception:
                n = 0
            return {"mode": "plain", "vault_exists": True,
                    "vault_encrypted": False, "existing_entries": n}
        return {"mode": "locked" if not san.is_loaded() else "active",
                "vault_exists": True, "vault_encrypted": True,
                "existing_entries": 0}

    @app.post("/dashboard/api/setup")
    async def dash_setup(request: Request, response: Response):
        """FIRST USE: the user picks the passphrase that encrypts the vault
        (nothing is saved: only the derived key, in RAM). Creates the vault
        (or preserves the entries of an existing plain one), loads the
        service and opens the session. Rejected if the vault is already
        encrypted."""
        if os.path.exists(VAULT_PATH) and dash.vault_is_encrypted(VAULT_PATH):
            raise HTTPException(409, "vault already encrypted: use the login "
                                     "with the existing passphrase")
        try:
            body = await request.json()
        except Exception:
            raise HTTPException(400, "JSON body required")
        pw = str(body.get("passphrase", ""))
        confirm = str(body.get("confirm", ""))
        if len(pw) < 8:
            raise HTTPException(400, "passphrase too short: minimum 8 characters")
        if pw != confirm:
            raise HTTPException(400, "the two passphrases do not match")
        with _admin_lock:
            if os.path.exists(VAULT_PATH):
                lines, _ = dash.vault_lines(VAULT_PATH, None)  # plain: no key
            else:
                lines = []
            salt = load_or_create_salt(KDF_SALT_PATH)
            key = derive_key(pw, salt)
            dash.persist_vault(VAULT_PATH, lines, key, encrypt=True)
            rep = san.load_vault(VAULT_PATH, master_key=key, enforce_perms=True)
        token = dash.SESSIONS.create(key)
        response.set_cookie(
            dash.SESSION_COOKIE, token, httponly=True, samesite="lax",
            max_age=dash.SESSION_TTL_ABS, path="/",
            secure=request.url.scheme == "https")
        print(f"[secrets-proxy] DASH SETUP (first run): vault created, "
              f"{rep['secrets']} secrets, {rep['named']} named", flush=True)
        dash.auto_unlock_disable(VAULT_PATH)   # new vault: invalid wrap
        return {"ok": True, "setup": True, "unlocked_service": True,
                "entries": rep["secrets"] + rep["named"]}


    # ------------------------------------------------ v1.2.5: recovery
    def _orphan_names():
        d = os.path.dirname(VAULT_PATH) or "."
        try:
            return sorted(os.listdir(d))
        except OSError:
            return []

    def _orphan_files():
        out = []
        d = os.path.dirname(VAULT_PATH) or "."
        for fn in _orphan_names():
            if not fn.startswith("vault.txt.") or fn.endswith(".salt"):
                continue
            p = os.path.join(d, fn)
            if not os.path.isfile(p):
                continue
            with open(p, "rb") as fh:
                head = fh.read(5)
            out.append({"file": fn, "bytes": os.path.getsize(p),
                        "mtime": int(os.path.getmtime(p)),
                        "encrypted": head.startswith(b"gAAAA")})
        return out

    def _salt_candidates(orph: str):
        """Salts to try for an orphan archive: first the current salt, then
        the archived salts paired with that vault."""
        cands = []
        if os.path.exists(KDF_SALT_PATH):
            cands.append(("current salt",
                          dash.load_or_create_salt(KDF_SALT_PATH)))
        d = os.path.dirname(VAULT_PATH) or "."
        extra = os.path.join(d, orph + ".salt")
        if os.path.isfile(extra):
            with open(extra, "rb") as fh:
                cands.append((orph + ".salt", fh.read()))
        if ".orphan-" in orph:
            ts = orph.split(".orphan-", 1)[1]
            p = os.path.join(d, "vault.txt.salt.orphan-" + ts)
            if os.path.isfile(p):
                with open(p, "rb") as fh:
                    cands.append(("vault.txt.salt.orphan-" + ts, fh.read()))
        return cands

    @app.get("/dashboard/api/orphans")
    def dash_orphans(request: Request):
        _sess(request)
        return {"orphans": _orphan_files()}

    @app.post("/dashboard/api/import")
    async def dash_import(request: Request):
        s = _sess(request)
        try:
            body = await request.json()
        except Exception:
            raise HTTPException(400, "JSON body required")
        fn = str(body.get("file", "")).strip()
        pw = str(body.get("passphrase", "") or "")
        if (not fn or fn != os.path.basename(fn)
                or not fn.startswith("vault.txt.") or fn.endswith(".salt")):
            raise HTTPException(400, "invalid file")
        d = os.path.dirname(VAULT_PATH) or "."
        p = os.path.join(d, fn)
        if not os.path.isfile(p):
            raise HTTPException(404, f"file not found: {fn}")
        with open(p, "rb") as fh:
            raw = fh.read()
        from cryptography.fernet import Fernet, InvalidToken
        plain = None
        if raw.startswith(b"gAAAA"):
            keys = [("current session", s["key"])]
            if pw:
                for nm, salt in _salt_candidates(fn):
                    keys.append((f"passphrase+{nm}",
                                 dash.derive_key(pw, salt)))
            for nm, k in keys:
                if not k:
                    continue
                try:
                    plain = Fernet(k).decrypt(raw).decode("utf-8")
                    break
                except InvalidToken:
                    continue
            if plain is None:
                raise HTTPException(422, "cannot decrypt the archive: try "
                                         "the passphrase used when it was "
                                         "active")
        else:
            plain = raw.decode("utf-8", "replace")
        new_lines = [ln.strip() for ln in plain.splitlines()
                     if ln.strip() and not ln.strip().startswith("#")]
        if not new_lines:
            raise HTTPException(422, "no valid entries in the archive")
        dash.parse_entries("\n".join(new_lines))   # validates, raises if broken
        with _admin_lock:
            cur_lines, _ = _vault_lines_with(s)
            added, skipped = 0, 0
            for ln in new_lines:
                try:
                    _check_duplicate(cur_lines, ln)
                    cur_lines.append(ln)
                    added += 1
                except HTTPException:
                    skipped += 1
            dash.persist_vault(VAULT_PATH, cur_lines, s["key"], encrypt=True)
            _reload_after_change(s["key"])
        print(f"[secrets-proxy] IMPORT from {fn}: {added} added, "
              f"{skipped} already present", flush=True)
        return {"ok": True, "added": added, "skipped": skipped,
                "total": len(cur_lines)}

    # ---------- v1.5.6: import history (list + per-import delete) ------
    @app.get("/dashboard/api/csv/history")
    async def dash_import_history(request: Request):
        """Encrypted registry of the CSV imports (v1.5.6): one record per
        ingest / sanitize+persist that added values to the vault."""
        s = _sess(request)
        recs = _imports_read(s)
        # v1.5.6 fix: newest first (last import on top of the UI list);
        # the registry itself stays append-ordered for the rollback logic.
        return {"ok": True, "imports": [
            {"id": r.get("id"), "ts": r.get("ts"), "file": r.get("file"),
             "added": r.get("added")} for r in reversed(recs)]}

    @app.delete("/dashboard/api/csv/history/{import_id}")
    async def dash_import_delete(request: Request, import_id: str):
        """Selective rollback (v1.5.6): removes from the vault every value
        added by that import (values imported earlier stay)."""
        s = _sess(request)
        out = _import_rollback(s, import_id)
        san.audit_log(f"import history delete: {import_id} "
                      f"(-{out['removed']} values)")
        return {"ok": True, **out}

    @app.post("/dashboard/api/reset")
    async def dash_reset(request: Request):
        _sess(request)
        try:
            body = await request.json()
        except Exception:
            raise HTTPException(400, "JSON body required")
        if str(body.get("confirm", "")) != "RESET":
            raise HTTPException(400, "missing confirmation: type RESET")
        ts = time.strftime("%Y%m%d-%H%M")
        d = os.path.dirname(VAULT_PATH) or "."
        arc = None
        with _admin_lock:
            if os.path.exists(VAULT_PATH):
                arc = os.path.basename(VAULT_PATH) + ".orphan-" + ts
                os.replace(VAULT_PATH, os.path.join(d, arc))
            if os.path.exists(KDF_SALT_PATH):
                os.replace(KDF_SALT_PATH,
                           os.path.join(d, "vault.txt.salt.orphan-" + ts))
            if_ = _imports_path()
            if os.path.exists(if_):
                os.replace(if_,
                           os.path.join(d, "vault.txt.imports.orphan-" + ts))
            dash.SESSIONS.drop_all()
            san.lock()
        dash.auto_unlock_disable(VAULT_PATH)   # fresh start: invalid wrap
        print(f"[secrets-proxy] RESET dashboard: vault archived as "
              f"{arc or 'N/A'}; LOCK, ready for a new setup", flush=True)
        return {"ok": True, "archived": arc}

    def _vault_lines_with(s: dict):
        """(lines, was_encrypted) using the session key."""
        from cryptography.fernet import InvalidToken
        try:
            return dash.vault_lines(VAULT_PATH, s["key"])
        except InvalidToken:
            raise HTTPException(503, "session key not aligned with the "
                                     "vault: log in again")
        except FileNotFoundError:
            raise HTTPException(503, f"vault missing: {VAULT_PATH}")

    def _reload_after_change(s_key: str) -> None:
        """Reloads the in-RAM state after a file write, PRESERVING the
        session salt (PWD_* tags already issued stay valid).
        NOTE: the caller must already hold _admin_lock."""
        if not san.is_loaded():
            return   # service locked: the next login reloads from disk
        enc = dash.vault_is_encrypted(VAULT_PATH)
        salt = san.salt                       # captured BEFORE the reload
        san.load_vault(VAULT_PATH, master_key=(s_key if enc else None),
                       enforce_perms=True, salt=salt)

    @app.get("/dashboard/api/state")
    def dash_state(request: Request):
        s = _sess(request)
        snap = {"service": "active" if san.is_loaded() else "locked",
                "version": "1.5.6",
                "upstream": UPSTREAM,
                "endpoints": _endpoints_list(),
                "vault_path": VAULT_PATH,
                "vault_encrypted": (os.path.exists(VAULT_PATH) and
                                    dash.vault_is_encrypted(VAULT_PATH)),
                "counts": {"secrets": len(san.secrets),
                           "named": len(san.named),
                           "patterns": len(san.patterns)},
                "stats": _stats,
                "uptime_s": round(time.time() - START_TS, 1),
                "sessions": dash.SESSIONS.count(),
                "ttl_idle_s": dash.SESSION_TTL_IDLE,
                "auto_unlock": dash.auto_unlock_enabled(VAULT_PATH),
                "trusted_ips": TRUSTED_IPS}
        if os.path.exists(VAULT_PATH):
            lines, _ = _vault_lines_with(s)
            snap["entries"] = dash.parse_entries("\n".join(lines))
        else:
            snap["entries"] = []
        return snap

    @app.get("/dashboard/api/audit")
    def dash_audit(request: Request):
        """Recent redacted audit events (newest first).

        #22 blocker 2+3: audit trail visible in the UI. Events carry
        timestamps and truncated tags only -- never secret content.
        """
        _sess(request)   # auth gate: 401 unless dashboard session cookie valid
        return {"events": san.audit_snapshot()[:N_AUDIT_EVENTS]}

    def _check_duplicate(lines: list, new_line: str) -> None:
        """Rejects duplicates: identical row, same named name, same secret
        value, same regex. Server-side comparison ONLY."""
        is_pattern = new_line.startswith("re:")
        new_name, new_val = (None, new_line)
        if not is_pattern and "=" in new_line:
            cand, val = new_line.split("=", 1)
            if dash.NAMED_RE.match(cand.strip()):
                new_name, new_val = cand.strip(), val
        for ln in lines:
            t = ln.strip()
            if not t or t.startswith("#"):
                continue
            if t == new_line:
                raise HTTPException(409, "entry already present")
            if is_pattern and t.startswith("re:") and t[3:] == new_line[3:]:
                raise HTTPException(409, "pattern already present")
            if new_name and t.split("=", 1)[0].strip() == new_name and "=" in t:
                raise HTTPException(409, f"entry already present: {new_name}")
            if not is_pattern and new_name is None:
                # plain secret: also rejects a value equal to a named one
                if t.startswith("re:"):
                    continue
                if "=" in t and dash.NAMED_RE.match(t.split("=", 1)[0].strip()):
                    if t.split("=", 1)[1] == new_val:
                        raise HTTPException(409, "value already present "
                                                 "as a named entry")

    @app.post("/dashboard/api/entries")
    async def dash_add(request: Request):
        s = _sess(request)
        try:
            body = await request.json()
        except Exception:
            raise HTTPException(400, "JSON body required")
        try:
            line = dash.parse_entry_input(str(body.get("kind", "secret")),
                                          body.get("name"),
                                          str(body.get("value", "")))
        except ValueError as e:
            raise HTTPException(400, str(e))
        with _admin_lock:
            lines, enc = _vault_lines_with(s)
            _check_duplicate(lines, line)
            lines.append(line)
            # DELIBERATE TRADE: every write encrypts the vault (automatic
            # upgrade from plain to encrypted on the first change). If the
            # vault was plain, the session passphrase becomes the permanent
            # unlock passphrase.
            dash.persist_vault(VAULT_PATH, lines, s["key"], encrypt=True)
            _reload_after_change(s["key"])
        print("[secrets-proxy] DASH entry added (vault updated)", flush=True)
        return {"ok": True}

    def _find_index(lines: list, eid: str) -> int:
        for i, ln in enumerate(lines):
            t = ln.strip()
            if not t or t.startswith("#"):
                continue
            if dash._entry_id(t) == eid:
                return i
        raise HTTPException(404, "entry not found")

    @app.put("/dashboard/api/entries/{eid}")
    async def dash_edit(eid: str, request: Request):
        s = _sess(request)
        try:
            body = await request.json()
        except Exception:
            raise HTTPException(400, "JSON body required")
        with _admin_lock:
            lines, enc = _vault_lines_with(s)
            idx = _find_index(lines, eid)
            old = lines[idx].strip()
            if old.startswith("re:"):
                kind, name = "pattern", None
            elif "=" in old and dash.NAMED_RE.match(old.split("=", 1)[0].strip()):
                kind, name = "named", old.split("=", 1)[0].strip()
            else:
                kind, name = "secret", None
            new_name = str(body.get("name") or name or "").strip() or None
            try:
                new_line = dash.parse_entry_input(kind, new_name,
                                                  str(body.get("value", "")))
            except ValueError as e:
                raise HTTPException(400, str(e))
            for i, ln in enumerate(lines):
                if i != idx and ln.strip() == new_line:
                    raise HTTPException(409, "entry already present")
            lines[idx] = new_line
            # DELIBERATE TRADE: every write encrypts the vault (automatic
            # upgrade from plain to encrypted on the first change). If the
            # vault was plain, the session passphrase becomes the permanent
            # unlock passphrase.
            dash.persist_vault(VAULT_PATH, lines, s["key"], encrypt=True)
            _reload_after_change(s["key"])
        return {"ok": True}

    @app.delete("/dashboard/api/entries/{eid}")
    async def dash_delete(eid: str, request: Request):
        s = _sess(request)
        with _admin_lock:
            lines, enc = _vault_lines_with(s)
            idx = _find_index(lines, eid)
            lines.pop(idx)
            # DELIBERATE TRADE: every write encrypts the vault (automatic
            # upgrade from plain to encrypted on the first change). If the
            # vault was plain, the session passphrase becomes the permanent
            # unlock passphrase.
            dash.persist_vault(VAULT_PATH, lines, s["key"], encrypt=True)
            _reload_after_change(s["key"])
        return {"ok": True}

    @app.post("/dashboard/api/entries/{eid}/tag")
    async def dash_tag(eid: str, request: Request):
        """PWD_* pseudonym used towards the upstream for that entry
        (never the clear value)."""
        s = _sess(request)
        if not san.is_loaded():
            raise HTTPException(503, "service locked")
        with _admin_lock:
            lines, enc = _vault_lines_with(s)
            idx = _find_index(lines, eid)
            old = lines[idx].strip()
            if old.startswith("re:"):
                raise HTTPException(400, "regex patterns have no fixed tag")
            if "=" in old and dash.NAMED_RE.match(old.split("=", 1)[0].strip()):
                value = old.split("=", 1)[1]
            else:
                value = old
            tag = san.tag_for(value)
        return {"tag": tag}

    @app.post("/dashboard/api/encrypt")
    async def dash_encrypt(request: Request):
        s = _sess(request)
        with _admin_lock:
            lines, enc = _vault_lines_with(s)
            if enc:
                raise HTTPException(400, "the vault is already encrypted")
            # DELIBERATE TRADE: every write encrypts the vault (automatic
            # upgrade from plain to encrypted on the first change). If the
            # vault was plain, the session passphrase becomes the permanent
            # unlock passphrase.
            dash.persist_vault(VAULT_PATH, lines, s["key"], encrypt=True)
            _reload_after_change(s["key"])
        print("[secrets-proxy] DASH vault encrypted in place", flush=True)
        return {"ok": True, "encrypted": True}

    @app.get("/dashboard/api/upstream")
    def dash_upstream_get(request: Request):
        _sess(request)
        return {"upstream": UPSTREAM, "source": "env" if ENV_UPSTREAM else "config",
                "endpoints": _endpoints_list()}

    @app.post("/dashboard/api/upstream")
    async def dash_upstream_set(request: Request):
        _sess(request)
        try:
            body = await request.json()
        except Exception:
            raise HTTPException(400, "JSON body required")
        return _set_upstream_url(str(body.get("url", "")))

    @app.get("/dashboard/api/endpoints")
    def dash_endpoints_get(request: Request):
        _sess(request)
        return {"endpoints": _endpoints_list(), "upstream": UPSTREAM,
                "source": "env" if ENV_UPSTREAM else "config"}

    @app.post("/dashboard/api/endpoints/add")
    async def dash_endpoints_add(request: Request):
        _sess(request)
        try:
            body = await request.json()
        except Exception:
            raise HTTPException(400, "JSON body required")
        return _add_endpoint_url(str(body.get("url", "")))

    @app.post("/dashboard/api/endpoints/delete")
    async def dash_endpoints_delete(request: Request):
        _sess(request)
        try:
            body = await request.json()
        except Exception:
            raise HTTPException(400, "JSON body required")
        return _remove_endpoint_url(str(body.get("url", "")))

    @app.post("/dashboard/api/endpoints/select")
    async def dash_endpoints_select(request: Request):
        _sess(request)
        try:
            body = await request.json()
        except Exception:
            raise HTTPException(400, "JSON body required")
        return _select_endpoint_url(str(body.get("url", "")))

    @app.post("/dashboard/api/lock")
    async def dash_lock(request: Request):
        """Locks the service and drops ALL sessions (RAM keys discarded).
        At the next app start: new passphrase prompt."""
        _sess(request)
        with _admin_lock:
            san.lock()
        n = dash.SESSIONS.drop_all()
        print("[secrets-proxy] LOCK (dashboard): sessions wiped", flush=True)
        return {"locked": True, "sessions_dropped": n}

    # ------------------------------------------------ v1.3.0: auto-unlock
    @app.get("/dashboard/api/auto-unlock")
    def dash_auto_unlock_get(request: Request):
        _sess(request)
        return {"enabled": dash.auto_unlock_enabled(VAULT_PATH),
                "note": "when enabled, the service unlocks by itself at "
                        "restart: the passphrase is not saved, only the "
                        "derived key, encrypted with a secret bound to "
                        "this machine"}

    @app.post("/dashboard/api/auto-unlock")
    async def dash_auto_unlock_set(request: Request):
        s = _sess(request)
        try:
            body = await request.json()
        except Exception:
            raise HTTPException(400, "JSON body required")
        enable = bool(body.get("enable"))
        if enable:
            if not os.path.exists(VAULT_PATH) or \
                    not dash.vault_is_encrypted(VAULT_PATH):
                raise HTTPException(409, "an encrypted vault is required: "
                                         "enable auto-unlock after 'Encrypt now'")
            if not san.is_loaded():
                raise HTTPException(409, "service locked: unlock first")
            dash.auto_unlock_enable(VAULT_PATH, s["key"])
            print("[secrets-proxy] AUTO-UNLOCK enabled (dashboard)",
                  flush=True)
            return {"enabled": True}
        dash.auto_unlock_disable(VAULT_PATH)
        print("[secrets-proxy] AUTO-UNLOCK disabled (dashboard)",
              flush=True)
        return {"enabled": False}

    # ------------------------------------------ v1.3.1: IP allowlist
    @app.get("/dashboard/api/trusted-ips")
    def dash_trusted_ips_get(request: Request):
        _sess(request)
        return {"trusted_ips": TRUSTED_IPS,
                "note": "empty = accept all sources; entries can be single "
                        "IPs or CIDR networks"}

    @app.post("/dashboard/api/trusted-ips")
    async def dash_trusted_ips_set(request: Request):
        global TRUSTED_IPS
        _sess(request)
        try:
            body = await request.json()
        except Exception:
            raise HTTPException(400, "JSON body required")
        ips = body.get("ips", [])
        if not isinstance(ips, list):
            raise HTTPException(400, "ips must be a list")
        clean = []
        for x in ips:
            e = str(x).strip().rstrip("/")
            if not e:
                continue
            try:
                if "/" in e:
                    clean.append(str(ipaddress.ip_network(e, strict=False)))
                else:
                    ipaddress.ip_address(e)   # validation only
                    clean.append(e)
            except ValueError:
                raise HTTPException(400, f"invalid IP or CIDR: {e!r}")
        TRUSTED_IPS = clean
        tmp = CONFIG_PATH + ".tmp"
        try:
            cfg = _load_config()
            cfg["trusted_ips"] = clean
            with open(tmp, "w") as f:
                json.dump(cfg, f, indent=1)
            os.replace(tmp, CONFIG_PATH)
            os.chmod(CONFIG_PATH, 0o600)
        except Exception as e:
            raise HTTPException(500, f"allowlist updated in memory but "
                                     f"not persisted: {e!r}")
        print(f"[secrets-proxy] IP ALLOWLIST: "
              f"{clean if clean else 'EMPTY (all sources)'}", flush=True)
        return {"trusted_ips": TRUSTED_IPS, "persisted": True}



    # ---------- v1.4.1: CSV workbench (upload / sanitize / restore) ----------
    def _persist_sanitize_values(s, pairs) -> int:
        """v1.5.0: append sanitize-discovered originals to the vault so the
        issued tags stay restorable across restarts (same preserved-salt
        reload as ingest). Best-effort: returns the number added."""
        if not pairs:
            return 0
        vals = sorted({str(v) for _t, v in pairs if v})
        if not vals:
            return 0
        from cryptography.fernet import InvalidToken
        try:
            lines, _enc = dash.vault_lines(VAULT_PATH, s["key"])
        except (InvalidToken, FileNotFoundError):
            return 0
        known = set()
        for ln in lines:
            t = ln.strip()
            if not t or t.startswith("#") or t.startswith("re:"):
                continue
            if t.startswith("ing:") and "=" in t:
                known.add(t[4:])
            elif "=" in t and dash.NAMED_RE.match(t.split("=", 1)[0].strip()):
                known.add(t.split("=", 1)[1])
            else:
                known.add(t)
        def _ok(v):
            if v.startswith("re:") or v.startswith("#"):
                return False
            if "=" in v:
                cand = v.split("=", 1)[0].strip()
                if dash.NAMED_RE.match(cand) or cand.startswith("ing:"):
                    return False
            return True
        new_values = [v for v in vals if v not in known and _ok(v)]
        if not new_values:
            return 0
        lines.extend(new_values)
        dash.persist_vault(VAULT_PATH, lines, s["key"], encrypt=True)
        if san.is_loaded():
            enc2 = dash.vault_is_encrypted(VAULT_PATH)
            # v1.5.2e fix: preserve the session salt across the reload,
            # else all tags minted this session are invalidated on restore.
            salt2 = getattr(san, "salt", None)
            san.load_vault(VAULT_PATH, master_key=(s["key"] if enc2 else None),
                           enforce_perms=True, salt=salt2)
        # v1.5.2 fix: the batch-minted tags already carry these values in
        # tag2secret, so diffing against a post-batch snapshot always gave 0.
        # Report what was actually appended to the vault instead.
        added = len(new_values)
        with _stats_lock:
            _stats["ingested"] += added
        # v1.5.6: a sanitize+persist batch is recorded in the import
        # history as its own entry (rollback = per-import delete).
        if added:
            _import_record_add(s, str(s.get("_upfile") or "sanitize"),
                               added, new_values)
        san.audit_log(f"csv sanitize persist: +{added} values to vault")
        return added

    @app.post("/dashboard/api/csv")
    async def dash_csv(request: Request):
        """CSV workbench for the UI: upload -> sanitize or restore.
        Auth = dashboard session (no client token needed). Same engine,
        same limits and same fail-safe as the /csv/* API: when the vault
        is locked the operation is refused (503)."""
        s = _sess(request)
        if not san.is_loaded():
            raise HTTPException(503, "vault locked: unlock the service first")
        ctype = request.headers.get("content-type", "")
        if "multipart/form-data" not in ctype:
            raise HTTPException(400, "multipart/form-data with a 'file' field required")
        form = await request.form()
        up = None
        for k, v in form.items():
            if hasattr(v, "read"):
                if up is not None:
                    raise HTTPException(400, "only one file per request")
                up = v
        if up is None:
            raise HTTPException(400, "missing csv file ('file' field)")
        filename = getattr(up, "filename", "upload.csv") or "upload.csv"
        s["_upfile"] = filename          # v1.5.6: for the import history
        raw = await up.read()
        if len(raw) > CSV_MAX_BYTES:
            raise HTTPException(413, f"CSV too large: {len(raw)} bytes "
                                     f"(max {CSV_MAX_BYTES})")
        csv_text = raw.decode("utf-8-sig", "replace")
        if not csv_text.strip():
            raise HTTPException(400, "empty file")
        mode = str(form.get("mode") or "sanitize").lower()
        if mode not in ("sanitize", "restore", "ingest", "purge"):
            raise HTTPException(400, "mode must be 'sanitize', 'restore', "
                                     "'ingest' or 'purge'")
        opts = {}
        for k in ("header", "delimiter", "typed", "on_missing", "prefix",
                  "columns", "column_prefixes", "_filename"):
            if k in form and str(form[k]).strip() != "":
                opts[k] = form[k]
        persist = str(form.get("persist") or "").lower() in ("1", "true", "yes")
        if mode == "sanitize":
            if persist:
                opts["return_map"] = "true"
            result = _csv_sanitize_core("dashboard", csv_text, opts)
            if persist:
                result["persisted"] = _persist_sanitize_values(
                    s, result.pop("replacements", []))
        elif mode == "ingest":
            opts["_filename"] = filename      # v1.5.6: name for the history
            result = _csv_ingest_core(s, csv_text, opts)
        elif mode == "purge":
            result = _csv_purge_core(s, csv_text, opts)
        else:
            result = _csv_restore_core("dashboard", csv_text, opts)
        result["filename"] = filename
        result["mode"] = mode
        san.audit_log(f"dashboard csv {mode}: file={filename!r} "
                      f"rows={result.get('rows')}")
        return result


_register_dashboard(app)


# ---------- v1.5.6: CSV import history registry (per-import delete) ----
IMPORTS_PATH = VAULT_PATH + ".imports"

def _imports_path() -> str:
    """v1.5.9: import registry path evaluated at CALL time — honours
    runtime VAULT_PATH changes (multi-vault reloads / test isolation);
    module-level IMPORTS_PATH stays as the import-time default."""
    return VAULT_PATH + ".imports"
IMPORTS_MAGIC = b"gAAAAA"     # Fernet token prefix


def _imports_read(s: dict) -> list:
    """Decrypted list of import records (one JSON object per line):
    {id, ts, file, added, vals: [vault lines appended by this import]}."""
    if not os.path.exists(_imports_path()):
        return []
    with open(_imports_path(), "rb") as f:
        raw = f.read()
    if raw.startswith(IMPORTS_MAGIC):
        raw = Fernet(s["key"].encode()).decrypt(raw)
    recs = []
    for ln in raw.decode("utf-8").splitlines():
        ln = ln.strip()
        if not ln:
            continue
        try:
            recs.append(json.loads(ln))
        except Exception:
            continue
    return recs


def _imports_write(s: dict, recs: list) -> None:
    """Atomic encrypted write of the registry (tmp 0600 + rename), same
    key as the vault; an empty list produces an empty plain file."""
    body = "\n".join(json.dumps(r, ensure_ascii=False) for r in recs)
    data = (body + "\n").encode("utf-8") if recs else b""
    if recs:
        data = Fernet(s["key"].encode()).encrypt(data)
    tmp = _imports_path() + ".tmp"
    fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    try:
        os.write(fd, data)
    finally:
        os.close(fd)
    os.replace(tmp, _imports_path())
    os.chmod(_imports_path(), 0o600)


def _parse_column_prefixes(opts: dict):
    """v1.5.7: shared per-column prefix parsing (v1.5.2 format
    "IDX:PREFIX,IDX:PREFIX", e.g. "0:NOME_,2:EMAIL_"). Returns
    {index: prefix} or None; raises HTTPException(400) on bad input."""
    if opts.get("column_prefixes") in (None, ""):
        return None
    from core import _PREFIX_RE as _prefix_rx
    column_prefixes = {}
    for part in str(opts["column_prefixes"]).split(","):
        part = part.strip()
        if not part:
            continue
        idx_s, _, pfx = part.partition(":")
        try:
            idx = int(idx_s.strip())
        except ValueError:
            raise HTTPException(
                400, "column_prefixes: index must be an integer "
                     "('IDX:PREFIX')")
        pfx = pfx.strip().upper()
        if idx < 0:
            raise HTTPException(400, "column_prefixes: negative index")
        if not _prefix_rx.fullmatch(pfx):
            raise HTTPException(
                400, "column_prefixes: prefix for column "
                     f"{idx} must match [A-Z][A-Z0-9_]{{0,15}}_")
        column_prefixes[idx] = pfx
    return column_prefixes


def _rebuild_value2prefix(master_key=None) -> None:
    """v1.5.7: rebuild the value -> column-prefix RAM index from the
    encrypted import registry after every vault (re)load. Fired by the
    Sanitizer._on_reload_cb hook (key = vault/session master key)."""
    try:
        recs = _imports_read({"key": master_key} if master_key else None)
        mapping = {}
        for r in recs:
            for v, p in (r.get("v2p") or {}).items():
                if isinstance(v, str) and isinstance(p, str):
                    mapping[v] = p
        if mapping:
            san.set_value_prefix(mapping)
            print(f"[secrets-proxy] value2prefix rebuilt: {len(mapping)} "
                  "entries", flush=True)
    except Exception as e:
        print(f"[secrets-proxy] value2prefix rebuild skipped: "
              f"{type(e).__name__}", flush=True)


san._on_reload_cb = _rebuild_value2prefix


def _import_record_add(s: dict, filename: str, added: int,
                       values: list, v2p: dict = None) -> None:
    """Appends one import record (v1.5.6); best-effort, never breaks the
    ingest/sanitize flow."""
    try:
        recs = _imports_read(s)
        rec = {"id": os.urandom(8).hex(),
               "ts": time.strftime("%Y-%m-%d %H:%M:%S"),
               "file": (filename or "upload.csv")[:120],
               "added": int(added),
               "vals": list(values)}
        if v2p:
            rec["v2p"] = dict(v2p)   # v1.5.7: value -> column prefix
        recs.append(rec)
        _imports_write(s, recs)
    except Exception as e:
        print(f"[secrets-proxy] import-history warning: {e}", flush=True)


def _import_rollback(s: dict, rec_id: str) -> dict:
    """Selective rollback (v1.5.6): removes from the vault every line
    recorded for the import `rec_id`, skipping lines that earlier imports
    recorded as well (a shared value stays until its last importer is
    deleted). Protected lines (#..., re:..., named client:/provider:...)
    are never touched. Returns {removed, skipped, vault_entries}."""
    from cryptography.fernet import InvalidToken
    recs = _imports_read(s)
    idx = next((i for i, r in enumerate(recs)
                if r.get("id") == rec_id), None)
    if idx is None:
        raise HTTPException(404, "import record not found")
    rec = recs.pop(idx)
    before = set()
    for r in recs[:idx]:
        before.update(r.get("vals") or [])
    drop = set(rec.get("vals") or [])
    try:
        lines, _enc = dash.vault_lines(VAULT_PATH, s["key"])
    except (InvalidToken, FileNotFoundError):
        raise HTTPException(503, "vault unreadable with this session key")
    kept, removed = [], []
    for ln in lines:
        st = ln.strip()
        if (st and not st.startswith("#") and not st.startswith("re:")
                and st in drop and st not in before):
            removed.append(st)
        else:
            kept.append(ln)
    if removed:
        dash.persist_vault(VAULT_PATH, kept, s["key"], encrypt=True)
        if san.is_loaded():
            enc2 = dash.vault_is_encrypted(VAULT_PATH)
            salt2 = san.salt            # captured BEFORE the reload
            san.load_vault(VAULT_PATH, master_key=(s["key"] if enc2
                                                   else None),
                           enforce_perms=True, salt=salt2)
    try:
        _imports_write(s, recs)
    except Exception as e:
        print(f"[secrets-proxy] import-history warning: {e}", flush=True)
    return {"removed": len(removed), "skipped": len(drop) - len(removed),
            "vault_entries": len(san.secrets) + len(san.named)}


# ---------- Mode A: transparent proxy ----------
def _walk_strings(obj, fn):
    """v1.5.10: apply fn to every string VALUE of a parsed JSON structure
    (dict values, list items, arbitrarily nested). Keys are protocol
    identifiers ("role", "model", "type", ...) and are deliberately left
    untouched: raw-text sanitization could rewrite them and corrupt the
    payload. Non-string leaves (numbers, booleans, null) pass through
    unchanged, so JSON literals can never be rewritten by the vault."""
    if isinstance(obj, str):
        return fn(obj)
    if isinstance(obj, list):
        return [_walk_strings(x, fn) for x in obj]
    if isinstance(obj, dict):
        return {k: _walk_strings(v, fn) for k, v in obj.items()}
    return obj


def _sanitize_body(raw: bytes):
    try:
        text = raw.decode("utf-8")
    except UnicodeDecodeError:
        return raw, 0  # binary payload: passthrough
    if not san.is_loaded():
        raise HTTPException(503, "vault not loaded: secrets cannot travel "
                                 "in clear to the upstream (fail-safe)")
    # v1.5.10: sanitize PARSED JSON string fields, never the raw JSON
    # text. With large CSV-ingested vaults (tens of thousands of
    # real-world cells) raw-text replacement can rewrite the JSON
    # structure itself (numeric literals like "id": 3471234567, the
    # true/false/null tokens, quotes and escapes inside string values):
    # the resulting body is no longer valid JSON and, forwarded as-is,
    # made upstreams answer '400 JSON parsing failed'. Parsing first and
    # walking only string values keeps the forwarded body valid JSON
    # whenever the client sent valid JSON. Non-JSON bodies keep the
    # legacy raw-text path (best effort).
    try:
        payload = json.loads(text)
    except Exception:
        out, n = san.sanitize(text)
        return out.encode("utf-8"), n
    total = 0

    def _san_str(s: str) -> str:
        nonlocal total
        out, n = san.sanitize(s)
        total += n
        return out

    new_payload = _walk_strings(payload, _san_str)
    if total == 0:
        return raw, 0
    return json.dumps(new_payload).encode("utf-8"), total


def _restore_response_text(text: str):
    """v1.5.10: desanitize PARSED JSON string fields when the upstream
    answer is JSON, so a restored secret containing quotes/backslashes/
    newlines is re-escaped by json.dumps instead of breaking the
    client-side JSON (mirror of the _sanitize_body fix). If nothing is
    restored the original text is returned byte-identical; non-JSON
    answers keep the legacy raw-text desanitize."""
    try:
        payload = json.loads(text)
    except Exception:
        return san.desanitize(text)
    restored, unresolved = 0, []

    def _des_str(s: str) -> str:
        nonlocal restored
        out, r, u = san.desanitize(s)
        restored += r
        unresolved.extend(u)
        return out

    new_payload = _walk_strings(payload, _des_str)
    if restored == 0:
        return text, 0, unresolved
    return json.dumps(new_payload,
                      ensure_ascii=False), restored, unresolved


def _inject_notice(payload, tagged: int):
    """Prepend the pseudonymization notice as the FIRST system message.
    Payload must already be a parsed JSON object. Best-effort: on any
    structure surprise the notice is simply skipped (never fails the
    request, never changes the chat semantics)."""
    if not tagged or not NOTICE_ENABLED:
        return payload
    try:
        if not payload.get("messages"):
            return payload
        msgs = payload["messages"]
        if isinstance(msgs[0], dict) and msgs[0].get("role") == "system" \
                and isinstance(msgs[0].get("content"), str) \
                and NOTICE_TEXT in msgs[0]["content"]:
            return payload                      # already there (idempotent)
        note = {"role": "system",
                "content": NOTICE_TEXT}
        payload["messages"] = [note] + msgs
        return payload
    except Exception:
        return payload


def _passthrough_headers(h) -> dict:
    return {k: v for k, v in h.items() if k.lower() not in HOP_HEADERS}


@app.api_route("/{path:path}",
               methods=["GET", "POST", "PUT", "PATCH", "DELETE"])
async def proxy(path: str, request: Request):
    t0 = time.perf_counter()            # v1.5.7 overhead telemetry
    if not UPSTREAM:
        raise HTTPException(404, "mode A not active (upstream not configured)")
    _gate_proxy(request)              # token (or open mode) + fail-safe locked
    raw = await request.body()
    body, n = _sanitize_body(raw)
    if n:
        try:
            payload = json.loads(body.decode("utf-8"))
            if isinstance(payload, dict):
                payload = _inject_notice(payload, n)
                body = json.dumps(payload).encode("utf-8")
        except Exception:
            pass                                # not JSON: forward as-is
    pre_ms = (time.perf_counter() - t0) * 1000.0   # proxy work pre-upstream
    with _stats_lock:
        _stats["requests"] += 1
        _stats["bytes_in"] += len(raw)
        _stats["sanitized_out"] += n
    if n:
        print(f"[secrets-proxy] OUT {request.method} /{path}: "
              f"{n} secrets pseudonymized", flush=True)
    if LOG_SANITIZED:
        _log_sanitized_payload(request.method, path, body, n)

    # v1.2.9: /v1 prefix normalization. If the upstream already ends with
    # "/v1" (e.g. https://openrouter.ai/api/v1) and the client uses a base
    # URL without /v1 while prefixing "v1/" to the path (OpenAI SDK style),
    # without the fix we generate {upstream}/v1/... -> 404 (HTML) and the
    # model list in the WebUI shows up empty. We strip the duplicate. With
    # an upstream WITHOUT /v1 (e.g. Ollama http://host:11434) the path is
    # kept verbatim: Ollama natively serves /v1/chat/completions.
    fwd = path
    if (fwd == "v1" or fwd.startswith("v1/")) and UPSTREAM.endswith("/v1"):
        fwd = fwd[3:] if fwd != "v1" else ""
    url = f"{UPSTREAM}/{fwd}" if fwd else UPSTREAM
    if request.url.query:
        url += f"?{request.url.query}"
    headers = _passthrough_headers(request.headers)
    # v1.2.8 auth passthrough: if the client sends a token (Authorization /
    # x-api-key) we forward it as-is, otherwise no header.
    # Only cookies stay forbidden (the dashboard session is never a
    # credential of an LLM API).
    for k in list(headers):
        if k.lower() == "cookie":
            del headers[k]

    client = httpx.AsyncClient(timeout=120.0)
    req = client.build_request(request.method, url, headers=headers, content=body)
    try:
        r = await client.send(req, stream=True)
    except Exception:
        await client.aclose()
        raise
    t_send = time.perf_counter()        # upstream returned (headers ready)

    ctype = r.headers.get("content-type", "")
    if "text/event-stream" in ctype:
        # v1.5.7: auto multi-family (PWD_ + every family minted this
        # session) so tags from prefix-tagged CSV imports restore in SSE.
        sd = StreamDesanitizer(san)

        async def gen():
            # v1.1.2: SSE-aware path. LLM providers wrap tokens into JSON
            # lines: desanitizing the RAW stream cannot rejoin a tag split
            # across two events (the halves are not adjacent). We extract
            # the content field of each event, desanitize it (the model
            # text IS adjacent) and re-encapsulate it.
            # Non-JSON lines / without content: untouched passthrough.
            try:
                async for chunk in r.aiter_text():
                    out = sse_feed_chunk(sd, chunk)
                    if out:
                        yield out
                tail = sse_flush(sd)
                if tail:
                    yield tail
            finally:
                await r.aclose()
                await client.aclose()
                with _stats_lock:
                    _stats["restored_in"] += sd.restored_count
                if sd.restored_count:
                    print(f"[secrets-proxy] IN (SSE) /{path}: "
                          f"{sd.restored_count} restorations", flush=True)

        if OVERHEAD_LOG:
            print(f"[secrets-proxy] OVERHEAD /{path}: pre={pre_ms:.2f}ms "
                  f"(SSE; post measured at stream end)", flush=True)
        return StreamingResponse(gen(), status_code=r.status_code,
                                 media_type="text/event-stream",
                                 headers={"X-Proxy-Overhead-ms":
                                          f"{pre_ms:.2f}"})

    # buffered response (JSON etc.): stream=True requires aread() before .text
    try:
        await r.aread()
        text = r.text
    finally:
        await r.aclose()
        await client.aclose()
    t_pre_ds = time.perf_counter()  # upstream I/O (aread/aclose) excluded
    out, restored, unresolved = _restore_response_text(text)
    with _stats_lock:
        _stats["restored_in"] += restored
        _stats["unresolved"] += len(unresolved)
    if restored or unresolved:
        print(f"[secrets-proxy] IN /{path}: {restored} restorations, "
              f"{len(unresolved)} unresolved tags", flush=True)
    post_ms = (time.perf_counter() - t_pre_ds) * 1000.0
    resp = Response(content=out.encode("utf-8"), status_code=r.status_code,
                    media_type=ctype or "application/json")
    # v1.5.7: proxy overhead = sanitize-in + desanitize-out (upstream wait
    # excluded) so the header isolates what the proxy itself costs.
    resp.headers["X-Proxy-Overhead-ms"] = f"{pre_ms + post_ms:.2f}"
    if OVERHEAD_LOG:
        print(f"[secrets-proxy] OVERHEAD /{path}: proxy="
              f"{pre_ms + post_ms:.2f}ms (pre={pre_ms:.2f}, "
              f"post={post_ms:.2f}) wall={(time.perf_counter() - t0) * 1000.0:.2f}ms",
              flush=True)
    return resp


def sd_feed(sd: StreamDesanitizer, chunk: str) -> str:
    return sd.feed(chunk)