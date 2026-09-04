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
core.py — secret pseudonymization <-> opaque tags.

Spec: llm_secrets_proxy_spec_v1.md (Reggie/Roby). v1.1.0.

Key rules:
- tag = HMAC-SHA256(session salt, secret)[:4 bytes] in hex  -> "PWD_xxxxxxxxx"
  (8 hex; 12 hex only for colliding items, detected at vault load)
- deterministic within the session: same secret -> same tag
- reverse map in-memory only (tag -> secret), never on disk
- fail-safe: with no vault loaded, sanitize() raises — never passes
  secrets in clear
- tolerant matching in desanitize: spaces/quotes around the tag, exact core
- longest-first replacement, final no-leak check on every sanitize

v1.1.0 — named entries:
- vault line "name=value" with a name matching FERNET_MAGIC = b"gAAAAA"   # stable prefix of Fernet tokens
NAMED_RE (client:*|provider:*)
  -> NAMED entry: the value is retrievable via lookup(name) AND masked in
  bodies like any other secret (the client token must never reach the upstream)
- lock(): full state wipe (used by POST /admin/lock)
- KDF: derive_key(passphrase, salt) -> Fernet key (PBKDF2-HMAC-SHA256)
"""
from __future__ import annotations

import base64
import functools
import hashlib
import hmac
import json
import os
import re
import threading
import time
from typing import Dict, List, Optional, Tuple

TAG_PREFIX = "PWD_"
TAG_CORE_RE = re.compile(r"PWD_([0-9a-f]{8,12})")
# tolerant: quotes/spaces around the tag, but the core stays exact
TAG_TOLERANT_RE = re.compile(r"[\"'\s]*PWD_([0-9a-f]{8,12})[\"'\s]*")


@functools.lru_cache(maxsize=256)
def _tolerant_rx(prefix: str = "PWD_") -> re.Pattern:
    """v1.5.0: same tolerant shape as TAG_TOLERANT_RE but for a custom
    prefix (used by desanitize when a non-default prefix is requested)."""
    esc = re.escape(prefix)
    return re.compile(r"[\"'\s]*" + esc + r"([0-9a-f]{8,12})[\"'\s]*")
TAG_MIN_TOTAL = len(TAG_PREFIX) + 8   # 12
TAG_MAX_TOTAL = len(TAG_PREFIX) + 12  # 16
# v1.4.0: whole-cell fast path for batch restore + header normalization
# v1.4.0 typed namespaces: allow underscores in the tag family (RAGIONE_SOC_*)
# v1.4.2-fix: family segments may also START with a digit (headers like
# R07_CD_AGENTE_02 mint namespaces ending in "_02": the old letter-only
# segment rule made those tags unrecognizable at restore -> never resolved
# and not even reported). The hex tail (8-12) remains the discriminator
# against ordinary business codes.
# v1.5.0: builder so a custom prefix keeps restore working via the
# whole-cell fast path. "PWD" stays as explicit first alternative.
def _whole_tag_rx(prefix: str = "PWD") -> re.Pattern:
    esc = re.escape(prefix)
    family = r"[A-Z][A-Z0-9]*(?:_[A-Z0-9][A-Z0-9]*)*"
    return re.compile(r"(?:" + esc + r"|" + family + r")_[0-9a-f]{8,12}")


_WHOLE_TAG_RE = _whole_tag_rx("PWD")

# v1.5.0: user-supplied whole-cell tag prefix (untyped mode). Uppercase
# start, then uppercase/digits/underscores, MUST end with a single
# trailing underscore, never two in a row (avoids "MY__" ambiguity).
_PREFIX_RE = re.compile(r"[A-Z](?:[A-Z0-9]|_(?!_)){0,15}_")
# Tag-LIKE but unknown: report-only (never altered). To avoid flagging
# ordinary business codes (e.g. "R07_CD_CLIENTE") the generic shape
# requires a HEX core (what this service actually mints for typed tags);
# the reserved PWD_ prefix flags any core, per unresolved-visibility req.
_TAG_LIKE_RE = re.compile(
    r"(?:PWD_[0-9A-Za-z]{6,}|[A-Z][A-Z0-9]*(?:_[A-Z0-9][A-Z0-9]*)*_[0-9a-f]{8,12})")


def _norm_header(h) -> str:
    """Normalize a CSV column header to the typed-mode namespace:
    lowercase, strip, collapse non-alphanumerics to single underscores,
    max 16 chars. e.g. 'Ragione  Sociale!' -> 'ragione_sociale'."""
    h = str(h or "").strip().lower()
    if not h:
        return ""
    h = re.sub(r"[^0-9a-z]+", "_", h).strip("_")
    return h[:16]

# named entries: client:<id> | provider:<id> | ing:<value> | ing:<value> | ing:<value>
FERNET_MAGIC = b"gAAAAA"   # stable prefix of Fernet tokens
NAMED_RE = re.compile(r"^(client|provider):[A-Za-z0-9_.-]+$")  # v1.4.1: ingested CSV values are stored as PLAIN lines (ing: prefix removed: it collided with the name=value parser)

# PBKDF2 iterations (OWASP 2023 guidance for PBKDF2-SHA256)
KDF_ITERATIONS = 600_000


class VaultNotLoaded(RuntimeError):
    """Vault not loaded: sanitize must fail, never pass secrets in clear."""


class VaultCollisionError(RuntimeError):
    """Distinct secrets -> same tag even after extension: we refuse."""


def derive_key(passphrase: str, salt: bytes,
               iterations: int = KDF_ITERATIONS) -> str:
    """Passphrase -> Fernet key (32B via PBKDF2-HMAC-SHA256). Deterministic."""
    dk = hashlib.pbkdf2_hmac("sha256", passphrase.encode("utf-8"),
                             salt, iterations, dklen=32)
    return base64.urlsafe_b64encode(dk).decode("ascii")


def load_or_create_salt(salt_path: str) -> bytes:
    """KDF salt (not secret): 16B random, 0600 file, created if absent."""
    if os.path.exists(salt_path):
        with open(salt_path, "rb") as f:
            salt = f.read()
        if len(salt) != 16:
            raise VaultNotLoaded(f"corrupted KDF salt: {salt_path}")
        return salt
    salt = os.urandom(16)
    fd = os.open(salt_path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    try:
        os.write(fd, salt)
    finally:
        os.close(fd)
    return salt


class Sanitizer:
    def __init__(self, salt: Optional[bytes] = None):
        self._lock = threading.RLock()
        self.salt: bytes = salt if salt is not None else os.urandom(16)
        self.secrets: List[str] = []        # plain secrets (dedup)
        self.patterns: List[re.Pattern] = []
        self.named: Dict[str, str] = {}     # name -> value (client:*, provider:*)
        self._values: List[str] = []        # plain secrets + named values
        self.tag2secret: Dict[str, str] = {}
        # v1.5.2: prefix-independent reverse index (tag core -> secret).
        # load_from_lists rebuilds only PWD_* tags, so custom-prefix
        # families (NOME_*, EMAIL_*) died on every vault reload; the core
        # is family-independent (HMAC(salt, secret)) -> safe lookup.
        self.tag_core2secret: Dict[str, str] = {}
        self._ac = None                    # Aho-Corasick index (perf v1.4.2)
        # v1.5.7: values minted as whole-cell tags (sanitize_rows / CSV
        # API). They are restorable via tag2secret but were NOT in the
        # dictionary/AC, so a later chat mentioning the value went out
        # UNFILTERED. This value->tag registry fixes the OUT direction too.
        self._minted_extra: Dict[str, str] = {}
        self.loaded: bool = False
        self.audit: List[str] = []          # redacted events (max 500)
        self.replace_count: int = 0

    # ---------- tag derivation ----------
    def _tag_core(self, secret: str, nbytes: int = 4) -> str:
        d = hmac.new(self.salt, secret.encode("utf-8"), hashlib.sha256).digest()
        core = d[:nbytes].hex()
        # v1.5.2: refresh the prefix-independent reverse index (restore of
        # custom-prefix families after a vault reload/restart).
        self.tag_core2secret[core] = secret
        return core

    def set_value_prefix(self, mapping: dict) -> None:
        """v1.5.7: bulk-set the value -> tag-family index used by
        tag_for()/sanitize() to mint column-aware tags for values that
        came from a CSV import with per-column prefixes. Last import
        wins for shared values; invalid entries are ignored."""
        if not isinstance(mapping, dict):
            return
        with self._lock:
            for v, p in mapping.items():
                if (isinstance(v, str) and isinstance(p, str)
                        and _PREFIX_RE.fullmatch(p)):
                    self.value2prefix[v] = p

    def tag_for(self, secret: str, prefix: str = "PWD_") -> str:
        # v1.5.7: column-aware family takes precedence for ingested values;
        # otherwise the caller's active family (sanitize prefix), then PWD_.
        fam = self.value2prefix.get(secret) or prefix or "PWD_"
        if fam != "PWD_":
            with self._lock:
                return self._mint(fam, secret)
        with self._lock:
            # registered tag (anti-collision extension) takes precedence
            for n in (4, 6):
                t = TAG_PREFIX + self._tag_core(secret, n)
                if t in self.tag2secret and self.tag2secret[t] == secret:
                    return t
            # _mint already returns "PWD_" + core; never prepend TAG_PREFIX
            # again (v1.4.0 bugfix: it produced double prefixes like
            # PWD_PWD_xxxx and broke the restore round-trip)
            return self._mint("PWD_", secret)

    def _mint(self, prefix: str, value: str) -> str:
        """Session-unique tag minting: prefix + hex core. On a collision
        with a DIFFERENT existing value the core widens up to 12 hex;
        every width matches TAG_TOLERANT_RE so restore is unaffected."""
        with self._lock:
            for n in (4, 6, 8, 10, 12):
                tag = prefix + self._tag_core(value, n)
                hit = self.tag2secret.get(tag)
                if hit is None or hit == value:
                    # v1.5.7: register every minted tag (also custom
                    # families) so desanitize()'s auto-family discovery
                    # sees them and stream/batch restore works.
                    self.tag2secret.setdefault(tag, value)
                    self._touch_fams(tag)
                    return tag
            self._audit(f"FATAL tag mint exhausted ({prefix}*)")
            raise RuntimeError(f"tag mint exhausted for prefix {prefix}")

    def _retag_token(self, tok: str, prefix: str = "PWD_") -> str:
        """v1.5.11: deterministic opaque token for a FOREIGN tag-shaped
        span (old tag from a previous vault state). Width starts at 8 hex
        so the token is always restore-matchable; the mapping is stored so
        desanitize() hands the original token back to the client. The core
        index uses setdefault only: a foreign token must NEVER overwrite
        the core->secret mapping of a real secret."""
        fam = prefix or "PWD_"
        with self._lock:
            # width 4/5/6 BYTES = 8/10/12 hex chars: the token must always
            # stay matchable by _MULTI_TAG_RX / TAG_TOLERANT_RE (8..12 hex)
            # so desanitize() can restore it.
            for n in (4, 5, 6):
                d = hmac.new(self.salt, tok.encode("utf-8"),
                             hashlib.sha256).digest()
                core = d[:n].hex()
                tag = fam + core
                hit = self.tag2secret.get(tag)
                if hit is None or hit == tok:
                    self.tag2secret.setdefault(tag, tok)
                    self.tag_core2secret.setdefault(core, tok)
                    self._touch_fams(tag)
                    return tag
            return self._mint(fam, tok)

    def _audit(self, event: str) -> None:
        self.audit.append(f"{time.strftime('%H:%M:%S')} {event}")
        if len(self.audit) > 500:
            del self.audit[:250]

    def audit_snapshot(self) -> list:
        """Recent redacted audit events, newest first (no secrets)."""
        with self._lock:
            return list(reversed(self.audit))

    def audit_log(self, event: str) -> None:
        """Public audit emitter for service-level events (e.g. login
        failures). Same ring, same redaction rules: no secret content."""
        self._audit(event)

    # ---------- named-entry lookup ----------
    def lookup(self, name: str) -> Optional[str]:
        with self._lock:
            return self.named.get(name)

    def named_clients(self) -> Dict[str, str]:
        """Client token -> entry name (for the service inbound auth)."""
        with self._lock:
            return {v: k for k, v in self.named.items()
                    if k.startswith("client:")}

    # ---------- vault ----------
    def load_vault(self, path: str, master_key: Optional[str] = None,
                   enforce_perms: bool = True,
                   salt: Optional[bytes] = None) -> Dict:
        """Loads the vault: one secret per line; 're:...' = regex pattern;
        'name=value' with a NAMED_RE name = named entry.
        If the file is Fernet-encrypted it decrypts it (needs master_key);
a plain file loads as-is even when master_key is set.
        """
        st = os.stat(path)
        if enforce_perms and (st.st_mode & 0o077):
            raise VaultNotLoaded(
                f"unsafe vault perms: {oct(st.st_mode & 0o777)} (0600 required)")
        with open(path, "rb") as f:
            raw = f.read()
        # decrypt ONLY if the file really is a Fernet token (v1.1.1):
        # a plain vault + master_key must load (mode B dev/test) without
        # raising InvalidToken.
        if raw.startswith(FERNET_MAGIC):
            if not master_key:
                raise VaultNotLoaded(
                    "encrypted vault but no key (master_key)")
            from cryptography.fernet import Fernet
            raw = Fernet(master_key.encode()).decrypt(raw)
        lines = [ln for ln in raw.decode("utf-8").splitlines()]
        secrets, patterns, named = [], [], {}
        for ln in lines:
            ln = ln.strip()
            if not ln or ln.startswith("#"):
                continue
            if ln.startswith("re:"):
                patterns.append(ln[3:])
                continue
            if ln.startswith("ing:") and "=" in ln:
                # v1.4.1 migration: legacy ingest lines stored the raw
                # value after the "ing:" prefix; keep it as a plain secret
                # (the prefix collided with the name=value parser).
                secrets.append(ln[4:])
                continue
            if "=" in ln:
                cand, val = ln.split("=", 1)
                if NAMED_RE.match(cand.strip()):
                    named[cand.strip()] = val
                    continue
            secrets.append(ln)
        # v1.5.2g: persistable HMAC tag salt (sidecar <vault>.tagsalt) so
        # tags survive a service restart: read when salt was not supplied,
        # rewritten after every successful load (new or preserved salt).
        tag_salt = salt
        if tag_salt is None:
            try:
                with open(path + ".tagsalt", "rb") as f:
                    raw_ts = f.read().strip()
                hex_ts = raw_ts.decode("ascii", "ignore")
                if len(hex_ts) >= 32 and len(hex_ts) % 2 == 0 and all(
                        c in "0123456789abcdefABCDEF" for c in hex_ts):
                    tag_salt = bytes.fromhex(hex_ts)
            except OSError:
                pass
        rep = self.load_from_lists(secrets, patterns, named, salt=tag_salt)
        try:
            fd = os.open(path + ".tagsalt",
                         os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
            try:
                os.write(fd, self.salt.hex().encode("ascii"))
            finally:
                os.close(fd)
        except OSError:
            pass
        # v1.5.7: notify the service layer after every (re)load so derived
        # RAM indexes are rebuilt (value2prefix from the import registry).
        # The hook decides what master_key allows; a None key wipes.
        _cb = self._on_reload_cb
        if _cb:
            try:
                _cb(master_key)
            except Exception as e:
                self._audit(f"reload_cb_error={e}")
        return rep

    def load_from_lists(self, secrets: List[str],
                        patterns: Optional[List[str]] = None,
                        named: Optional[Dict[str, str]] = None,
                        salt: Optional[bytes] = None) -> Dict:
        with self._lock:
            # v1.2.0: preservable salt (dashboard CRUD) so that tags already
            # issued in the session are NOT invalidated; default = new salt
            # (rotation as in v1.1.x)
            self.salt = salt if salt is not None else os.urandom(16)
            self.secrets = list(dict.fromkeys(secrets))
            self.named = dict(named or {})
            self._values = list(dict.fromkeys(
                self.secrets + list(self.named.values())))
            self._rebuild_ac()
            self.patterns = [re.compile(p) for p in (patterns or [])]
            self.tag2secret = {}
            self._fams_cache = None
            self._session_fams: set = set()  # v1.5.9 unresolved-reporting memory
            report = {"secrets": len(self.secrets), "named": len(self.named),
                      "patterns": len(self.patterns), "extended": []}
            # first pass 8 hex, collisions -> 12 hex, still colliding -> fail
            self.tag_core2secret = {}
            # v1.5.7: value -> tag-family RAM index for values ingested
            # from CSVs with explicit per-column prefixes, so the tags
            # minted at chat time match the import-time family
            # (e.g. R07_RAGIONE_SO_xxxx instead of PWD_xxxx).
            self.value2prefix: Dict[str, str] = {}
            # v1.5.7: service hook fired after every vault (re)load so the
            # service layer can rebuild derived RAM indexes (value2prefix
            # from the encrypted import registry).
            self._on_reload_cb = getattr(self, "_on_reload_cb", None)  # v1.5.7: preserved
            tags4: Dict[str, List[str]] = {}
            for s in self._values:
                tags4.setdefault(TAG_PREFIX + self._tag_core(s, 4), []).append(s)
            colliding = [s for t, ss in tags4.items() if len(ss) > 1 for s in ss]
            for s in self._values:
                n = 6 if s in colliding else 4
                t = TAG_PREFIX + self._tag_core(s, n)
                if t in self.tag2secret and self.tag2secret[t] != s:
                    raise VaultCollisionError(
                        f"persistent collision on {t} (fail-safe: refused)")
                self.tag2secret[t] = s
                self._touch_fams(t)
                if n == 6:
                    report["extended"].append(TAG_PREFIX + t[4:10] + "...")
            self.loaded = True
            self._audit(f"vault load: {report['secrets']} secrets, "
                        f"{report['named']} named, "
                        f"{report['patterns']} patterns, "
                        f"{len(report['extended'])} extended tags")
            # v1.5.7: let the service layer rebuild derived state
            # (value2prefix from the encrypted import registry).
            if self._on_reload_cb is not None:
                try:
                    self._on_reload_cb(master_key)
                except Exception:
                    pass
            return report

    def lock(self) -> None:
        """Full state wipe (unlock = reload from disk)."""
        with self._lock:
            self.salt = os.urandom(16)
            self.secrets, self.patterns = [], []
            self.named, self._values = {}, []
            self.tag2secret = {}
            self._fams_cache = None
            self.tag_core2secret = {}
            self.value2prefix = {}
            self._ac = None
            self.loaded = False
            # v1.5.9: _session_fams is NOT cleared here — it feeds unresolved-
            # tag reporting only (no restore: tag2secret is empty).
            # v1.5.9: minted whole-cell tags belong to the wiped session too;
            # keeping them made load_vault resurrect tags from PREVIOUS vaults
            # (cross-vault leak: cells from vault A got tagged in vault B).
            self._minted_extra = {}
            self._audit("lock: state wiped")

    def is_loaded(self) -> bool:
        return self.loaded

    # ---------- secret index (perf v1.4.2) ----------
    def _rebuild_ac(self):
        """Builds the Aho-Corasick automaton over _values. One scan replaces
        the per-secret substring loops; semantics identical to the old
        longest-first sequential replace (non-overlapping, leftmost,
        longest-wins). If pyahocorasick is unavailable the index stays None
        and sanitize() falls back to the sequential path (same results)."""
        self._ac = None
        try:
            import ahocorasick
        except ImportError:
            return
        try:
            A = ahocorasick.Automaton()
            for s in self._values:
                if s:
                    A.add_word(s, s)
            if len(A):                    # non-empty only
                A.make_automaton()
                self._ac = A
        except Exception:
            self._ac = None               # fail-open to sequential path

    # ---------- sanitize (out) ----------
    def _sanitize_plain(self, seg: str, prefix: str) -> Tuple[str, int]:
        """v1.5.11 helper: sanitize a fragment that contains NO foreign
        tag spans. Values are replaced in a SINGLE left-to-right pass
        (AC matches, longest-first overlap resolution): a replacement is
        never rescanned, so a minted tag can never be shredded by a later
        shorter value (the field bug: value "0"/"NAZIONE" inside families
        like R07_CD_NAZIONE_*). Patterns then run only on the gaps
        between already-minted tags, so a pattern can never match inside a
        freshly minted tag (hex cores look like many regex payloads)."""
        count = 0
        # ---- values: single-pass, overlap-resolved replacement ----
        matches = []
        if self._ac is not None:
            # pyahocorasick yields end as the index of the LAST match
            # character (INCLUSIVE): exclusive end = end + 1.
            for end, sv in self._ac.iter(seg):
                if sv:
                    matches.append((end - len(sv) + 1, end + 1, sv))
        else:
            for sv in self._values:
                if not sv:
                    continue
                i = seg.find(sv)
                while i >= 0:
                    matches.append((i, i + len(sv), sv))
                    i = seg.find(sv, i + 1)
        matches.sort(key=lambda m: (m[0], -(m[1] - m[0])))
        picked = []
        last_end = -1
        for st, en, sv in matches:
            if st >= last_end and sv:
                picked.append((st, en, sv))
                last_end = en
        parts = []
        pos = 0
        for st, en, sv in picked:
            parts.append(seg[pos:st])
            if sv in self._minted_extra:
                mt = self._minted_extra[sv]
                self.tag2secret.setdefault(mt, sv)
                self.tag_core2secret.setdefault(
                    mt[len(self.value2prefix.get(sv) or TAG_PREFIX):], sv)
                self._touch_fams(mt)
                tag = mt
            else:
                tag = self.tag_for(sv, prefix)
            parts.append(tag)
            pos = en
            count += 1
        parts.append(seg[pos:])
        out = "".join(parts)
        # ---- patterns: minted tags shielded via fams+hex segmentation ----
        with self._lock:
            fams = set(self._get_fams()) | set(self._session_fams)
        fams.add(TAG_PREFIX)
        if self.patterns and len(fams) > 1:
            mrx = re.compile(
                "(?:" + "|".join(re.escape(f) for f in sorted(fams))
                + r")[0-9a-f]{8,24}")
            gaps = []
            gpos = 0
            for gm in mrx.finditer(out):
                if gm.start() > gpos:
                    gaps.append((gpos, gm.start()))
                gpos = gm.end()
            gaps.append((gpos, len(out)))
            rebuilt = []
            prev = 0
            for a, b in gaps:
                rebuilt.append(out[prev:a])
                seg = out[a:b]
                for pat in self.patterns:
                    def _cb(m, _seg=seg):
                        nonlocal count
                        v = m.group(0)
                        t = self._mint(self.value2prefix.get(v) or prefix, v)
                        self.tag2secret.setdefault(t, v)
                        self.tag_core2secret.setdefault(
                            t[len(self.value2prefix.get(v) or prefix):], v)
                        self._touch_fams(t)
                        count += 1
                        return t
                    seg = pat.sub(_cb, seg)
                rebuilt.append(seg)
                prev = b
            rebuilt.append(out[prev:])
            out = "".join(rebuilt)
        else:
            for pat in self.patterns:
                def _cb(m):
                    nonlocal count
                    v = m.group(0)
                    t = self._mint(self.value2prefix.get(v) or prefix, v)
                    self.tag2secret.setdefault(t, v)
                    self.tag_core2secret.setdefault(
                        t[len(self.value2prefix.get(v) or prefix):], v)
                    self._touch_fams(t)
                    count += 1
                    return t
                out = pat.sub(_cb, out)
        return out, count

    def sanitize(self, text: str, prefix: str = "PWD_") -> Tuple[str, int]:
        """v1.5.11: segmented sanitization (field fix, .222).

        Long chat histories echo back tag-shaped tokens minted by previous
        rounds / previous vault states. Their internals (family text like
        R07_CD_NAZIONE_ or hex cores) collide with current vault values;
        the old sequential replace shredded those tokens (e.g. value "0"
        inside every R07_* family) and re-introduced values through minted
        families, leaving tag-soup that trips the no-leak scan ->
        fail-closed RuntimeError -> 500 on exactly the long-history
        requests. Now:
          1. tag-shaped spans are located first and classified: tags of
             this store are kept verbatim (shielded atoms), foreign/old
             tags are queued for whole-token re-tagging, and a token that
             is itself a vault VALUE stays in the plain flow (value
             replacement, as before);
          2. only the gaps between spans are value-sanitized, each gap in
             a single collision-free pass;
          3. foreign spans are then replaced WHOLE with a deterministic,
             restore-mapped opaque tag (round-trip preserved);
          4. the no-leak scan is unchanged (fail-closed preserved).
        """
        if not self.loaded:
            raise VaultNotLoaded("vault not loaded: sanitize refused (fail-safe)")
        with self._lock:
            count = 0
            # ---- 1) locate tag-shaped spans and classify them ----
            spans: List[Tuple[int, int, str, bool]] = []  # (a, b, tok, retag)
            for m in self._OLD_TAG_RX.finditer(text):
                tok = m.group(0)
                if tok in self._values:
                    continue  # vault value shaped like a tag: value pass
                a, b = m.span()
                if spans and a < spans[-1][1]:
                    if b > spans[-1][1]:
                        spans[-1] = (spans[-1][0], b, m.group(0),
                                     m.group(0) not in self.tag2secret)
                    continue
                spans.append((a, b, tok, tok not in self.tag2secret))
            # ---- 2) build segments; sanitize gaps; re-tag spans whole ----
            out_parts: List[str] = []
            pos = 0
            for a, b, tok, retag in spans:
                if a > pos:
                    seg, c = self._sanitize_plain(text[pos:a], prefix)
                    count += c
                    out_parts.append(seg)
                if retag:
                    try:
                        t2 = self._retag_token(tok, prefix)
                        out_parts.append(t2)
                        count += 1
                    except RuntimeError:
                        raise
                    except Exception as exc:
                        # opaque-token retag must never break the request:
                        # keep the span verbatim and rely on the no-leak
                        # scan (fail-closed) to judge the result.
                        self._audit(f"retag failed ({type(exc).__name__})")
                        out_parts.append(tok)
                else:
                    # tag of THIS store: pass through untouched (restore
                    # happens on the way back via tag2secret).
                    out_parts.append(tok)
                pos = b
            if pos < len(text):
                seg, c = self._sanitize_plain(text[pos:], prefix)
                count += c
                out_parts.append(seg)
            out = "".join(out_parts)
            # ---- 3) no-leak check: no secret must survive (single AC
            # scan when available; identical threshold: only len>=4
            # secrets are fatal)
            scan = out
            with self._lock:
                fams = set(self._get_fams()) | set(self._session_fams)
            fams.add(TAG_PREFIX)
            if len(fams) > 1:
                mrx = re.compile(
                    "(?:" + "|".join(re.escape(f) for f in sorted(fams))
                    + r")[0-9a-f]{8,24}")
                scan = mrx.sub(" ", scan)
            resid = None
            if self._ac is not None:
                for _, sv in self._ac.iter(scan):
                    if len(sv) >= 4:
                        resid = sv
                        break
            else:
                for sv in self._values:
                    if len(sv) >= 4 and sv in scan:
                        resid = sv
                        break
            if resid is not None:
                # v1.5.10 diagnostic: shape of the residual WITHOUT disclosing
                # the secret (length + first 2 chars + context with the
                # occurrence itself blanked out).
                try:
                    i = scan.find(resid)
                    ctx = ""
                    if i >= 0:
                        pre = scan[max(0, i - 40):i]
                        post = scan[i + len(resid): i + len(resid) + 40]
                        ctx = pre + "<RESID:" + str(len(resid)) + ">" + post
                    self._audit("FATAL no-leak residual secret in output "
                                f"(len={len(resid)} head={resid[:2]}* "
                                f"ctx={ctx!r})")
                    raise RuntimeError(
                        "no-leak check failed after sanitize "
                        f"(len={len(resid)} head={resid[:2]}* ctx={ctx!r})")
                except RuntimeError:
                    raise
                except Exception:
                    raise RuntimeError("no-leak check failed after sanitize")
            self.replace_count += count
            return out, count

    # ---------- desanitize (in) ----------
    def _desanitize_one(self, text: str, prefix: str = "PWD_") -> Tuple[str, int, List[str]]:
        """Single-family restore (v1.5.7 internal). Returns
        (text, restorations, unresolved tags).
        prefix (v1.5.0): tag family to restore; default PWD_ keeps legacy
        behaviour (TAG_TOLERANT_RE). Tolerant matching: spaces/quotes
        around the tag. Only exact tags present in the reverse map are
        restored; the others stay verbatim
        and are audited.
        """
        out = []
        resolved, unresolved = 0, []
        pos = 0
        with self._lock:
            rx = TAG_TOLERANT_RE if prefix == "PWD_" else _tolerant_rx(prefix)
            plen = len(prefix)
            for m in rx.finditer(text):
                core = m.group(1)
                tag = prefix + core
                # span of the CORE ONLY inside the tolerant match
                core_start = m.group(0).find(prefix + core)
                s_abs = m.start() + core_start
                e_abs = s_abs + plen + len(core)
                out.append(text[pos:s_abs])
                secret = self.tag2secret.get(tag)
                if secret is None:
                    # v1.5.2: core-index fallback — custom-prefix families
                    # are not rebuilt by load_from_lists after a reload.
                    secret = self.tag_core2secret.get(core)
                if secret is not None:
                    out.append(secret)
                    resolved += 1
                else:
                    out.append(text[s_abs:e_abs])
                    unresolved.append(tag)
                    self._audit(f"unresolved tag {tag[:8]}..")
                pos = e_abs
            out.append(text[pos:])
            return "".join(out), resolved, unresolved

    # v1.5.8: family-set cache. tag2secret can hold tens of thousands of
    # tags after CSV imports; rebuilding the family set on every response
    # cost ~25 ms in production. The cache is invalidated by _touch_fams()
    # at every mutation site of tag2secret.
    _fams_cache = None

    def _touch_fams(self, tag: str | None = None):
        self._fams_cache = None
        # v1.5.9: session-family memory for unresolved-tag reporting.
        # Survives lock() (audit/reporting only: resolution stays hard-cut).
        if tag:
            i = tag.rfind("_")
            if i > 0:
                self._session_fams.add(tag[:i + 1])

    def _get_fams(self):
        with self._lock:
            if self._fams_cache is None:
                fams = set()
                for t in self.tag2secret:
                    i = t.rfind("_")
                    if i > 0:
                        fams.add(t[:i + 1])
                self._fams_cache = frozenset(fams)
            return self._fams_cache

    # v1.5.8: single generic pattern covering any tag family
    # (family = uppercase chunks with trailing _, core = hex).
    _MULTI_TAG_RX = re.compile(
        r"[\"'\s]*([A-Z][A-Z0-9]*(?:_[A-Z0-9]+)*_)([0-9a-f]{8,12})[\"'\s]*")

    # v1.5.11: tag-shaped token as it may appear in a client history
    # (tags minted by previous rounds under a previous vault state).
    # Matches family (uppercase chunks) + 8..12 hex, WITHOUT the quotes/
    # spaces guards used by the restore path: here we want raw spans.
    # v1.5.11: the family part must NOT require a trailing underscore:
    # glued tokens like R07_ST_MOD597531b7 (family + core without "_")
    # were invisible to the span protection and got shredded by the
    # value pass. Greedy family with backtracking; false positives are
    # safe (they are retagged and restored verbatim on the way back).
    # v1.5.11 FINAL: word-anchored whole-token spans:
    #   - (?<![0-9A-Za-z]) / (?![0-9a-f]) isolate the token: a hex run
    #     inside a longer word (e.g. ...80 lines) can never match;
    #   - the span is retagged WHOLE, so no partial-match residue is left
    #     next to the minted tag to be re-shredded by the value pass;
    #   - false positives on real words are SAFE: retag + verbatim restore.
    _OLD_TAG_RX = re.compile(
        r"([A-Z][A-Z0-9]*(?:_[A-Z0-9]+)*_?)([0-9a-f]{8,12})(?![0-9a-f])")

    def _desanitize_multi(self, text: str) -> Tuple[str, int, List[str]]:
        """Single-scan restore across ALL families. Tag-shaped tokens are
        looked up directly in tag2secret (then core-index fallback); only
        tokens whose family is actually minted in the store count as
        unresolved, so ordinary words like ABC_12345678 in LLM output are
        left untouched and unaudited."""
        out = []
        resolved, unresolved = 0, []
        pos = 0
        fams = self._get_fams()
        with self._lock:
            for m in self._MULTI_TAG_RX.finditer(text):
                fam, core = m.group(1), m.group(2)
                tag = fam + core
                secret = self.tag2secret.get(tag)
                if secret is None:
                    secret = self.tag_core2secret.get(core)
                if secret is None:
                    # v1.5.9: families seen this session (incl. before a
                    # lock) still get reported as unresolved — hard-cut
                    # keeps resolution impossible, but the attempt is
                    # visible in the response and in the audit ring.
                    if fam in fams or fam in self._session_fams:
                        unresolved.append(tag)
                    continue
                s_abs, e_abs = m.start(1), m.end(2)
                out.append(text[pos:s_abs])
                out.append(secret)
                pos = e_abs
                resolved += 1
        out.append(text[pos:])
        # v1.5.9: audit unresolved-tag attempts (redacted: count only)
        if unresolved:
            self._audit(f"desanitize: unresolved={len(unresolved)}")
        return "".join(out), resolved, unresolved

    def desanitize(self, text: str, prefix: str = "PWD_",
                   families=None) -> Tuple[str, int, List[str]]:
        """Multi-family restore (v1.5.7): tries each tag family in turn.
        families=None -> auto: the requested prefix plus every family
        minted this session (parsed from the reverse map), so custom
        prefix tags from CSV imports restore without the caller having
        to know the family. Returns (text, restorations, unresolved)."""
        # v1.5.8: auto mode -> single generic scan across all families
        # (per-family finditer loops made responses O(F) with F families;
        # CSV imports mint one family per record, F in the hundreds).
        if families is None:
            return self._desanitize_multi(text)
        fams: List[str] = []
        for f in list(families) + [prefix]:
            if isinstance(f, str) and _PREFIX_RE.fullmatch(f) and f not in fams:
                fams.append(f)
        out, total, un = text, 0, []
        for f in fams:
            out, n, u = self._desanitize_one(out, prefix=f)
            total += n
            for t in u:
                if t not in un:
                    un.append(t)
        if un:
            self._audit(f"desanitize: unresolved={len(un)}")
        return out, total, un

    # ---------- batch CSV (v1.4.0-dev) ----------
    # Whole-cell tagging mode ("listone"): every non-empty cell >=
    # SENSITIVE_CELL_MIN chars gets an opaque tag; shorter cells (codes,
    # provinces, ZIP) stay in clear unless they match a known secret or
    # a pattern. Exact-secret sanitization ALWAYS applies first.
    SENSITIVE_CELL_MIN = 4
    # v1.4.0 typed mode: columns whose normalized header is in this set
    # NEVER get whole-cell tags (ids/codes/notes are workflow data, not PII).
    # Whole-cell typing is opt-in via typed=true; exact secrets/patterns
    # apply to these columns anyway.
    NONSENSITIVE_HEADERS = frozenset({
        "id", "ids", "code", "codice", "tipo", "type", "stato", "state",
        "nota", "note", "comment", "comments", "desc", "description",
        "token", "ref", "rif"})

    def _sanitize_cell(self, cell, on_missing: str = "keep",
                       typed: str = "", typed_mode: bool = False,
                       prefix: str = "PWD_", force_sensitive: bool = False,
                       col_override: str = ""):
        """Single-cell pipeline. Returns (out, n_exact, n_tagged).
        on_missing='keep': cell with no known secret stays verbatim.
        on_missing='tag' : cell with no match and >= SENSITIVE_CELL_MIN
                           chars gets a whole-cell tag (reverse map in RAM).
        typed=<header>: typed mode. Whole-cell tags use the per-column
        namespace <HEADER>_* unless the header is in NONSENSITIVE_HEADERS
        (then the cell stays clear). Exact-secret sanitization ALWAYS runs
        first, in every mode."""
        if not isinstance(cell, str):
            cell = str(cell)
        if not cell:
            return cell, 0, 0
        out, n = self.sanitize(cell, prefix=prefix)
        if n == 0 and on_missing == "tag" and len(cell) >= self.SENSITIVE_CELL_MIN:
            if typed_mode:
                if typed and (force_sensitive or
                              typed not in self.NONSENSITIVE_HEADERS):
                    tag = self._mint(col_override or typed.upper() + "_", cell)
                    with self._lock:
                        self.tag2secret.setdefault(tag, cell)
                        self._touch_fams(tag)
                        self._minted_extra.setdefault(cell, tag)
                    return tag, 0, 1
                if typed and not force_sensitive:
                    # non-sensitive column (ID, NOTA, ...) stays CLEAR
                    return cell, 0, 0
            # untyped mode (v1.3.3 behaviour) or missing header -> opaque tag
            # (v1.5.0: prefix is configurable, default PWD_)
            tag = self._mint(prefix, cell)
            with self._lock:
                self.tag2secret.setdefault(tag, cell)
                self._touch_fams(tag)
                self._minted_extra.setdefault(cell, tag)
            return tag, 0, 1
        return out, n, 0

    def sanitize_rows(self, rows, on_missing: str = "keep",
                      header: bool = True, typed: bool = False,
                      columns=None, prefix: str = "PWD_",
                      column_prefixes: dict | None = None):
        """Batch sanitize for tabular data (list of lists, e.g. CSV rows).
        header=True: row 0 is a header -> excluded from whole-cell tagging
        (exact secrets/patterns still apply). Per-value cache: the same
        value repeated on N rows costs ONE tag derivation. typed=True:
        whole-cell tags carry a per-column namespace (<HEADER>_XXXX where
        HEADER is the sanitized lowercase column name of row 0).
        columns (v1.5.0): optional set of 0-based column indices that are
        ALLOWED to receive whole-cell tags; other columns are forced to
        keep (exact secrets/patterns still apply everywhere). An explicitly
        selected column OVERRIDES the NONSENSITIVE_HEADERS typed policy
        (user selection wins). prefix (v1.5.0): tag prefix for the
        untyped/missing-header whole-cell mint (default "PWD_").
        column_prefixes (v1.5.2): optional {col_index: prefix} override:
        per-column tag prefix for the untyped/missing-header whole-cell
        mint; wins over the global prefix for those columns.
        Returns (out_rows, replaced, tagged_cells)."""
        if on_missing not in ("keep", "tag"):
            raise ValueError("on_missing must be 'keep' or 'tag'")
        if prefix is None or not isinstance(prefix, str):
            raise ValueError("prefix must be a string")
        colprefixes = {}
        if column_prefixes:
            if not isinstance(column_prefixes, dict):
                raise ValueError("column_prefixes must be a dict")
            for k, v in column_prefixes.items():
                ki = int(k)
                if ki < 0:
                    raise ValueError("column_prefixes: negative column index")
                if not isinstance(v, str) or not _PREFIX_RE.fullmatch(v):
                    raise ValueError("column_prefixes[%d]: invalid prefix" % ki)
                colprefixes[ki] = v
        if not _PREFIX_RE.fullmatch(prefix):
            raise ValueError("invalid prefix: must match "
                             "[A-Z][A-Z0-9_]{0,15}_ (trailing underscore, "
                             "no trailing '__')")
        if columns is not None:
            cols = set(columns)
            if not cols or not all(isinstance(x, int) and x >= 0
                                   for x in cols):
                raise ValueError("columns must be non-negative ints")
        else:
            cols = None
        out_rows = []
        replaced = tagged = 0
        cache = {}
        ncol = 0
        for i, row in enumerate(rows):
            new_row = []
            for j, cell in enumerate(row):
                c = cell if isinstance(cell, str) else str(cell)
                if not c:
                    new_row.append(c)
                    continue
                if header and i == 0:
                    out, n, t = self._sanitize_cell(c, "keep")
                else:
                    hnorm = ""
                    if typed and header and ncol:
                        if j < len(rows[0]):
                            hnorm = _norm_header(rows[0][j])
                    # v1.5.0 column selection: unset on_missing for
                    # non-selected columns; force tagging for explicitly
                    # selected ones (overrides NONSENSITIVE_HEADERS).
                    if cols is not None:
                        sel = j in cols
                        eff_missing = on_missing if sel else "keep"
                        force = bool(sel and on_missing == "tag")
                    else:
                        eff_missing, force = on_missing, False
                    # v1.5.2: per-column prefix override (untyped mint)
                    eff_prefix = colprefixes.get(j, prefix)
                    if typed:
                        key = (hnorm, c, eff_missing == "tag", force,
                               eff_prefix)
                    else:
                        key = (c, eff_missing == "tag", force, eff_prefix)
                    hit = cache.get(key)
                    if hit is None:
                        out, n, t = self._sanitize_cell(c, eff_missing,
                                                        hnorm, typed,
                                                        eff_prefix, force,
                                                        col_override=
                                                        colprefixes.get(j))
                        cache[key] = (out, n, t)
                    else:
                        out, n, t = hit
                replaced += n
                tagged += t
                new_row.append(out)
            if header and i == 0:
                ncol = len(row)
            out_rows.append(new_row)
        self._audit(f"csv sanitize typed={typed}: {len(rows)} rows, "
                    f"{replaced} replaced, {tagged} cells tagged")
        return out_rows, replaced, tagged

    def restore_rows(self, rows, prefix: str = "PWD_", families=None):
        """Batch restore (in): PWD_*/<TYPE>_* tags -> original cells.
        prefix (v1.5.0): selects the whole-cell fast-path regex family
        (custom prefixes from sanitize). Unknown tags stay verbatim and
        are reported (dedup) — never invented. Returns
        (out_rows, restored, unresolved_tags_dedup)."""
        if not isinstance(prefix, str) or not _PREFIX_RE.fullmatch(prefix):
            raise ValueError("invalid prefix")
        # v1.5.7: families to try (custom prefixes from sanitize_rows);
        # the first family whose whole-tag regex matches the cell wins.
        fams = [prefix]
        if families:
            for f in families:
                if (isinstance(f, str) and _PREFIX_RE.fullmatch(f)
                        and f not in fams):
                    fams.append(f)
        out_rows = []
        restored = 0
        unresolved = []
        cache = {}
        for row in rows:
            new_row = []
            for cell in row:
                c = cell if isinstance(cell, str) else str(cell)
                if not c:
                    new_row.append(c)
                    continue
                # fast path: whole cell is exactly one tag
                m, fam_len = None, len(prefix)
                for fam in fams:
                    m = _whole_tag_rx(fam[:-1] if fam.endswith("_")
                                      else fam).fullmatch(c)
                    if m is not None:
                        fam_len = len(fam)
                        break
                if m is not None:
                    hit = cache.get(c)
                    if hit is None:
                        secret = self.tag2secret.get(c)
                        if secret is None:
                            # v1.5.2: core-index fallback for custom-prefix
                            # families (not rebuilt by load_from_lists).
                            secret = self.tag_core2secret.get(c[fam_len:])
                        if secret is not None:
                            hit = (secret, 1, [])
                        else:
                            hit = (c, 0, [c])
                            self._audit(f"unresolved tag {c[:8]}..")
                        cache[c] = hit
                    out, n, u = hit
                elif _TAG_LIKE_RE.fullmatch(c) is not None:
                    # tag-like but unknown core: stays verbatim, reported
                    # as unresolved (dedup) - never invented
                    hit = cache.get(c)
                    if hit is None:
                        hit = (c, 0, [c])
                        self._audit(f"unresolved tag {c[:8]}..")
                        cache[c] = hit
                    out, n, u = hit
                else:
                    # partial match inside a longer text -> standard scan
                    hit = cache.get(c)
                    if hit is None:
                        out, n, u = self.desanitize(c, families=fams)
                        cache[c] = (out, n, u)
                    else:
                        out, n, u = hit
                restored += n
                for t in u:
                    if t not in unresolved:
                        unresolved.append(t)
                new_row.append(out)
            out_rows.append(new_row)
        self._audit(f"csv restore: {len(rows)} rows, {restored} restored, "
                    f"{len(unresolved)} unresolved")
        return out_rows, restored, unresolved

    # ---------- streaming SSE ----------
    def make_stream_desanitizer(self):
        return StreamDesanitizer(self)


_CORE_MIN_HEX = 8           # minimum valid tag core (hex)
_TAG_CORE_MAX = 12          # maximum valid tag core (hex)


class StreamDesanitizer:
    """Desanitize over a stream of chunks (SSE): a tag can split across chunks.

    feed(chunk) -> emitted text; flush() -> the rest. The buffer holds back
    only text that can be the start of a tag (prefix "PWD_" or a still
    potentially incomplete hex core); v1.1.2 handles real SSE where tokens
    travel wrapped inside long JSON lines.
    """

    def __init__(self, sanitizer: Sanitizer, prefix: str = "PWD_",
                 families=None):
        # v1.5.0: prefix parameterized so SSE streaming also works with
        # custom tag families minted by sanitize_rows(prefix=...).
        # v1.5.7: families=None -> auto multi-family (every family minted
        # this session + prefix), so ingest-sourced tags restore in SSE.
        if not isinstance(prefix, str) or not _PREFIX_RE.fullmatch(prefix):
            raise ValueError("invalid prefix")
        fams = [prefix]
        if families is None:
            famrx = re.compile(
                r"^([A-Z][A-Z0-9]*(?:_[A-Z0-9]+)*)_([0-9a-f]{4,12})$")
            try:
                with sanitizer._lock:
                    keys = list(sanitizer.tag2secret)
            except Exception:
                keys = []
            for t in keys:
                m = famrx.match(t)
                if m and m.group(1) + "_" not in fams:
                    # v1.5.7: keep the trailing underscore (families are
                    # PWD_-style prefixes, _PREFIX_RE requires it).
                    fams.append(m.group(1) + "_")
        elif families:
            for f in families:
                if (isinstance(f, str) and _PREFIX_RE.fullmatch(f)
                        and f not in fams):
                    fams.append(f)
        self.san = sanitizer
        self.prefix = prefix
        self.fams = fams
        self.buf = ""
        self.keep = (max(len(f) for f in fams) + _TAG_CORE_MAX + 2
                     ) if fams else len(prefix) + _TAG_CORE_MAX + 2
        self.linebuf = ""                  # incomplete SSE line
        self.restored_count = 0            # restored tags (feed+flush)
        self.last_shape = None             # last content shape seen: "openai"|"ollama"|"generic"

    def feed(self, chunk: str) -> str:
        """Emits only text that cannot contain the start of a tag.

        v1.1.2: the old approach (fixed tail window TAG_MAX_TOTAL+2) fails
        with real SSE (e.g. Ollama/OpenAI-compat): tokens arrive wrapped in
        long JSON lines, so the first half of a split tag can sit FAR before
        the end of the buffer and gets emitted before the second half
        arrives -> never reassembled. New rule: cut before the start of
        every potential tag:
          1) a buffer suffix that is a proper prefix of TAG_PREFIX
          2) the last "PWD_" whose hex core is potentially incomplete
             (<8 hex, or 8-11 hex with the buffer ending on the core).
        A complete tag with core>=8 followed by a non-hex char is final:
        desanitize resolves it (see _HEX/_CORE_MAX below).
        """
        self.buf += chunk
        buf = self.buf
        if not buf:
            return ""
        cut = len(buf)
        # 1) tail that might be a proper prefix of a tag family
        for fam in self.fams:
            for k in range(min(len(fam) - 1, len(buf)), 0, -1):
                if fam.startswith(buf[-k:]):
                    cut = min(cut, len(buf) - k)
                    break
        # 2) last tag prefix in the buffer: complete core, or wait?
        for fam in self.fams:
            idx = buf.rfind(fam)
            if idx < 0:
                continue
            core_ = buf[idx + len(fam):]
            hexc = 0
            while hexc < len(core_) and core_[hexc] in "0123456789abcdef":
                hexc += 1
            if hexc < _CORE_MIN_HEX:
                cut = min(cut, idx)          # core too short: wait
            elif hexc < _TAG_CORE_MAX and hexc == len(core_):
                cut = min(cut, idx)          # 8..11 core and buffer ended: could grow
            # else: definitive core (>=MAX, or >=8 with non-hex after) -> emit
        safe, self.buf = buf[:cut], buf[cut:]
        if not safe:
            return ""
        resolved, rst, _ = self.san.desanitize(safe, families=self.fams)
        self.restored_count += rst
        return resolved

    def flush(self) -> str:
        resolved, rst, _ = self.san.desanitize(self.buf, families=self.fams)
        self.buf = ""
        self.restored_count += rst
        return resolved


# --------------------------------------------------------------------------
# SSE-aware desanitization (v1.1.2)
#
# With real LLM providers (Ollama, OpenAI-compat) each SSE token is wrapped
# in a long JSON line: a tag split across two tokens is NOT adjacent in the
# raw stream and no text-level buffering can reassemble it. The correct
# solution is desanitizing at the CONTENT FIELD level: we extract the model
# text from each event (known shapes: OpenAI-compat choices[].delta.content,
# native Ollama message.content, top-level generic content), desanitize it
# and re-wrap it into the JSON before forwarding to the client. Non-JSON
# lines or lines without a content field pass through untouched.
# --------------------------------------------------------------------------

def _sse_content_extract(obj):
    """Returns (container, "content", shape) when obj holds a content field
    in one of the known shapes, else None."""
    if not isinstance(obj, dict):
        return None
    ch = obj.get("choices")
    if isinstance(ch, list) and ch and isinstance(ch[0], dict):
        for hk in ("delta", "message"):          # OpenAI-compat streaming
            h = ch[0].get(hk)
            if isinstance(h, dict) and isinstance(h.get("content"), str):
                return (h, "content", "openai")
    msg = obj.get("message")
    if isinstance(msg, dict) and isinstance(msg.get("content"), str):
        return (msg, "content", "ollama")
    if isinstance(obj.get("content"), str):
        return (obj, "content", "generic")
    return None


def _sse_process_line(sd, line):
    """Desanitizes the content field of an SSE JSON line; passthrough otherwise."""
    if not line.startswith("data:"):
        return line
    payload = line[5:].strip()
    if not payload or payload == "[DONE]":
        return line
    try:
        obj = json.loads(payload)
    except ValueError:
        return line
    hit = _sse_content_extract(obj)
    if hit is None:
        return line
    container, key, shape = hit
    sd.last_shape = shape
    container[key] = sd.feed(container[key])
    try:
        return "data: " + json.dumps(obj, ensure_ascii=False, separators=(",", ":"))
    except (TypeError, ValueError):
        return line


def sse_feed_chunk(sd, chunk: str) -> str:
    """SSE-aware path: processes an HTTP chunk line by line.

    The content field of each JSON event is desanitized: the model text
    becomes adjacent (no JSON wrapper), so tags split across tokens get
    reassembled in the buffer. Returns the string to forward.
    """
    sd.linebuf += chunk
    out = []
    while "\n" in sd.linebuf:
        line, sd.linebuf = sd.linebuf.split("\n", 1)
        out.append(_sse_process_line(sd, line))
        out.append("\n")
    return "".join(out)


def sse_flush(sd) -> str:
    """Closes the SSE-aware stream: processes the residual incomplete line
    and emits the desanitizer remainder as a final synthetic event in the
    same shape as the last content field seen."""
    parts = []
    if sd.linebuf:
        parts.append(_sse_process_line(sd, sd.linebuf) + "\n")
        sd.linebuf = ""
    rest = sd.flush()
    if rest:
        payload = json.dumps(rest, ensure_ascii=False)
        if sd.last_shape == "ollama":
            evt = '{"message":{"content":%s}}' % payload
        elif sd.last_shape == "openai":
            evt = '{"choices":[{"delta":{"content":%s}}]}' % payload
        else:
            evt = '{"content":%s}' % payload
        parts.append("data: " + evt + "\n\n")
    return "".join(parts)
