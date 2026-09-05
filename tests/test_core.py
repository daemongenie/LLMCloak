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

"""Mandatory test suite — spec v1 section 7.
Run (relocatable):
  python3 -m pytest tests/ -v
The tests locate the package from their own location; alternatively point to
an external layout with:
  LLMCLOAK_HOME=/dir/of/the/code python3 -m pytest ...
"""
import json
import os
import stat
import sys
import time
from pathlib import Path

import pytest

# Home del pacchetto: LLMCLOAK_HOME se impostata, altrimenti
# derivata dalla posizione del file test (parent del pacchetto).
_PKG_HOME = Path(os.environ.get(
    "LLMCLOAK_HOME",
    Path(__file__).resolve().parents[1],
))
sys.path.insert(0, str(_PKG_HOME))
from core import (Sanitizer, StreamDesanitizer, VaultNotLoaded,
                                VaultCollisionError, TAG_PREFIX)

SECRETS = ["Ex4mpl3-P@ss!42", "F4ke-P4ss-9876", "s3cr3t-API-KEY-xyz", "Tr0ub4dor&3",
           "7f4a8f9c2b1d4e6f8a0b3c5d7e9f1a2b", "p@ssw0rd!àèìòù"]


@pytest.fixture
def san():
    s = Sanitizer(salt=b"\x00" * 16)
    s.load_from_lists(SECRETS)
    return s


# ---------- 7.1 round-trip ----------
def test_roundtrip_plain(san):
    t = "usa Ex4mpl3-P@ss!42 per vboxuser"
    out, n = san.sanitize(t)
    assert "Ex4mpl3-P@ss!42" not in out and n == 1
    back, r, un = san.desanitize(out)
    assert back == t and r == 1 and un == []


def test_roundtrip_nested_json(san):
    obj = {"db": {"user": "root", "pwd": "Ex4mpl3-P@ss!42",
                  "opts": ["Tr0ub4dor&3", {"nested": "s3cr3t-API-KEY-xyz"}]}}
    t = json.dumps(obj, ensure_ascii=False)
    out, n = san.sanitize(t)
    assert n == 3 and "Ex4mpl3-P@ss!42" not in out
    back, r, _ = san.desanitize(out)
    assert json.loads(back) == obj


def test_roundtrip_code_and_markdown(san):
    t = "# README\n```bash\nsshpass -p 'Ex4mpl3-P@ss!42' ssh deploy@203.0.113.7\ncurl -H 'Authorization: Bearer s3cr3t-API-KEY-xyz' ...\n```\n**密码:** p@ssw0rd!àèìòù — sécret français, 普通话, русский\n"
    out, n = san.sanitize(t)
    for s in SECRETS:
        assert s not in out
    back, r, un = san.desanitize(out)
    assert back == t and un == []


def test_roundtrip_unicode(san):
    t = "key: 7f4a8f9c2b1d4e6f8a0b3c5d7e9f1a2b — emoji 🔑 — àèéìòù"
    out, _ = san.sanitize(t)
    back, _, un = san.desanitize(out)
    assert back == t and un == []


def test_deterministic_same_session(san):
    a, _ = san.sanitize("x Ex4mpl3-P@ss!42 y")
    b, _ = san.sanitize("z Ex4mpl3-P@ss!42 w")
    ta = a.split()[1]; tb = b.split()[1]
    assert ta == tb and ta.startswith(TAG_PREFIX) and len(ta) == 12  # PWD_+8


def test_same_secret_twice_count(san):
    out, n = san.sanitize("Ex4mpl3-P@ss!42 and again Ex4mpl3-P@ss!42")
    assert n == 2 and "Ex4mpl3-P@ss!42" not in out


def test_longest_first_no_partial(san):
    s = Sanitizer(salt=b"\x01" * 16)
    s.load_from_lists(["abc", "abcxyz"])
    out, n = s.sanitize("abcxyz e abc")
    assert n == 2
    back, r, _ = s.desanitize(out)
    assert back == "abcxyz e abc"


# ---------- 7.2 streaming SSE with tags split across chunks ----------
def test_stream_split_every_position(san):
    text = "la pwd e' Ex4mpl3-P@ss!42 e la key e' s3cr3t-API-KEY-xyz fine"
    tagged, _ = san.sanitize(text)
    for cut in range(1, len(tagged)):
        st = StreamDesanitizer(san)
        out = st.feed(tagged[:cut]) + st.feed(tagged[cut:]) + st.flush()
        assert out == text, f"split @{cut} failed"


def test_stream_many_chunks(san):
    text = json.dumps({"messages": [{"role": "u", "content": "pwd Ex4mpl3-P@ss!42"}] * 5})
    tagged, _ = san.sanitize(text)
    st = StreamDesanitizer(san)
    out = ""
    for i in range(0, len(tagged), 3):
        out += st.feed(tagged[i:i + 3])
    out += st.flush()
    assert out == text


# ---------- 7.3 no-leak ----------
def test_noleak_upstream_payload(san, tmp_path):
    for s in SECRETS:
        assert s not in san.tag2secret  # sanity
    t = "\n".join(SECRETS) + "\nextra Ex4mpl3-P@ss!42 in the text"
    out, _ = san.sanitize(t)
    for s in SECRETS:
        assert s not in out


def test_noleak_audit_and_errors(san):
    t = "Ex4mpl3-P@ss!42"
    san.sanitize(t)
    blob = "\n".join(san.audit)
    for s in SECRETS:
        assert s not in blob


def test_unresolved_tag_stays_and_audited(san):
    out, r, un = san.desanitize("inventato PWD_00000000 e PWD_deadbeef")
    assert r == 0 and out == "inventato PWD_00000000 e PWD_deadbeef"
    assert sorted(un) == ["PWD_00000000", "PWD_deadbeef"]
    assert any("unresolved" in ev for ev in san.audit)


def test_fail_safe_not_loaded():
    s = Sanitizer()
    with pytest.raises(VaultNotLoaded):
        s.sanitize("Ex4mpl3-P@ss!42")


# ---------- 7.4 anti-collisione ----------
def test_anticollision_100_synthetic(san):
    secrets = [f"S3cret_{i:03d}!x{i}" for i in range(150)] + SECRETS
    s = Sanitizer(salt=b"\x02" * 16)
    rep = s.load_from_lists(secrets)
    tags = {s.tag_for(x) for x in secrets}
    assert len(tags) == len(secrets)  # all distinct
    assert len(rep["extended"]) >= 0


def test_collision_extension_resolves():
    class HalfFixed(Sanitizer):
        def _tag_core(self, secret, nbytes=4):
            import hashlib, hmac as h
            d = h.new(b"\x03" * 16, secret.encode(), hashlib.sha256).digest()
            # first 4 bytes constant for the sample secrets, rest varies
            if secret.startswith("Ex4mpl3") and nbytes == 4:
                return (b"\xaa" * 4).hex()
            return d[:nbytes].hex()
    s = HalfFixed(salt=b"\x03" * 16)
    rep = s.load_from_lists(["Ex4mpl3-P@ss!42", "Ex4mpl3-P@ss!43", "altro1", "altro2"])
    assert len(rep["extended"]) == 2
    assert s.tag_for("Ex4mpl3-P@ss!42") != s.tag_for("Ex4mpl3-P@ss!43")


def test_persistent_collision_fails():
    class Fixed(Sanitizer):
        def _tag_core(self, secret, nbytes=4):
            return ("aa" * nbytes)  # always the same -> persistent collision
    s = Fixed(salt=b"\x04" * 16)
    with pytest.raises(VaultCollisionError):
        s.load_from_lists(["uno", "due"])


# ---------- 7.5 latenza ----------
def test_latency_typical_body(san):
    body = json.dumps({"model": "gpt-x", "messages": [
        {"role": "user", "content": "config con pwd Ex4mpl3-P@ss!42 e key "
         "s3cr3t-API-KEY-xyz, " + "lorem ipsum dolor " * 30}] * 4})
    assert len(body) < 4000  # body tipico
    t0 = time.perf_counter()
    out, _ = san.sanitize(body)
    mid = time.perf_counter()
    san.desanitize(out)
    dt_out = (mid - t0) * 1000
    dt_in = (time.perf_counter() - mid) * 1000
    assert dt_out < 10 and dt_in < 10, f"latenza eccessiva out={dt_out:.2f}ms in={dt_in:.2f}ms"


# ---------- vault su file ----------
def test_vault_file_perms_and_reload(tmp_path):
    v = tmp_path / "vault.txt"
    v.write_text("# commento\nEx4mpl3-P@ss!42\nre:sk-[a-zA-Z0-9]{20,}\n")
    os.chmod(v, 0o600)
    s = Sanitizer()
    rep = s.load_vault(str(v))
    assert rep["secrets"] == 1 and rep["patterns"] == 1
    out, n = san_and_count(s, "pwd Ex4mpl3-P@ss!42 con key sk-abcDEF1234567890ABCDEF")
    assert n == 2 and "Ex4mpl3-P@ss!42" not in out and "sk-abcDEF" not in out
    back, r, _ = s.desanitize(out)
    assert back == "pwd Ex4mpl3-P@ss!42 con key sk-abcDEF1234567890ABCDEF"
    # permessi larghi -> rifiuto
    os.chmod(v, 0o644)
    s2 = Sanitizer()
    with pytest.raises(VaultNotLoaded):
        s2.load_vault(str(v))


def san_and_count(s, t):
    out, n = s.sanitize(t)
    return out, n


def test_vault_fernet(tmp_path):
    from cryptography.fernet import Fernet
    key = Fernet.generate_key()
    v = tmp_path / "vault.enc"
    data = "Ex4mpl3-P@ss!42\nre:sk-[a-zA-Z0-9]{20,}\n"
    v.write_bytes(Fernet(key).encrypt(data.encode()))
    os.chmod(v, 0o600)
    s = Sanitizer()
    rep = s.load_vault(str(v), master_key=key.decode())
    assert rep["secrets"] == 1
    out, n = s.sanitize("usa Ex4mpl3-P@ss!42")
    assert n == 1 and "Ex4mpl3-P@ss!42" not in out


# ---------------- v1.1.0: voci nominate, lock, KDF ----------------

def test_named_entries_parse_and_lookup(tmp_path):
    from core import Sanitizer
    v = tmp_path / "vault.txt"
    v.write_text("# esempio\n"
                 "client:default=agent-token-1\n"
                 "provider:default=sk-real-provider-key\n"
                 "mia-password-plain\n"
                 "re:sk-[a-zA-Z0-9]{20,}\n")
    os.chmod(v, 0o600)
    s = Sanitizer(salt=b"\x01" * 16)
    rep = s.load_vault(str(v), enforce_perms=True)
    assert rep["named"] == 2 and rep["secrets"] == 1 and rep["patterns"] == 1
    assert s.lookup("client:default") == "agent-token-1"
    assert s.lookup("provider:default") == "sk-real-provider-key"
    assert s.lookup("inesistente") is None
    # named values are MASKED in bodies like any other secret
    out, n = s.sanitize("token: agent-token-1 key: sk-real-provider-key "
                        "pwd: mia-password-plain")
    assert n == 3 and "agent-token-1" not in out
    assert "sk-real-provider-key" not in out and "mia-password-plain" not in out
    back, r, un = s.desanitize(out)
    assert back == "token: agent-token-1 key: sk-real-provider-key " \
                   "pwd: mia-password-plain" and un == []
    # named_clients for the service auth
    cl = s.named_clients()
    assert cl == {"agent-token-1": "client:default"}


def test_named_line_with_equals_in_value(tmp_path):
    from core import Sanitizer
    v = tmp_path / "vault.txt"
    v.write_text("provider:default=sk-key=with=equals\n")
    os.chmod(v, 0o600)
    s = Sanitizer()
    s.load_vault(str(v))
    assert s.lookup("provider:default") == "sk-key=with=equals"


def test_plain_secret_with_equals_stays_plain(tmp_path):
    from core import Sanitizer
    v = tmp_path / "vault.txt"
    v.write_text("p@ss=word-mia\n")   # name not matching NAMED_RE -> plain secret
    os.chmod(v, 0o600)
    s = Sanitizer()
    rep = s.load_vault(str(v))
    assert rep["named"] == 0 and rep["secrets"] == 1
    assert "p@ss=word-mia" in s.secrets


def test_lock_wipes_state():
    from core import Sanitizer, VaultNotLoaded
    s = Sanitizer()
    s.load_from_lists(["segreto-abc"], named={"client:default": "tok"})
    out, _ = s.sanitize("segreto-abc tok")
    s.lock()
    assert s.is_loaded() is False
    assert s.lookup("client:default") is None
    assert s.tag2secret == {} and s.secrets == [] and s.named == {}
    with pytest.raises(VaultNotLoaded):
        s.sanitize("x")
    # i vecchi tag non sono piu' risolvibili (hard-cut)
    _, r, un = s.desanitize(out)
    assert r == 0 and len(un) >= 1


def test_kdf_deterministic_and_wrong_pass():
    from core import derive_key
    from cryptography.fernet import Fernet, InvalidToken
    salt = b"\x02" * 16
    k1 = derive_key("correct horse", salt)
    k2 = derive_key("correct horse", salt)
    k3 = derive_key("wrong horse", salt)
    assert k1 == k2 and k1 != k3
    tok = Fernet(k1.encode()).encrypt(b"dati segreti")
    assert Fernet(k1.encode()).decrypt(tok) == b"dati segreti"
    with pytest.raises(InvalidToken):
        Fernet(k3.encode()).decrypt(tok)


def test_salt_file_create_and_reload(tmp_path):
    from core import load_or_create_salt
    p = tmp_path / "vault.txt.salt"
    s1 = load_or_create_salt(str(p))
    assert len(s1) == 16
    s2 = load_or_create_salt(str(p))
    assert s1 == s2                      # deterministico tra i riavvii
    assert oct(p.stat().st_mode & 0o777) == "0o600"
    with pytest.raises(Exception):
        p.write_bytes(b"short")          # corrotto -> errore
        load_or_create_salt(str(p))


def test_encrypted_named_vault_roundtrip(tmp_path):
    from core import Sanitizer, derive_key, load_or_create_salt
    from cryptography.fernet import Fernet
    sp = tmp_path / "vault.txt.salt"
    salt = load_or_create_salt(str(sp))
    key = derive_key("pass-frase-robusta", salt)
    v = tmp_path / "vault.txt"
    v.write_bytes(Fernet(key.encode()).encrypt(
        "client:default=tok-xyz\nprovider:default=sk-prov\n".encode()))
    os.chmod(v, 0o600)
    s = Sanitizer()
    s.load_vault(str(v), master_key=key)
    assert s.lookup("provider:default") == "sk-prov"
    # passphrase sbagliata -> InvalidToken
    from cryptography.fernet import InvalidToken
    s2 = Sanitizer()
    with pytest.raises(InvalidToken):
        s2.load_vault(str(v), master_key=derive_key("errata", salt))


# ---------- 7.11 SSE-aware desanitizzazione (v1.1.2) ----------
import re as _re

from core import sse_feed_chunk, sse_flush


def _sse_openai_event(content):
    return ('data: {"id":"c1","object":"chat.completion.chunk","model":"m",'
            '"choices":[{"index":0,"delta":{"content":'
            + json.dumps(content, ensure_ascii=False)
            + '},"finish_reason":null}]}\n\n')


def _sse_ollama_event(content):
    return ('data: {"model":"m","created_at":"2026-01-01T00:00:00Z",'
            '"message":{"role":"assistant","content":'
            + json.dumps(content, ensure_ascii=False)
            + '},"done":false}\n\n')


def _collect_texts(out):
    """Rebuilds the model text from a processed SSE stream."""
    texts = []
    for line in out.split("\n"):
        line = line.strip()
        if not line.startswith("data:") or line == "data: [DONE]":
            continue
        try:
            o = json.loads(line[5:])
        except ValueError:
            continue
        ch = o.get("choices")
        if isinstance(ch, list) and ch and isinstance(ch[0], dict):
            for hk in ("delta", "message"):
                if isinstance(ch[0].get(hk), dict) and \
                        isinstance(ch[0][hk].get("content"), str):
                    texts.append(ch[0][hk]["content"])
        elif isinstance(o.get("message"), dict) and \
                isinstance(o["message"].get("content"), str):
            texts.append(o["message"]["content"])
        elif isinstance(o.get("content"), str):
            texts.append(o["content"])
    return texts


def _run_sse(san, events, chunk_size=5):
    body = "".join(events) + "data: [DONE]\n\n"
    chunks = [body[i:i + chunk_size] for i in range(0, len(body), chunk_size)]
    sd = StreamDesanitizer(san)
    out = "".join(sse_feed_chunk(sd, c) for c in chunks)
    out += sse_flush(sd)
    return out, sd


def test_sse_tag_split_across_events_openai(san):
    secret = "Ex4mpl3-P@ss!42"
    tagged, n = san.sanitize(f"usa {secret} ora")
    tag = _re.search(r"PWD_[0-9a-f]{8,12}", tagged).group(0)
    cut = 5  # 'PWD_f' + resto
    events = [_sse_openai_event(f"usa {tag[:cut]}"),
              _sse_openai_event(tag[cut:] + " ora")]
    out, sd = _run_sse(san, events)
    text = "".join(_collect_texts(out))
    assert secret in text and tag not in text
    assert sd.restored_count == 1


def test_sse_tag_split_across_events_ollama(san):
    secret = "F4ke-P4ss-9876"
    tagged, n = san.sanitize(f"pwd: {secret}")
    tag = _re.search(r"PWD_[0-9a-f]{8,12}", tagged).group(0)
    events = [_sse_ollama_event("pwd: " + tag[:1]),
              _sse_ollama_event(tag[1:])]
    out, sd = _run_sse(san, events)
    text = "".join(_collect_texts(out))
    assert secret in text and tag not in text
    assert sd.restored_count == 1


def test_sse_tag_every_split_point(san):
    secret = "s3cr3t-API-KEY-xyz"
    tagged, n = san.sanitize(f"key={secret};")
    tag = _re.search(r"PWD_[0-9a-f]{8,12}", tagged).group(0)
    for cut in range(1, len(tag)):
        events = [_sse_openai_event(f"key={tag[:cut]}"),
                  _sse_openai_event(tag[cut:] + ";")]
        out, sd = _run_sse(san, events)
        text = "".join(_collect_texts(out))
        assert secret in text and tag not in text, f"cut={cut}"
        assert sd.restored_count == 1, f"cut={cut}"


def test_sse_nonjson_passthrough(san):
    body = ("event: message\n"
            "data: not-json-at-all\n"
            "data: [DONE]\n")
    chunks = [body[i:i + 3] for i in range(0, len(body), 3)]
    sd = StreamDesanitizer(san)
    out = "".join(sse_feed_chunk(sd, c) for c in chunks)
    out += sse_flush(sd)
    assert "event: message\n" in out
    assert "data: not-json-at-all\n" in out
    assert "data: [DONE]\n" in out
    assert sd.restored_count == 0


def test_sse_flush_residual_partial_prefix(san):
    # the text ends with a potential tag prefix: it must be emitted at flush
    out, sd = _run_sse(san, [_sse_openai_event("end of text PW")])
    text = "".join(_collect_texts(out))
    assert text == "end of text PW"


def test_sse_no_tag_clean_passthrough(san):
    t = "response with no secrets, hello"
    out, sd = _run_sse(san, [_sse_openai_event(t)])
    text = "".join(_collect_texts(out))
    assert text == t and sd.restored_count == 0


def test_sse_unknown_tag_not_crash(san):
    # unknown 'PWD_' + hex: passes through without resolving and without crash
    out, sd = _run_sse(san, [_sse_openai_event("x PWD_deadbeef y")])
    text = "".join(_collect_texts(out))
    assert "PWD_deadbeef" in text and sd.restored_count == 0


def test_sse_content_field_restored_inplace(san):
    # the reworked JSON preserves the other keys
    secret = "Tr0ub4dor&3"
    tagged, n = san.sanitize(secret)
    tag = _re.search(r"PWD_[0-9a-f]{8,12}", tagged).group(0)
    events = [_sse_openai_event(f"ciao {tag}")]
    out, sd = _run_sse(san, events)
    assert '"id":"c1"' in out or '"id": "c1"' in out
    text = "".join(_collect_texts(out))
    assert secret in text
