"""End-to-end test of the full proxy (v1.1.0):
  fake upstream :8919  <-  proxy  <-  client

Services:
  A :8917 encrypted vault, no env key -> LOCKED at startup
      -> wrong unlock 401, correct unlock -> active, round-trip, client auth,
         upstream auth passthrough (v1.2.8), repeated lock/unlock
  B :8918 PLAIN vault with client:/provider: -> active at startup (env-less mode B),
      failed reload does NOT wipe the in-memory map
  C :8921 vault without provider:default -> /v1/* works (client-provided auth)
  D :8922 no vault -> 503 fail-safe (mode A and B)

Key assertions:
  1. upstream NEVER saw the secrets in the body (no-leak)
  2. upstream received Authorization: Bearer <client token> (passthrough v1.2.8)
  3. buffered response and SSE restore the secrets (verbatim round-trip)
  4. fail-closed everywhere: locked/401/503/403
"""
import json
import os
import signal
import subprocess
import sys
import time
from pathlib import Path

import requests

BASE = Path(os.environ.get(
    "SECRETS_PROXY_HOME",
    Path(__file__).resolve().parents[1],
))
PKG = BASE
PROXY_LOG = PKG / "tests" / "proxy_e2e.log"
sys.path.insert(0, str(BASE))
os.chdir(str(BASE))

from core import derive_key, load_or_create_salt  # noqa: E402
from cryptography.fernet import Fernet  # noqa: E402

os.environ["SECRETS_PROXY_UPSTREAM"] = "http://127.0.0.1:8919"
# NEUTRAL config for the test instances: keeps a deployed
# service_config.json from altering the expected behavior
_cfg_test = BASE / "_e2e_config.json"
_cfg_test.write_text('{"upstream": "https://api.openai.com"}\n')
os.environ["SECRETS_PROXY_CONFIG"] = str(_cfg_test)
os.environ["SECRETS_PROXY_API_KEY"] = "test-admin-key"
ADMIN = {"X-Admin-Token": "test-admin-key"}
CLIENT_TOKEN = "agent-token-e2e-1"
PROVIDER_KEY = "sk-provider-real-key-e2e"
SECRETS = ["Ex4mpl3-P@ss!42", "s3cr3t-API-KEY-xyz"]
AUTH = {"Authorization": f"Bearer {CLIENT_TOKEN}"}

vault_enc = PKG / "tests" / "_vault_enc.txt"      # service A (encrypted)
vault_plain = PKG / "tests" / "_vault.txt"        # service B (plain)
vault_noprov = PKG / "tests" / "_vault_noprov.txt"  # service C

# vault A: encrypted, no env key -> LOCKED at startup (mode A)
salt = load_or_create_salt(str(vault_enc) + ".salt")
enc_pass = "e2e-passphrase-robust"
plain_lines = ("client:default=" + CLIENT_TOKEN + "\n"
               "provider:default=" + PROVIDER_KEY + "\n"
               + "\n".join(SECRETS) + "\n")
vault_enc.write_bytes(Fernet(derive_key(enc_pass, salt).encode())
                      .encrypt(plain_lines.encode()))
os.chmod(vault_enc, 0o600)

# vault B: plain, loads itself at startup
vault_plain.write_text("# test vault\n" + plain_lines)
os.chmod(vault_plain, 0o600)

# vault C: no provider:default (v1.2.8: auth handled by the client)
vault_noprov.write_text("client:default=" + CLIENT_TOKEN + "\n"
                        + SECRETS[0] + "\n")
os.chmod(vault_noprov, 0o600)

procs = []


def up(url, name, wait_s=30):
    t0 = time.time()
    while time.time() - t0 < wait_s:
        try:
            requests.get(url, timeout=1)
            return True
        except Exception:
            time.sleep(0.4)
    raise RuntimeError(f"{name} did not come up")


def start_service(port, vault_path, extra_env=None):
    env = {**os.environ, "SECRETS_PROXY_VAULT": str(vault_path)}
    env.update(extra_env or {})
    log = open(f"{PROXY_LOG}.{port}", "w")
    procs.append(subprocess.Popen(
        [sys.executable, "-m", "uvicorn", "service:app",
         "--host", "127.0.0.1", "--port", str(port), "--log-level", "warning"],
        cwd=str(BASE), stdout=log, stderr=subprocess.STDOUT, env=env))


def main():
    ok = True
    try:
        procs.append(subprocess.Popen(
            [sys.executable, str(PKG / "tests" / "fake_upstream.py")],
            stdout=subprocess.DEVNULL, stderr=subprocess.STDOUT))
        up("http://127.0.0.1:8919/v1/_received", "fake upstream")

        req = {"model": "gpt-test", "messages": [{"role": "user",
               "content": "my password is Ex4mpl3-P@ss!42 and the api key is "
                          "s3cr3t-API-KEY-xyz"}]}

        # ================= A :8917 — mode A (encrypted, LOCKED) ==========
        start_service(8917, vault_enc)
        up("http://127.0.0.1:8917/health", "proxy A")
        h = requests.get("http://127.0.0.1:8917/health", timeout=5).json()
        assert h["status"] == "locked" and h["loaded"] is False, h
        r = requests.post("http://127.0.0.1:8917/sanitize",
                          json={"text": "x"}, timeout=5)
        assert r.status_code == 503, r.status_code
        print("[E2E] A1 encrypted start with no key -> LOCKED, /sanitize 503 OK")

        r = requests.post("http://127.0.0.1:8917/admin/unlock",
                          json={"passphrase": "wrong-pass"}, timeout=10,
                          headers=ADMIN)
        assert r.status_code == 401, r.status_code
        print("[E2E] A2 wrong unlock passphrase -> 401 OK")

        r = requests.post("http://127.0.0.1:8917/admin/unlock",
                          json={"passphrase": enc_pass}, timeout=30,
                          headers=ADMIN)
        assert r.status_code == 200 and r.json()["unlocked"], r.text
        rep = r.json()["report"]
        assert rep["named"] == 2 and rep["secrets"] == 2, rep
        print("[E2E] A3 correct unlock -> active OK", rep)

        r = requests.post("http://127.0.0.1:8917/sanitize",
                          json={"text": "Ex4mpl3-P@ss!42"}, timeout=5)
        assert r.status_code == 401, r.status_code   # loaded but no client token
        r = requests.post("http://127.0.0.1:8917/sanitize",
                          json={"text": "Ex4mpl3-P@ss!42"}, timeout=5,
                          headers={"Authorization": "Bearer wrong-token"})
        assert r.status_code == 401, r.status_code
        r = requests.post("http://127.0.0.1:8917/sanitize",
                          json={"text": "Ex4mpl3-P@ss!42"}, timeout=5,
                          headers=AUTH)
        assert r.status_code == 200 and r.json()["replaced"] == 1, r.text
        print("[E2E] A4 auth client: 401/401/200 OK")

        # buffered round-trip + no-leak + provider passthrough
        r = requests.post("http://127.0.0.1:8917/v1/chat/completions",
                          json=req, timeout=10, headers=AUTH)
        assert r.status_code == 200, r.text
        cited = r.json()["choices"][0]["message"]["content"]
        for s in SECRETS:
            assert s in cited, f"round-trip failed: {cited!r}"
        seen = requests.get("http://127.0.0.1:8919/v1/_received", timeout=5).json()
        blob = "\n".join(e["body"] for e in seen["entries"])
        for s in SECRETS + [CLIENT_TOKEN]:
            assert s not in blob, f"NO-LEAK VIOLATION: upstream saw {s!r}"
        assert "PWD_" in blob
        auths = {e["authorization"] for e in seen["entries"]}
        assert auths == {f"Bearer {CLIENT_TOKEN}"}, auths
        print("[E2E] A5 round-trip OK; upstream: solo tag, auth passthrough =",
              auths.pop())

        # SSE with tags split across 3-char chunks
        req["stream"] = True
        chunks = []
        with requests.post("http://127.0.0.1:8917/v1/chat/completions-stream",
                           json=req, timeout=15, stream=True, headers=AUTH) as rs:
            assert rs.status_code == 200
            for line in rs.iter_lines(decode_unicode=True):
                if line:
                    chunks.append(line)
        blob_sse = "\n".join(chunks)
        for s in SECRETS:
            assert s in blob_sse, f"SSE round-trip failed: {blob_sse[:200]!r}"
        assert "[DONE]" in blob_sse
        print("[E2E] A6 SSE 3-char chunks OK ->", blob_sse[:110], "...")

        # lock -> 503, unlock -> active again
        r = requests.post("http://127.0.0.1:8917/admin/lock", timeout=5,
                          headers=ADMIN)
        assert r.status_code == 200
        h = requests.get("http://127.0.0.1:8917/health", timeout=5).json()
        assert h["status"] == "locked"
        r = requests.post("http://127.0.0.1:8917/v1/chat/completions",
                          json=req, timeout=5, headers=AUTH)
        assert r.status_code == 503
        r = requests.post("http://127.0.0.1:8917/admin/unlock",
                          json={"passphrase": enc_pass}, timeout=30,
                          headers=ADMIN)
        assert r.status_code == 200
        r = requests.post("http://127.0.0.1:8917/sanitize",
                          json={"text": "Ex4mpl3-P@ss!42"}, timeout=5,
                          headers=AUTH)
        assert r.status_code == 200
        print("[E2E] A7 lock -> 503 -> re-unlock -> active OK")

        # admin without token from non-loopback: 403
        r = requests.post("http://127.0.0.1:8917/admin/lock", timeout=5,
                          headers={"X-Admin-Token": "wrong-token"})
        assert r.status_code == 403
        print("[E2E] A8 wrong admin token -> 403 OK")

        # ================= B :8918 — plain, active at startup ============
        start_service(8918, vault_plain)
        up("http://127.0.0.1:8918/health", "proxy B")
        h = requests.get("http://127.0.0.1:8918/health", timeout=5).json()
        assert h["status"] == "active", h
        # a failed reload must NOT wipe the in-memory map
        os.rename(str(vault_plain), str(vault_plain) + ".hidden")
        r2 = requests.post("http://127.0.0.1:8918/vault/reload", timeout=5,
                           headers={**ADMIN, "X-Proxy-Key": "test-admin-key"})
        assert r2.status_code >= 400, r2.status_code
        h2 = requests.get("http://127.0.0.1:8918/health", timeout=5).json()
        assert h2["loaded"] is True, "failed reload must not unload"
        tag = requests.post("http://127.0.0.1:8918/sanitize",
                            json={"text": "Ex4mpl3-P@ss!42"}, timeout=5,
                            headers=AUTH).json()["text"]
        back = requests.post("http://127.0.0.1:8918/desanitize",
                             json={"text": tag}, timeout=5, headers=AUTH).json()
        assert "Ex4mpl3-P@ss!42" in back["text"], "map lost after failed reload"
        os.rename(str(vault_plain) + ".hidden", str(vault_plain))
        print("[E2E] B1 plain vault active; failed reload -> map preserved OK")

        # ========= C :8921 — no provider:default (v1.2.8 passthrough) ===
        start_service(8921, vault_noprov)
        up("http://127.0.0.1:8921/health", "proxy C")
        r = requests.post("http://127.0.0.1:8921/v1/chat/completions",
                          json=req, timeout=5, headers=AUTH)
        assert r.status_code == 200, r.status_code
        cited = r.json()["choices"][0]["message"]["content"]
        assert SECRETS[0] in cited, f"round-trip C failed: {cited!r}"
        print("[E2E] C1 no provider:default -> 200, client-provided auth OK")

        # ================= D :8922 — no vault =============================
        start_service(8922, "/nonexistent/vault.txt")
        up("http://127.0.0.1:8922/health", "proxy D")
        r4a = requests.post("http://127.0.0.1:8922/sanitize",
                            json={"text": "x"}, timeout=5)
        assert r4a.status_code == 503, r4a.status_code
        r4b = requests.post("http://127.0.0.1:8922/v1/chat/completions",
                            json=req, timeout=5, headers=AUTH)
        assert r4b.status_code == 503, r4b.status_code
        print("[E2E] D1 fail-safe OK (no vault -> 503 in mode A and B)")

        h = requests.get("http://127.0.0.1:8917/health", timeout=5).json()
        print("[E2E] health:", json.dumps(h["stats"]))
        print("E2E ALL GREEN")
    except Exception as e:
        ok = False
        print("E2E FAILED:", repr(e))
        for port in (8917, 8918, 8921, 8922):
            try:
                print(f"--- proxy.log.{port} ---")
                print(open(f"{PROXY_LOG}.{port}").read()[-1500:])
            except Exception:
                pass
        raise
    finally:
        for p in procs:
            try:
                p.send_signal(signal.SIGTERM)
            except Exception:
                pass
        for p in procs:
            p.wait(timeout=10)
    sys.exit(0 if ok else 1)


if __name__ == "__main__":
    main()
