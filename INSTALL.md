# LLMCloak — Installation, step by step

This guide takes you from zero to a running proxy. If a step fails,
jump to the **TROUBLESHOOTING** section at the bottom.

---

## 0. What you need

| requirement | why |
|---|---|
| Linux (Debian/Ubuntu is fine) or macOS | the project was born there; on Windows use WSL2 |
| Python **3.10+** (`python3 --version`) | the code is pure Python |
| a few dependencies (installed in step 2) | FastAPI, uvicorn, httpx, cryptography, python-multipart |

No Docker, no database, no open ports toward the internet.

---

## 1. Get the code

```bash
git clone <repo-url> llmcloak
cd llmcloak
```

(or copy the folder via SCP — the important files are: `core.py`,
`service.py`, `dashboard.py`, `vaultctl.py`, `run_proxy.sh`)

---

## 2. Install the dependencies

```bash
python3 -m venv .venv
source .venv/bin/activate
pip install fastapi uvicorn httpx cryptography python-multipart
```

> If you run the service without a venv, run the same `pip install` with the
> system Python. A venv is the recommended setup.

---

## 3. Start the service

```bash
./run_proxy.sh start
./run_proxy.sh status
```

Expected output:

```
ONLINE ... secrets:0 named:0 patterns:0 uptime:2s
```

Default port: **8917**. Want a different port?
`./run_proxy.sh start 9000` or export `LLMCLOAK_PORT=9000`.

---

## 4. First run: create the passphrase

Open your browser at:

```
http://127.0.0.1:8917/dashboard
```

- The dashboard shows **setup** mode: choose a passphrase (minimum
  8 characters, confirm it).
- This passphrase **encrypts the vault** and is **never stored anywhere**:
  if you lose it, you lose the secrets (see TROUBLESHOOTING).
- From now on, at every service start the vault comes up **locked**:
  unlock it with the passphrase (dashboard button or
  `./run_proxy.sh unlock`).

---

## 5. Add secrets

**Via dashboard** (recommended): secrets tab → add. You can also import a
CSV: choose the columns to import (preview included), assign the prefixes
(e.g. `NAME_`), confirm. Every import is kept in the history with the file
name and an ✕ to bulk-remove all values from that import.

**Via file**: create `vault.txt` next to the code, one secret per line:

```
MySuperSecret123!
sk-my-api-key-1234567890
re:sk-[a-zA-Z0-9]{20,}      <- pattern: masks ALL sk-... keys, even new ones
client:app1=TOKEN12345      <- token your app will use to authenticate
provider:default=sk-real-upstream
```

then press "encrypt" on the dashboard (or `python3 vaultctl.py encrypt`)
and restart:

```bash
./run_proxy.sh restart && ./run_proxy.sh unlock
```

---

## 6. Point your application at the proxy

In your app (Laravel/Python/Node/any OpenAI-compatible client) change only
the base URL and, if you use token mode, the API key:

```python
from openai import OpenAI
client = OpenAI(
    base_url="http://127.0.0.1:8917/v1",   # <- the proxy
    api_key="TOKEN12345",                   # <- client: token from the vault
)
```

The proxy forwards to the real upstream (default
`https://api.openai.com`) and automatically replaces the client token with
the real `provider:` key. Different upstream?
`./run_proxy.sh upstream https://api.yourprovider.com` or edit
`service_config.json`.

---

## 7. Verify everything works

```bash
curl -s http://127.0.0.1:8917/health
```

`"status":"active"` = vault unlocked and service OK.

Quick end-to-end test (with a secret `MySuperSecret123!` in the vault):

```bash
curl -s -X POST http://127.0.0.1:8917/v1/chat/completions \
  -H "Authorization: Bearer TOKEN12345" \
  -H "Content-Type: application/json" \
  -d '{"model":"gpt-4o-mini","messages":[{"role":"user",
        "content":"Repeat exactly: MySuperSecret123!"}]}' | head -c 400
```

If the answer comes back with `MySuperSecret123!` — the proxy masked it
toward the LLM and **restored** it toward you: everything works.

---

## 8 (optional). Autostart with systemd

```ini
# /etc/systemd/system/llmcloak.service
[Unit]
Description=LLMCloak
After=network.target

[Service]
User=youruser
WorkingDirectory=/path/to/llmcloak
ExecStart=/path/to/llmcloak/.venv/bin/uvicorn service:app --host 0.0.0.0 --port 8917
Restart=on-failure

[Install]
WantedBy=multi-user.target
```

```bash
sudo systemctl daemon-reload && sudo systemctl enable --now llmcloak
```

Note: after every service restart the vault is **locked** (by design:
the key lives only in RAM). Unlock via dashboard or
`python3 vaultctl.py unlock --passphrase '...'`.

---

## TROUBLESHOOTING

| symptom | cause | fix |
|---|---|---|
| `503` on every call | vault locked | dashboard → login, or `./run_proxy.sh unlock` |
| `Connection refused` | service not running | `./run_proxy.sh status`, then `./run_proxy.sh logs` |
| `401/403` from your app | wrong client token or IP not whitelisted | check `client:` entries in the vault and `trusted_ips` |
| port already in use | another process on 8917 | `./run_proxy.sh start 9000` |
| I forgot the passphrase | the vault is encrypted with that key | no recovery: restore a vault backup or recreate it |
| the LLM replies with visible `PWD_...` tags | the proxy could not restore (value not in the vault) | check that the secret exists and the vault is unlocked; see the `x-proxy-*` headers and the log counters |
| I want to change the upstream only for a test | runtime config | `./run_proxy.sh upstream <URL>` |

## Updating

```bash
git pull
./run_proxy.sh restart && ./run_proxy.sh unlock
```

The vault (`vault.txt`, encrypted) is never touched by code updates.
**Back it up before every update**: it is the only file holding your
real secrets.

---

LLMCloak — Copyright 2026 Quantum Sphere EOOD. Licensed under the Apache License, Version 2.0 (see LICENSE).
