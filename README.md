# LLMCloak

> **TL;DR:** a self-hosted, OpenAI-compatible reverse proxy that sits between
> your application and any LLM API. It replaces passwords, API keys and customer
> personal data with opaque tags *before* the request reaches the model, and
> restores the real values in the response. Real secrets never leave your machine.

---

## What is it? (plain explanation)

Imagine you need to ask ChatGPT (or any other LLM):

> *"Write a welcome email for the client Acme. Their password is `SuperSecret123!`."*

If you send the text as-is, the password ends up **on the LLM provider's servers**
and stays there. With LLMCloak, instead, your application talks to the proxy
(running on your own machine/server) and the proxy talks to the LLM:

```
Your app ──► LLMCLOAK PROXY ──► LLM (OpenAI, GLM, ...)
                 │                   │
                 │ "the password is  │ "the password is PWD_a1b2c3"
                 │  SuperSecret123"  │ ◄── the model sees ONLY the tag
                 │                   │
                 └── response with   │
                     the REAL value ◄┘ (the proxy puts the real value back)
```

1. **Before the request**: the proxy looks up passwords, API keys and sensitive
   data from its encrypted *vault* and replaces them with meaningless tags
   (`PWD_xxxxxxxx`).
2. **The model works on tags**: it can use them, copy them, repeat them — but it
   never learns the real value.
3. **After the response**: the proxy puts the real values back in place of the
   tags, so your application receives the complete, correct text.

The tag↔value mapping lives **only in RAM**, the vault on disk is **encrypted**,
and logs never contain conversation text.

## Use cases

- Use an LLM (even cloud-hosted) **without exposing** corporate credentials.
- Send **customer data** (company names, VAT numbers, phones, emails...) for
  analysis without leaking them to the provider.
- Switch model/provider without rewriting code: the proxy speaks the standard
  OpenAI `/v1/chat/completions` protocol.

## What it does NOT protect against (honest disclaimer)

- If **you** write a secret in the prompt and that secret **is not in the
  vault**, the proxy cannot know it: it protects what it knows, it does not
  guess. (A `re:...` pattern filter exists for predictable formats such as
  `sk-...` API keys.)
- It does not encrypt conversations: the words are *masked* toward the LLM.
  Toward you, the response comes back complete.
- It is not a firewall: whoever can access the proxy and the vault has access
  to the secrets.

## Quick start (3 minutes)

```bash
git clone <repo-url> && cd llmcloak
python3 -m venv .venv && source .venv/bin/activate
pip install fastapi uvicorn httpx cryptography python-multipart
./run_proxy.sh start            # service on http://0.0.0.0:8917
# open the dashboard, set the passphrase on first launch:
#   http://127.0.0.1:8917/dashboard
```

Then, in your application, change only the API base URL:

```python
# before:  base_url = "https://api.openai.com/v1"
base_url = "http://127.0.0.1:8917/v1"
```

The full step-by-step guide (including troubleshooting) is in
**[INSTALL.md](INSTALL.md)**.

## How to add secrets

Three ways, from simplest to most powerful:

1. **Web dashboard** (`http://host:8917/dashboard`): create/list/delete the
   entries, import a CSV, run purges. The passphrase is asked at every start
   and is never stored.
2. **Vault file** (`vault.txt`): one secret per line, encryptable with one
   click from the dashboard. See `vault.example.txt`.
3. **CLI** `vaultctl.py`: add/remove/list/encrypt/decrypt from a terminal.

### Named secrets

- `client:myname=TOKEN123` → callers of the proxy must present `TOKEN123` as a
  Bearer token (token mode, default).
- `provider:default=sk-real...` → the proxy uses this REAL key toward the
  upstream: your application never sees it.

### CSV import (batch)

From the dashboard: upload a CSV, **choose which columns to import** (preview
included), assign a per-column prefix (e.g. `NAME_`) and the values become tags
like `NAME_PWD_xxxx`. Every import is kept in the **import history**: with the
✕ button next to the CSV name you can wipe all values of that import at once.

### Dynamic patterns

`re:<regex>` lines in the vault: they catch predictable formats (e.g.
`re:sk-[a-zA-Z0-9]{20,}` for API keys) even if you never entered them.

## Access modes

| mode | who can call the proxy |
|---|---|
| `open_mode: false` (default) | only callers presenting a valid `client:` token |
| `open_mode: true` | anyone (can be restricted with the `trusted_ips` IP/CIDR allowlist) |

Configuration lives in `service_config.json` (see
`service_config.example.json`), editable from the dashboard as well.

## Tests

```bash
python3 tests_e2e.py        # end-to-end suite (simulated upstream, offline)
python3 -m pytest tests/ -q # unit tests
```

## Performance

Measured overhead in production with a vault of ~48,000 entries: **0.5–0.9 ms
per request** (details and methodology in [BENCH_REPORT.md](BENCH_REPORT.md)).

## Status

- Current version: **v1.5.9** — short changelog in the git log.
- Designed for Linux, tested on Debian; runs anywhere Python 3.10+ is available.

## License

LLMCloak is **open source**, licensed under the [Apache License, Version 2.0](LICENSE).

    Copyright 2026 Quantum Sphere EOOD

    Licensed under the Apache License, Version 2.0 (the "License");
    you may not use this file except in compliance with the License.
    You may obtain a copy of the License at

        http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software distributed under the License is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the [LICENSE](LICENSE) file for the specific language governing permissions and limitations under the License.

See [NOTICE](NOTICE) for attribution details and [CONTRIBUTING](CONTRIBUTING.md) to contribute (DCO sign-off required).
