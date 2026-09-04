# INSTALLAZIONE — guida passo-passo (a prova di deficiente)

Questa guida ti porta da zero al proxy funzionante. Se un passaggio non va,
vai alla sezione **PROBLEMI COMUNI** in fondo.

---

## 0. Cosa ti serve

| requisito | perché |
|---|---|
| Linux (Debian/Ubuntu va bene) o macOS | il progetto nasce lì; su Windows usa WSL2 |
| Python **3.10+** (`python3 --version`) | il codice è Python |
| 3 dipendenze (le installiamo al passo 2) | FastAPI, uvicorn, httpx, cryptography, python-multipart |

Non serve Docker, non serve un database, non serve aprire porte verso internet.

---

## 1. Prendi il codice

```bash
git clone <repo-url> secrets_proxy
cd secrets_proxy
```

(oppure copia la cartella via SCP — i file importanti sono: `core.py`,
`service.py`, `dashboard.py`, `vaultctl.py`, `run_proxy.sh`)

---

## 2. Installa le dipendenze

```bash
python3 -m venv .venv
source .venv/bin/activate
pip install fastapi uvicorn httpx cryptography python-multipart
```

> Se usi il servizio senza venv, dai lo stesso `pip install` con il Python di
> sistema. Il venv è la scelta consigliata.

---

## 3. Avvia il servizio

```bash
./run_proxy.sh start
./run_proxy.sh status
```

Output atteso:

```
ONLINE ... secrets:0 named:0 patterns:0 uptime:2s
```

Porta di default: **8917**. Vuoi un'altra porta?
`./run_proxy.sh start 9000` oppure export `SECRETS_PROXY_PORT=9000`.

---

## 4. Primo avvio: crea la passphrase

Apri il browser su:

```
http://127.0.0.1:8917/dashboard
```

- Il dashboard ti mostra la modalità **setup**: scegli una passphrase
  (minimo 8 caratteri, confermala).
- Questa passphrase **cifra il vault** e **non viene salvata da nessuna
  parte**: se la perdi, perdi i segreti (vedi PROBLEMI COMUNI).
- Da qui in poi, a ogni avvio del servizio, il vault parte **bloccato**:
  sblocca con la passphrase (bottone del dashboard oppure
  `./run_proxy.sh unlock`).

---

## 5. Inserisci i segreti

**Via dashboard** (consigliato): tab segreti → aggiungi. Puoi anche importare
un CSV: selezioni le colonne da importare (c'è l'anteprima), assegni i prefissi
(es. `NOME_`), confermi. Ogni import resta nello storico con il nome del file e
una ✕ per rimuovere in blocco tutti i valori di quell'import.

**Via file**: crea `vault.txt` accanto al codice, un segreto per riga:

```
SuperSegreta123!
sk-mia-api-key-1234567890
re:sk-[a-zA-Z0-9]{20,}      ← pattern: maschera TUTTE le sk-... anche nuove
client:app1=TOKEN12345      ← token che la tua app userà per autenticarsi
provider:default=sk-reale-upstream
```

poi dal dashboard premi "encrypt" (o `python3 vaultctl.py encrypt`) e riavvia:

```bash
./run_proxy.sh restart && ./run_proxy.sh unlock
```

---

## 6. Punta la tua applicazione al proxy

Nella tua app (Laravel/Python/Node/qualunque client OpenAI-compatible) cambia
solo il base URL e, se usi la modalità token, la API key:

```python
from openai import OpenAI
client = OpenAI(
    base_url="http://127.0.0.1:8917/v1",   # ← il proxy
    api_key="TOKEN12345",                   # ← token client: del vault
)
```

Il proxy inoltra al vero upstream (default `https://api.openai.com`) e
sostituisce in automatico il token client con la chiave `provider:` reale.
Upstream diverso? `./run_proxy.sh upstream https://api.tuoprovider.it`
o campo nel `service_config.json`.

---

## 7. Verifica che tutto funzioni

```bash
curl -s http://127.0.0.1:8917/health
```

`"status":"active"` = vault sbloccato e servizio ok.

Test rapido end-to-end (con un segreto `SuperSegreta123!` nel vault):

```bash
curl -s -X POST http://127.0.0.1:8917/v1/chat/completions \
  -H "Authorization: Bearer TOKEN12345" \
  -H "Content-Type: application/json" \
  -d '{"model":"gpt-4o-mini","messages":[{"role":"user",
        "content":"Ripeti esattamente: SuperSegreta123!"}]}' | head -c 400
```

Se nella risposta torna `SuperSegreta123!` — è il proxy che l'ha mascherata
verso l'LLM e **ripristinata** verso di te: tutto funziona.

---

## 8 (opzionale). Avvio automatico con systemd

```ini
# /etc/systemd/system/secrets-proxy.service
[Unit]
Description=LLMCloak
After=network.target

[Service]
User=tuoutente
WorkingDirectory=/percorso/secrets_proxy
ExecStart=/percorso/secrets_proxy/.venv/bin/uvicorn service:app --host 0.0.0.0 --port 8917
Restart=on-failure

[Install]
WantedBy=multi-user.target
```

```bash
sudo systemctl daemon-reload && sudo systemctl enable --now secrets-proxy
```

Nota: dopo ogni riavvio del servizio il vault è **bloccato** (by design:
la chiave vive solo in RAM). Sblocca via dashboard o
`python3 vaultctl.py unlock --passphrase '...'`.

---

## PROBLEMI COMUNI

| sintomo | causa | rimedio |
|---|---|---|
| `503` su ogni chiamata | vault bloccato | dashboard → login, o `./run_proxy.sh unlock` |
| `Connection refused` | servizio non attivo | `./run_proxy.sh status`, guarda `./run_proxy.sh logs` |
| `401/403` dalla tua app | token client errato o IP non in whitelist | controlla `client:` nel vault e `trusted_ips` |
| porta occupata | altro processo su 8917 | `./run_proxy.sh start 9000` |
| ho dimenticato la passphrase | il vault è cifrato con quella chiave | nessun recupero: riparti da un backup del vault o ricrealo |
| l'LLM risponde con tag `PWD_...` visibili | il proxy non ha potuto ripristinare (valore non in vault) | controlla che il segreto sia presente/sbloccato; vedi `x-proxy-*` header e log contatori |
| voglio aggiornare l'upstream solo per un test | config a runtime | `./run_proxy.sh upstream <URL>` |

## Aggiornare

```bash
git pull
./run_proxy.sh restart && ./run_proxy.sh unlock
```

Il vault (`vault.txt`, cifrato) non viene toccato dagli aggiornamenti del codice.
**Fanne un backup prima di ogni aggiornamento**: è l'unico file con i tuoi
segreti veri.
