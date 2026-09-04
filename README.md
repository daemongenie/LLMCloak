# LLM Secrets Proxy

> **English TL;DR:** a self-hosted, OpenAI-compatible reverse proxy that sits between
> your application and any LLM API. It replaces passwords, API keys and customer
> personal data with safe tags *before* the request reaches the model, and restores
> the real values in the response. The real secrets never leave your machine.

---

## Che cos'è? (spiegazione semplice)

Immagina di dover chiedere a ChatGPT (o a un altro LLM):

> *"Scrivi una email di benvenuto al cliente Acme. La sua password è `SuperSegreta123!`."*

Se mandi il testo così com'è, la password finisce **sui server dell'LLM** e lì
resta. Con il Secrets Proxy, invece, la tua applicazione parla con il proxy
(che gira sul tuo computer/server) e il proxy parla con l'LLM:

```
La tua app ──► SECRETS PROXY ──► LLM (OpenAI, GLM, ...)
                  │                    │
                  │  "la password è    │  "la password è PWD_a1b2c3"
                  │   SuperSegreta123" │  ◄── il modello vede SOLO il tag
                  │                    │
                  └── risposta con la  │
                      password VERA ◄──┘ (il proxy rimette il valore reale)
```

1. **Prima della richiesta**: il proxy cerca nel testo password, API key e dati
   sensibili presenti nel suo "cofre" (*vault*) e li sostituisce con tag senza
   significato (`PWD_xxxxxxxx`).
2. **Il modello lavora sui tag**: può usarli, copiarli, ripeterli — ma non sa
   qual è il valore vero.
3. **Dopo la risposta**: il proxy rimette al posto dei tag i valori veri, così
   la tua applicazione riceve il testo completo e corretto.

La mappatura tag↔valore vive **solo in memoria RAM**, il vault su disco è
**cifrato**, e i log non contengono mai il testo delle conversazioni.

## A cosa serve

- Usare un LLM (anche cloud) **senza esporre** credenziali aziendali.
- Mandare in analisi **dati dei clienti** (ragioni sociali, P.IVA, telefoni,
  email…) senza fuggirli al provider.
- Cambiare modello/provider senza riscrivere il codice: il proxy parla il
  protocollo standard `/v1/chat/completions` di OpenAI.

## Cosa NON protegge (onestà digitale)

- Se **tu** scrivi un segreto nel prompt e quel segreto **non è nel vault**,
  il proxy non può saperlo: proteggere lo fa, indovinare no. (Esiste un filtro
  di pattern `re:...` per i formati prevedibili, tipo chiavi `sk-...`.)
- Non cripta le conversazioni: le voice *maschera* verso l'LLM. Verso di te
  la risposta arriva completa.
- Non è un firewall: chi ha accesso al proxy e al vault ha accesso ai segreti.

## Avvio rapido (3 minuti)

```bash
git clone <repo-url> && cd secrets_proxy
python3 -m venv .venv && source .venv/bin/activate
pip install fastapi uvicorn httpx cryptography python-multipart
./run_proxy.sh start            # servizio su http://0.0.0.0:8917
# apri il dashboard, crea la passphrase al primo avvio:
#   http://127.0.0.1:8917/dashboard
```

Poi, nella tua applicazione, cambia solo l'URL dell'API:

```python
# prima:  base_url = "https://api.openai.com/v1"
base_url = "http://127.0.0.1:8917/v1"
```

La guida completa passo-passo (con risoluzione dei problemi) è in
**[INSTALL.md](INSTALL.md)**.

## Come aggiungere i segreti

Tre modi, dal più semplice al più potente:

1. **Dashboard web** (`http://host:8917/dashboard`): aggiungi/vedi/cancelli le
   voci, importi un CSV, lanci i purge. La passphrase viene chiesta a ogni
   avvio e non viene mai salvata.
2. **File vault** (`vault.txt`): un segreto per riga, cifrabile con un click
   dal dashboard. Esempio in `vault.example.txt`.
3. **CLI** `vaultctl.py`: add/remove/list/encrypt/decrypt da terminale.

### Segreti "nominati"

- `client:mionome=TOKEN123` → chi chiama il proxy deve presentare `TOKEN123`
  come Bearer token (modalità token, default).
- `provider:default=sk-reale...` → il proxy usa questa chiave VERA verso
  l'upstream: la tua app non la conosce mai.

### Import CSV (batch)

Dal dashboard: carichi un CSV, **scegli quali colonne importare** (anteprima
incluse), assegni un prefisso a colonna (es. `NOME_`) e i valori diventano tag
tipo `NOME_PWD_xxxx`. Ogni import finisce nello **storico**: con la ✕ accanto
al nome del CSV cancelli in un colpo solo tutti i valori di quell'import.

### Pattern dinamici

Righe `re:<regex>` nel vault: catturano formati prevedibili (es.
`re:sk-[a-zA-Z0-9]{20,}` per le API key) anche se non li hai mai inseriti.

## Modalità di accesso

| modalità | chi può chiamare il proxy |
|---|---|
| `open_mode: false` (default) | solo chi presenta un token `client:` valido |
| `open_mode: true` | chiunque (restrigibile con whitelist IP/CIDR `trusted_ips`) |

La configurazione vive in `service_config.json` (esempio in
`service_config.example.json`), modificabile anche dal dashboard.

## Test

```bash
python3 tests_e2e.py        # suite end-to-end (upstream simulato, offline)
python3 -m pytest tests/ -q # unit test
```

## Prestazioni

Overhead misurato in produzione su vault da ~48.000 segreti: **0,5–0,9 ms per
richiesta** (dettagli e metodologia in [BENCH_REPORT.md](BENCH_REPORT.md)).

## Stato

- Versione corrente: **v1.5.8** — changelog sintetico nel git log.
- Progettato per Linux, testato su Debian; funziona ovunque ci sia Python 3.10+.

## License

TBD (da definire prima della pubblicazione).
