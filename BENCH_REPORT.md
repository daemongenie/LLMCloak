# LLMCloak — Benchmark v1.5.7

pyahocorasick disponibile: **SI** — Python 3.9.2

### A. sanitize() — testo 2 KB, latenza vs dimensione vault

| scenario | iter | p50 | p95 | p99 |
|---|---|---|---|---|
| 100 segreti — AC attivo | 300 |       48 us |       57 us |       74 us |
| 1,000 segreti — AC attivo | 300 |       49 us |       51 us |       63 us |
| 10,000 segreti — AC attivo | 300 |       49 us |       51 us |       65 us |
|---|---|---|---|---|
| 100 segreti — fallback senza AC | 300 |       88 us |       93 us |      145 us |
| 1,000 segreti — fallback senza AC | 300 |      704 us |      759 us |      811 us |
| 10,000 segreti — fallback senza AC | 222 |     6.98 ms |     7.26 ms |     7.76 ms |

### B. sanitize() — vault 1.000 segreti, latenza vs dimensione testo

| scenario | iter | p50 | p95 | p99 |
|---|---|---|---|---|
| testo 0.2 KB — AC attivo | 300 |       25 us |       25 us |       38 us |
| testo 0.2 KB — fallback | 300 |      387 us |      431 us |      507 us |
| testo 2 KB — AC attivo | 300 |       50 us |       52 us |       85 us |
| testo 2 KB — fallback | 300 |      717 us |      758 us |      784 us |
| testo 20 KB — AC attivo | 300 |      290 us |      329 us |      364 us |
| testo 20 KB — fallback | 300 |     4.52 ms |     4.66 ms |     5.01 ms |
| testo 200 KB — AC attivo | 300 |     2.71 ms |     3.03 ms |     3.21 ms |
| testo 200 KB — fallback | 33 |    45.19 ms |    45.75 ms |    45.84 ms |

### C. desanitize() — testo 2 KB, impatto della discovery family sul n. di tag mintati

| scenario | iter | p50 | p95 | p99 |
|---|---|---|---|---|
|     10 tag in sessione | 300 |       77 us |       80 us |      108 us |
|  1,000 tag in sessione | 300 |      838 us |      897 us |      974 us |
| 10,000 tag in sessione | 175 |     8.11 ms |     8.49 ms |     8.79 ms |

### D. StreamDesanitizer (SSE) — testo 100 KB, chunk 256 B

| scenario | iter | p50 | p95 | p99 |
|---|---|---|---|---|
| stream restore (5 tag) — 31.88 MB/s | 300 |     3.06 ms |     3.14 ms |     3.36 ms |

### E. sanitize_rows() — CSV 1.000 righe x 5 colonne

| scenario | iter | p50 | p95 | p99 |
|---|---|---|---|---|
| batch sanitize (cache per-valore attiva) | 3 |     1.98 s |     1.99 s |     1.99 s |

### F. Overhead aggiunto dal proxy a ogni turno di chat (testo 2 KB, vault 1.000)

| componente | iter | p50 | p95 | p99 |
|---|---|---|---|---|
| sanitize (richiesta -> LLM) | 300 |       49 us |       51 us |       53 us |
| desanitize (risposta -> client) | 300 |      456 us |      508 us |      553 us |
| **TOTALE aggiunto per turno** | — | **     506 us** | — | — |

Su una risposta LLM di 1.000 ms l'overhead e' **0.1%**; su 3.000 ms e' **0.0%**.

### G. Caricamento vault 10.000 segreti (inclusa build Aho-Corasick)

| metrica | valore |  |  |  |
|---|---|---|---|---|
| load_from_lists() 10k |   153.31 ms | | | |
| RAM Sanitizer (current/peak) | 4.2 / 6.8 MB | | | |

## Lettura dei risultati

1. **pyahocorasick e' il fattore dominante.** Senza il modulo, sanitize()
   esegue un `str.count()` per OGNI segreto del vault: costo O(V·n). Con il
   modulo la scansione e' un'unica passata O(n). A 10k segreti la differenza
   e' di ordini di grandezza. AZIONE: installare `pip install pyahocorasick`
   sulla VM di produzione (il codice gia' lo usa se presente).
2. **desanitize() scala col numero di tag mintati** (discovery family:
   una regex per ogni chiave di tag2secret per chiamata). Con import CSV
   molto grandi la discovery pesa; restare sotto ~10k tag/sessione e' ok.
   Un indice {family: set(tags)} eliminerebbe il costo (miglioria futura).
3. **L'overhead per turno di chat** (F) e' trascurabile rispetto alla
   latenza LLM tipica (>1 s) se AC e' attivo.
4. **Lo stream SSE (D)** ripristina in tempo reale con margine ampio
   rispetto alla velocita' di token dei LLM (decine di MB/s vs ~KB/s).
5. **Il caricamento del vault (G)** e' un costo una tantum per sessione
   (build AC), accettabile fino a decine di migliaia di segreti.


---

# Delta v1.5.8 — hotfix desanitize O(N) + cache fams + telemetria overhead

## Problema riscontrato in produzione
- Vault reale: **57.742 segreti**. La discovery-family di desanitize() ricalcolava
  la lista `fams` (una regex per ogni famiglia di tag) a OGNI chiamata: in prod
  l'overhead per turno risultava **80-90 ms** (misurato con header `x-proxy-overhead-ms`).
- Breakdown (profilazione su prod): pre≈0.5 ms, **post≈80 ms** — il costo era quasi
  tutto nella fase desanitize (ricompilazione delle N regex family per risposta).

## Fix (v1.5.8)
1. **Desanitize single-pass**: una sola regex combinata che include il separatore
   di famiglia (underscore finale incluso nel gruppo). Le famiglie scartate
   (non presenti in tag2secret) vengono gestite con un fallback zero-cost:
   niente piu' compattazione nel hot path. Benchmark locale: **0.09 ms vs 26.71 ms
   (300x)** sul caso peggiormente degradato; output identico al vecchio algoritmo
   (5/5 tag ripristinati, decoy intatto).
2. **Cache fams versionata** (`_fams_cache` + `_touch_fams()`): il set di famiglie
   viene ricostruito solo dopo una mutazione (mint/load/purge), non a ogni chiamata.
   Benchmark @57k tag: cold=14.23 ms (una volta), **warm=0.004-0.008 ms**.
   Invalidazione verificata su 7 punti mutazione.

## Risultato in produzione (header `x-proxy-overhead-ms` su /v1/chat/completions)
| versione | overhead per turno | note |
|---|---|---|
| v1.5.7 (baseline) | 80-90 ms | dominato da desanitize O(V) |
| **v1.5.8** | **0.45-0.61 ms** | ~170x piu' veloce; overhead ≈ 0.05% su risposta da 1 s |

## Nuova telemetria
- `x-proxy-overhead-ms`: aggiunto a OGNI risposta (GET e POST), sempre attivo:
  tempo totale aggiunto dal proxy a quella richiesta.
- `/admin/log-overhead` (v1.5.7/1.5.8): logging persistito del per-request overhead
  (attualmente disattivato in prod; la telemetria sull'header resta attiva).

## Nota igiene dati (trovata durante i test E2E su prod)
Nel vault prod residuano **14.937 segreti solo-cifre** ("0","00","000001",...) e
~150 token corti ("MI","RM","SRL","fax1"..."N","I","V") provenienti da import CSV
(colonne id/provincia ecc. selezionate come sensibili). Effetto: ogni testo in uscita
contenente cifre viene annidato con tag multipli (T2/T6b E2E su prod falliscono per
questo — comportamento pre-esistente alla 1.5.8, non causato dall'hotfix).
PURGE ESEGUITO (2026-09-04, OK Roby): rimossi 9.996 valori junk (1.822 cifre <=4, 9.755 codici 5-6 cifre, 234 token corti tipo province/SRL/fax, 2 residui E2E). Vault: 57.744 -> 47.749 segreti. PRESERVATE le 5.000 P.IVA a 11 cifre (dati reali). Backup: vault_backup_pre_purge_20260904_104059.txt. E2E su prod ora 7/7 PASSED (T6b replaced=0). Overhead post-purge: 0.55-0.86 ms/turno.
