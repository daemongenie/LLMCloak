
# LLMCloak — Benchmark v1.5.7

pyahocorasick available: **YES** — Python 3.9.2

### A. sanitize() — 2 KB text, latency vs vault size

| scenario | iter | p50 | p95 | p99 |
|---|---|---|---|---|
| 100 secrets — AC active | 300 |       48 us |       57 us |       74 us |
| 1,000 secrets — AC active | 300 |       49 us |       51 us |       63 us |
| 10,000 secrets — AC active | 300 |       49 us |       51 us |       65 us |
|---|---|---|---|---|
| 100 secrets — fallback without AC | 300 |       88 us |       93 us |      145 us |
| 1,000 secrets — fallback without AC | 300 |      704 us |      759 us |      811 us |
| 10,000 secrets — fallback without AC | 222 |     6.98 ms |     7.26 ms |     7.76 ms |

### B. sanitize() — 1,000-secret vault, latency vs text size

| scenario | iter | p50 | p95 | p99 |
|---|---|---|---|---|
| 0.2 KB text — AC active | 300 |       25 us |       25 us |       38 us |
| 0.2 KB text — fallback | 300 |      387 us |      431 us |      507 us |
| 2 KB text — AC active | 300 |       50 us |       52 us |       85 us |
| 2 KB text — fallback | 300 |      717 us |      758 us |      784 us |
| 20 KB text — AC active | 300 |      290 us |      329 us |      364 us |
| 20 KB text — fallback | 300 |     4.52 ms |     4.66 ms |     5.01 ms |
| 200 KB text — AC active | 300 |     2.71 ms |     3.03 ms |     3.21 ms |
| 200 KB text — fallback | 33 |    45.19 ms |    45.75 ms |    45.84 ms |

### C. desanitize() — 2 KB text, impact of the discovery family on the number of minted tags

| scenario | iter | p50 | p95 | p99 |
|---|---|---|---|---|
|     10 tags in session | 300 |       77 us |       80 us |      108 us |
|  1,000 tags in session | 300 |      838 us |      897 us |      974 us |
| 10,000 tags in session | 175 |     8.11 ms |     8.49 ms |     8.79 ms |

### D. StreamDesanitizer (SSE) — 100 KB text, 256 B chunks

| scenario | iter | p50 | p95 | p99 |
|---|---|---|---|---|
| stream restore (5 tags) — 31.88 MB/s | 300 |     3.06 ms |     3.14 ms |     3.36 ms |

### E. sanitize_rows() — CSV 1,000 rows x 5 columns

| scenario | iter | p50 | p95 | p99 |
|---|---|---|---|---|
| batch sanitize (per-value cache active) | 3 |     1.98 s |     1.99 s |     1.99 s |

### F. Overhead added by the proxy per chat turn (2 KB text, 1,000-secret vault)

| component | iter | p50 | p95 | p99 |
|---|---|---|---|---|
| sanitize (request -> LLM) | 300 |       49 us |       51 us |       53 us |
| desanitize (response -> client) | 300 |      456 us |      508 us |      553 us |
| **TOTAL added per turn** | — | **     506 us** | — | — |

On a 1,000 ms LLM response the overhead is **0.1%**; on 3,000 ms it is **0.0%**.

### G. Loading a 10,000-secret vault (including the Aho-Corasick build)

| metric | value |  |  |  |
|---|---|---|---|---|
| load_from_lists() 10k |   153.31 ms | | | |
| Sanitizer RAM (current/peak) | 4.2 / 6.8 MB | | | |

## Reading the results

1. **pyahocorasick is the dominant factor.** Without the module, sanitize()
   performs a `str.count()` for EVERY secret in the vault: O(V·n) cost. With the
   module the scan is a single O(n) pass. At 10k secrets the difference is
   orders of magnitude. ACTION: run `pip install pyahocorasick` on the
   production VM (the code already uses it when present).
2. **desanitize() scales with the number of minted tags** (discovery family:
   one regex per tag2secret key per call). With very large CSV imports the
   discovery cost matters; staying under ~10k tags/session is fine.
   A {family: set(tags)} index would remove the cost (future improvement).
3. **The per-chat-turn overhead (F)** is negligible compared to typical
   LLM latency (>1 s) when AC is active.
4. **The SSE stream (D)** restores in real time with a wide margin
   compared to LLM token speed (tens of MB/s vs ~KB/s).
5. **Vault loading (G)** is a one-off cost per session (AC build),
   acceptable up to tens of thousands of secrets.


---

# Delta v1.5.8 — desanitize O(N) hotfix + fams cache + overhead telemetry

## Problem found in production
- Real vault: **57,742 secrets**. The desanitize() discovery-family recomputed
  the `fams` list (one regex per tag family) at EVERY call: in prod the
  per-turn overhead was **80-90 ms** (measured with the `x-proxy-overhead-ms` header).
- Breakdown (profiling on prod): pre≈0.5 ms, **post≈80 ms** — the cost was almost
  entirely in the desanitize stage (recompiling the N family regexes per response).

## Fix (v1.5.8)
1. **Desanitize single-pass**: a single combined regex that includes the family
   separator (the trailing underscore inside the group). Discarded families
   (not present in tag2secret) are handled with a zero-cost fallback:
   no more compaction in the hot path. Local benchmark: **0.09 ms vs 26.71 ms
   (300x)** on the worst degraded case; output identical to the old algorithm
   (5/5 tags restored, decoy intact).
2. **Versioned fams cache** (`_fams_cache` + `_touch_fams()`): the set of families
   is rebuilt only after a mutation (mint/load/purge), not on every call.
   Benchmark @57k tags: cold=14.23 ms (once), **warm=0.004-0.008 ms**.
   Invalidation verified at 7 mutation points.

## Result in production (header `x-proxy-overhead-ms` on /v1/chat/completions)
| version | overhead per turn | notes |
|---|---|---|
| v1.5.7 (baseline) | 80-90 ms | dominated by O(V) desanitize |
| **v1.5.8** | **0.45-0.61 ms** | ~170x faster; overhead ≈ 0.05% on a 1 s response |

## New telemetry
- `x-proxy-overhead-ms`: added to EVERY response (GET and POST), always active:
  total time added by the proxy to that request.
- `/admin/log-overhead` (v1.5.7/1.5.8): persisted logging of per-request overhead
  (currently disabled in prod; the header telemetry stays active).

## Data hygiene note (found during E2E tests on prod)
The prod vault still contains **14,937 digits-only secrets** ("0","00","000001",...) and
~150 short tokens ("MI","RM","SRL","fax1"..."N","I","V") coming from CSV imports
(id/province columns etc. selected as sensitive). Effect: any outgoing text
containing digits gets nested with multiple tags (T2/T6b E2E on prod fail for
this reason — behaviour pre-existing to 1.5.8, not caused by the hotfix).
PURGE DONE (2026-09-04, OK Roby): removed 9,996 junk values (1,822 digits <=4, 9,755 5-6 digit codes, 234 short tokens like provinces/SRL/fax, 2 E2E leftovers). Vault: 57,744 -> 47,749 secrets. The 5,000 11-digit VAT numbers (real data) were PRESERVED. Backup: vault_backup_pre_purge_20260904_104059.txt. E2E on prod now 7/7 PASSED (T6b replaced=0). Post-purge overhead: 0.55-0.86 ms/turn.

---

LLMCloak — Copyright 2026 Quantum Sphere EOOD. Licensed under the Apache License, Version 2.0 (see LICENSE).
