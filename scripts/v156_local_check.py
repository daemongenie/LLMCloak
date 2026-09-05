#!/usr/bin/env python3
# -*- coding: utf-8 -*-
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

# STANDALONE SCRIPT — run directly: python3 scripts/v156_local_check.py
# NOT part of the pytest suite (module-level code would fail under pytest collection).

"""Functional test v1.5.6 (CSV import history + per-import rollback).

Expectations derived from the REAL service semantics (v1.5.6):
  - ingest: header excluded; EVERY distinct cell (even numeric ids) becomes
    a vault value; protected (#/re:/named/ing:) -> skipped.
  - sanitize+persist (like the UI): on_missing=tag + selected columns;
    cells < SENSITIVE_CELL_MIN(4) NOT tagged; header never tagged;
    an already-known (exact) value generates neither persist nor record.
  - history API: newest-first (last import on top); registry append-order.
  - rollback: removes the record rows; a value shared with a previous
    import stays; protected (#/re:/named) never touched.
Setup: temporary encrypted vault + TestClient.
Scenarios:
  T1  ingest CSV #1  -> added=5, skipped=1, record in the history
  T1b ingest CSV #2 (value shared with #1) -> added=3, skipped=1
  T2  sanitize+persist (column 1, on_missing=tag like the UI) -> persisted=1
  T3  GET /csv/history -> newest-first, correct file/added
  T4  DELETE import#2 (orders) -> removed=3: '7','8',GAMMA go out;
      ALFA (shared with #1) and DELTA stay
  T5  DELETE import#1 (customers) -> removed=5: ALFA+BETA+ids go out
  T6  egress after rollback: ALFA/GAMMA no longer filter; DELTA still does
  T7  remaining history = [codici.csv]; DELETE unknown id -> 404
  T8  protected never touched (named/regex/comment stay)
  T9  sanitize+persist with no new values -> no record (no noise)
  T10 registry encrypted on disk (Fernet magic), 0600
  T11 ingest protected cells -> added=5 ('1'-'4'+EPS-9), skipped=3;
      rollback -> removed=5 (numeric cells go out too)
  T12 purge -> purged=1 (only DELTA), NO record in the history
STANDALONE SCRIPT — run directly: python3 scripts/v156_local_check.py (NOT part of the pytest suite)
"""
import os, sys, shutil

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
os.chdir(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

TMP = '/tmp/llmcloak_v156'
if os.path.exists(TMP):
    shutil.rmtree(TMP)
os.makedirs(TMP, exist_ok=True)
os.environ['LLMCLOAK_VAULT'] = TMP + '/vault.txt'
os.environ['LLMCLOAK_SALT'] = TMP + '/vault.txt.salt'

import core
import dashboard as dash

SALT_PATH = TMP + '/vault.txt.salt'
VAULT_PATH = TMP + '/vault.txt'
salt = core.load_or_create_salt(SALT_PATH)
key = core.derive_key('SENTINEL_VM_PASSWORD', salt)
NAMED = 'client:dextest=SECRET-CLIENT-TOKEN-123'
START = [NAMED, 're:(?i)(api[_-]?key)', '# keep-me', 'Marco Rossi']
dash.persist_vault(VAULT_PATH, START, key, encrypt=True)

svc = __import__('importlib').import_module('service')
svc.VAULT_PATH = VAULT_PATH
svc.KDF_SALT_PATH = SALT_PATH
svc.IMPORTS_PATH = VAULT_PATH + '.imports'
svc.san.load_vault(VAULT_PATH, master_key=key, enforce_perms=False, salt=salt)
print('san loaded:', svc.san.is_loaded(), '| secrets:', len(svc.san.secrets))

from fastapi.testclient import TestClient
client = TestClient(svc.app)
r = client.post('/dashboard/api/session', json={'passphrase': 'SENTINEL_VM_PASSWORD'})
assert r.status_code == 200, r.text
cookie = dict(r.cookies)
print('login OK')

def vault_lines():
    return [l.strip() for l in dash.vault_lines(VAULT_PATH, key)[0] if l.strip()]

def dash_csv(mode, csv_text, delimiter='auto', header='true', persist=None,
             columns=None, fname='t.csv', on_missing='tag'):
    data = {'mode': mode, 'delimiter': delimiter, 'header': header,
            'on_missing': on_missing}
    if persist is not None:
        data['persist'] = persist
    if columns is not None:
        data['columns'] = columns
    r = client.post('/dashboard/api/csv',
                    files={'file': (fname, csv_text.encode(), 'text/csv')},
                    data=data, cookies=cookie)
    return r

def hist():
    r = client.get('/dashboard/api/csv/history', cookies=cookie)
    assert r.status_code == 200, r.text
    return r.json()['imports']

def rec(fname):
    m = [x for x in hist() if x['file'] == fname]
    assert len(m) == 1, (fname, hist())
    return m[0]

# --- T1: ingest CSV #1: celle distinte = 99,100,101,ALFA,BETA,MarcoRossi -
# Marco Rossi already known -> skipped=1; everything else (even ids) enters.
csv1 = 'id;ragione_sociale\n99;E2E-ALFA-1\n100;E2E-BETA-2\n101;Marco Rossi\n'
r = dash_csv('ingest', csv1, fname='clienti.csv')
j = r.json()
print('T1 ingest #1 ->', r.status_code, {k: j.get(k) for k in ('added', 'skipped')})
assert r.status_code == 200 and j['added'] == 5 and j['skipped'] == 1
h = hist()
assert len(h) == 1 and h[0]['file'] == 'clienti.csv' and h[0]['added'] == 5
ID1 = h[0]['id']
assert ID1
print('T1 record:', h[0])

# --- T1b: ingest CSV #2: new cells 7,8,GAMMA; ALFA shared -> skipped
csv2 = 'id;nome\n7;E2E-GAMMA-3\n8;E2E-ALFA-1\n'
r = dash_csv('ingest', csv2, fname='ordini.csv')
j = r.json()
print('T1b ingest #2 ->', j['added'], j['skipped'])
assert j['added'] == 3 and j['skipped'] == 1
ID2 = rec('ordini.csv')['id']
assert ID2 != ID1
vl = vault_lines()
assert 'E2E-ALFA-1' in vl and 'E2E-BETA-2' in vl and 'E2E-GAMMA-3' in vl

# --- T2: sanitize+persist LIKE THE UI (on_missing=tag, columns=1) --------
# header keep; '1' (<4 char, column not selected) stays; DELTA col1
# selected -> force tag -> 1 new original into the vault -> persisted=1.
csv3 = 'id;codice\n1;E2E-DELTA-4\n'
r = dash_csv('sanitize', csv3, persist='true', columns='1', fname='codici.csv')
j = r.json()
print('T2 sanitize+persist -> tagged:', j.get('tagged_cells'),
      'persisted:', j.get('persisted'))
assert j.get('persisted', 0) == 1 and j.get('tagged_cells') == 1
ID3 = rec('codici.csv')['id']
assert hist()[0]['file'] == 'codici.csv'
assert any('E2E-DELTA-4' in l for l in vault_lines())

# --- T3: full list (newest-first) ----------------------------------------
h = hist()
assert [x['file'] for x in h] == ['codici.csv', 'ordini.csv', 'clienti.csv']
assert all(x['id'] and x['ts'] for x in h)
print('T3 history (newest first) ->', [(x['file'], x['added']) for x in h])

# --- T4: DELETE import #2 (orders) -> GAMMA+7+8 go out, ALFA stays --------
# orders record: vals=['7','8','E2E-GAMMA-3']; no sharing with the previous
# records (ALFA had been added by clienti.csv, not by ordini)
r = client.delete('/dashboard/api/csv/history/' + ID2, cookies=cookie)
j = r.json()
print('T4 delete ordini ->', r.status_code, j)
assert r.status_code == 200 and j['removed'] == 3 and j['skipped'] == 0
vl = vault_lines()
assert 'E2E-GAMMA-3' not in vl and '7' not in vl and '8' not in vl
assert 'E2E-ALFA-1' in vl and 'E2E-BETA-2' in vl and 'E2E-DELTA-4' in vl

# --- T5: DELETE import #1 (customers) -> its 5 values go out --------------
r = client.delete('/dashboard/api/csv/history/' + ID1, cookies=cookie)
j = r.json()
print('T5 delete clienti ->', r.status_code, j)
assert r.status_code == 200 and j['removed'] == 5 and j['skipped'] == 0
vl = vault_lines()
assert 'E2E-ALFA-1' not in vl and 'E2E-BETA-2' not in vl
assert '99' not in vl and '100' not in vl and '101' not in vl
assert 'E2E-DELTA-4' in vl

# --- T6: egress after rollback --------------------------------------------
for v in ('E2E-ALFA-1', 'E2E-GAMMA-3'):
    rr = client.post('/sanitize', json={'text': 'contatto ' + v},
                     headers={'Authorization': 'Bearer SECRET-CLIENT-TOKEN-123'})
    jj = rr.json()
    print('T6 egress', v, '-> replaced:', jj['replaced'])
    assert jj['replaced'] == 0
# value still in vault -> filtered
rr = client.post('/sanitize', json={'text': 'codice E2E-DELTA-4 ok'},
                 headers={'Authorization': 'Bearer SECRET-CLIENT-TOKEN-123'})
assert rr.json()['replaced'] == 1
print('T6 remaining value still filtered: OK')

# --- T7: remaining history + 404 on unknown id ------------------------------
h = hist()
assert [x['file'] for x in h] == ['codici.csv']
r = client.delete('/dashboard/api/csv/history/nope', cookies=cookie)
print('T7 delete unknown ->', r.status_code)
assert r.status_code == 404

# --- T8: protected mai toccate --------------------------------------------
vl = vault_lines()
assert NAMED in vl
assert any(l.startswith('re:') for l in vl)
assert any(l.startswith('#') for l in vl)
assert 'Marco Rossi' in vl
print('T8 protected intact: OK')

# --- T9: sanitize+persist with no new values -> no record ------------------
# 'Marco Rossi' is already in the vault: replaced yes, persisted=0, no record.
r = dash_csv('sanitize', 'id;nome\n2;Marco Rossi\n', persist='true',
             columns='1', fname='noto.csv')
assert r.json().get('persisted', 0) == 0
assert len(hist()) == 1
print('T9 no-noise: OK')

# --- T10: registry encrypted + perms ----------------------------------------
raw = open(svc.IMPORTS_PATH, 'rb').read()
assert raw.startswith(b'gAAAAA') or raw == b''
st = os.stat(svc.IMPORTS_PATH)
assert st.st_mode & 0o777 == 0o600, oct(st.st_mode & 0o777)
print('T10 registry encrypted+0600:', raw[:6], oct(st.st_mode & 0o777))

# --- T11: protected cells in the ingest -> skipped, numbers+EPS-9 enter ----
csvp = 'id;x\n1;#cmt\n2;re:abc\n3;client:foo=bar\n4;E2E-EPS-9\n'
r = dash_csv('ingest', csvp, fname='prot.csv')
j = r.json()
print('T11 ingest prot ->', j['added'], j['skipped'])
assert j['added'] == 5 and j['skipped'] == 3
assert hist()[0]['file'] == 'prot.csv' and hist()[0]['added'] == 5
vl = vault_lines()
assert not any('client:foo=bar' in l for l in vl)  # protected -> skipped
assert 'E2E-EPS-9' in vl and '1' in vl and '4' in vl
# rollback -> all 5 recorded rows go out (none shared)
IDP = rec('prot.csv')['id']
r = client.delete('/dashboard/api/csv/history/' + IDP, cookies=cookie)
j = r.json()
assert j['removed'] == 5 and j['skipped'] == 0
vl = vault_lines()
assert 'E2E-EPS-9' not in vl
assert '1' not in vl and '2' not in vl and '3' not in vl and '4' not in vl
print('T11 protected cells skipped: OK')

# --- T12: purge does NOT record (only DELTA matches the vault) --------------
r = dash_csv('purge', 'id;codice\n1;E2E-DELTA-4\n', fname='p.csv')
j = r.json()
print('T12 purge -> purged:', j['purged'])
assert j['purged'] == 1
assert len(hist()) == 1
print('T12 purge does not record: OK')

print('ALL v1.5.6 FUNCTIONAL TESTS PASSED')