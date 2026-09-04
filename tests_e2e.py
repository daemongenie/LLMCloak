#!/usr/bin/env python3
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

"""LLMCloak E2E suite (v1.5.5). Run on the VM: python3 tests_e2e.py
Requires vault passphrase in VAULT_PW env (default SENTINEL_VM_PASSWORD) and a
client token line 'client:<name>=<token>' in the vault (default dextest)."""
import json, os, sys, urllib.request, urllib.error, urllib.parse, uuid

BASE = os.environ.get('BASE', 'http://127.0.0.1:8917')
PW = os.environ.get('VAULT_PW', 'SENTINEL_VM_PASSWORD')
TOK = os.environ.get('VAULT_TOKEN_NAME', 'dextest')

def _tok():
    # resolve the token VALUE from the vault (bearer = value, not the name)
    import core, dashboard as dash
    salt = core.load_or_create_salt(os.path.join(os.path.dirname(os.path.abspath(__file__)), "vault.txt.salt"))
    key = core.derive_key(os.environ.get('VAULT_PW','SENTINEL_VM_PASSWORD'), salt)
    lines, _ = dash.vault_lines(os.path.join(os.path.dirname(os.path.abspath(__file__)), "vault.txt"), key)
    want = TOK if TOK.startswith('client:') else 'client:' + TOK
    for l in lines:
        st = l.strip()
        if st.startswith(want + '='):
            return st.split('=',1)[1]
    raise SystemExit('token line not found: ' + want)

def post(path, body, token=None):
    h = {'Content-Type': 'application/json'}
    if token:
        h['Authorization'] = 'Bearer ' + token
    req = urllib.request.Request(BASE+path, data=json.dumps(body).encode(), headers=h)
    try:
        with urllib.request.urlopen(req, timeout=10) as r:
            return r.code, json.loads(r.read())
    except urllib.error.HTTPError as e:
        return e.code, json.loads(e.read() or b'{}')

def dash_session():
    h = {'Content-Type': 'application/json'}
    req = urllib.request.Request(BASE+'/dashboard/api/session',
                                 data=json.dumps({'passphrase': PW}).encode(), headers=h)
    with urllib.request.urlopen(req, timeout=10) as r:
        return r.headers.get('Set-Cookie','').split(';')[0]

def dash_csv(cookie, tmpfile, **fields):
    boundary = '----E2E' + uuid.uuid4().hex
    body = b''
    for k, v in fields.items():
        body += (f'--{boundary}\r\nContent-Disposition: form-data; name="{k}"\r\n\r\n{v}\r\n').encode()
    data = open(tmpfile,'rb').read()
    body += (f'--{boundary}\r\nContent-Disposition: form-data; name="file"; filename="{os.path.basename(tmpfile)}"\r\n'
             'Content-Type: text/csv\r\n\r\n').encode() + data + b'\r\n'
    body += (f'--{boundary}--\r\n').encode()
    req = urllib.request.Request(BASE+'/dashboard/api/csv', data=body, headers={
        'Cookie': cookie, 'Content-Type': f'multipart/form-data; boundary={boundary}'})
    with urllib.request.urlopen(req, timeout=15) as r:
        return json.loads(r.read())

def get(path):
    with urllib.request.urlopen(BASE+path, timeout=10) as r:
        return json.loads(r.read())

def main():
    cookie = dash_session()
    h = get('/health')
    print('health:', h.get('status'), '| secrets:', h.get('secrets'), '| named:', h.get('named'))
    assert h.get('status') == 'active'

    marker = 'E2E-' + uuid.uuid4().hex[:8].upper()
    cell = f'000001-{marker} SPA'
    # T1 seed via ingest (delimiter=auto path, v1.5.4)
    csv_path = '/tmp/e2e_seed.csv'
    open(csv_path,'w').write(f'id;ragione_sociale\n99;{cell}\n')
    res = dash_csv(cookie, csv_path, mode='ingest', delimiter='auto')
    print('T1 ingest delimiter=auto:', {k: res.get(k) for k in ('added','delimiter')})
    assert res.get('added',0) >= 1
    # T2 egress on the single cell (the Roby repro)
    code, r = post('/sanitize', {'text': cell}, token=_tok())
    print('T2 egress cell:', r.get('text'), '| replaced:', r.get('replaced'))
    assert r.get('replaced') == 1 and marker not in r.get('text','')
    # T3 restore roundtrip
    code, r2 = post('/desanitize', {'text': r['text']}, token=_tok())
    print('T3 restore:', r2.get('text'), '| restored:', r2.get('restored'))
    assert r2.get('text') == cell
    # T4 clean text untouched
    code, r3 = post('/sanitize', {'text':'Write a poem about the sea.'}, token=_tok())
    assert r3.get('replaced') == 0
    print('T4 clean text untouched: OK')
    # T5 invalid delimiter -> 400 on /csv/sanitize
    code, _ = post('/csv/sanitize', {'csv': 'a;b\n1;2', 'delimiter': 'ab'}, token=_tok())
    print('T5 invalid delimiter ->', code); assert code == 400
    # T6 purge: remove the seeded values from the vault (exact whole-cell)
    res = dash_csv(cookie, csv_path, mode='purge', delimiter='auto')
    print('T6 purge:', {k: res.get(k) for k in ('rows', 'cells', 'purged', 'kept')})
    assert res.get('purged', 0) >= 1
    # T6b egress no longer filters the purged value
    code, r4 = post('/sanitize', {'text': cell}, token=_tok())
    print('T6b after purge:', r4.get('text'), '| replaced:', r4.get('replaced'))
    assert r4.get('replaced') == 0
    # T7 guard: a CSV cell matching a named entry -> 400, vault untouched
    prot_path = '/tmp/e2e_prot.csv'
    open(prot_path, 'w').write('v\nclient:' + TOK + '=' + _tok() + '\n')
    code7 = 0
    try:
        dash_csv(cookie, prot_path, mode='purge', delimiter='auto')
    except urllib.error.HTTPError as e:
        code7 = e.code
    print('T7 protected guard ->', code7); assert code7 == 400
    # cleanup: remove E2E values from the vault (marker cell + bare id cell)
    import core, dashboard as dash
    salt = core.load_or_create_salt(os.path.join(os.path.dirname(os.path.abspath(__file__)), "vault.txt.salt"))
    key = core.derive_key(os.environ.get('VAULT_PW','SENTINEL_VM_PASSWORD'), salt)
    VP = os.path.join(os.path.dirname(os.path.abspath(__file__)), "vault.txt")
    lines, enc = dash.vault_lines(VP, key)
    keep = [l for l in lines if 'E2E-' not in l and l.strip() != '99']
    print('cleanup: removed', len(lines)-len(keep))
    dash.persist_vault(VP, keep, key, encrypt=True)
    post('/vault/reload', {}, token=_tok())
    h = get('/health')
    print('post-cleanup secrets:', h.get('secrets'))
    print('E2E PASSED')

if __name__ == '__main__':
    main()
