"""CSV ingestion tests (v1.4.0-dev, goal g-e5ef4ce5).

Whole-list anonymization (e.g. a customer table extracted from Oracle):
  /csv/sanitize (OUT) and /csv/restore (IN), same auth as /sanitize,
  fail-safe (locked -> 503), deterministic tags, verbatim round-trip,
  limits (size/rows), multipart upload, delimiter option, header mode.
Zero secrets in logs/fixtures (synthetic data only).

Import-order note: pytest imports every test module at COLLECTION time.
The service module snapshots SECRETS_PROXY_* env at import, so who
imports first wins. This suite deliberately does NOT import `service`
at module level: it imports it lazily inside the autouse fixture and
monkeypatches the module globals (VAULT_PATH, KDF_SALT_PATH, CONFIG_PATH)
to a per-test temp dir, so it coexists with any suite that imported the
service before (order-independent, like test_open_mode's monkeypatching).
"""
import os
import sys
from types import SimpleNamespace

import pytest

# ensures the repo root is importable regardless of cwd
_REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if _REPO_ROOT not in sys.path:
    sys.path.insert(0, _REPO_ROOT)

PW = "Csv-T3st-Pass!"
SECRET_A = "Ex4mpl3-Csv-Pwd!42"        # synthetic, like the other suites
SECRET_B = "S3cond-Dataset#9"
CLIENT_TOKEN = "agent-token-csv-1"

from cryptography.fernet import Fernet          # noqa: E402
from fastapi.testclient import TestClient       # noqa: E402

SVC = None            # service module, bound per-test by the fixture


def _get_service():
    """Imports (or reuses) the service module without touching the
    process env when another suite already configured it."""
    if "service" in sys.modules:
        return sys.modules["service"]
    import tempfile
    _TMPDIR = tempfile.mkdtemp(prefix="sp_csv_test_")
    os.environ["SECRETS_PROXY_VAULT"] = os.path.join(_TMPDIR, "vault.txt")
    os.environ["SECRETS_PROXY_CONFIG"] = os.path.join(_TMPDIR, "service_config.json")
    os.environ["SECRETS_PROXY_API_KEY"] = "csv-test-admin"
    os.environ["SECRETS_PROXY_UPSTREAM"] = ""
    os.environ.pop("SECRETS_PROXY_KEY", None)
    import service            # noqa: F401
    return sys.modules["service"]


@pytest.fixture(autouse=True)
def sp(monkeypatch, tmp_path):
    """Per-test isolated service state (no env races, no module pollution)."""
    global SVC
    SVC = _get_service()
    from core import derive_key, load_or_create_salt
    monkeypatch.setattr(SVC, "VAULT_PATH", str(tmp_path / "vault.txt"))
    monkeypatch.setattr(SVC, "KDF_SALT_PATH", str(tmp_path / "vault.txt.salt"))
    monkeypatch.setattr(SVC, "CONFIG_PATH", str(tmp_path / "service_config.json"))
    SVC.san.lock()
    ns = SimpleNamespace(svc=SVC)
    ns.mk_vault = lambda enc=True: _make_vault(ns, enc)
    ns.unlock = lambda: _unlock(ns)
    ns.client = lambda: TestClient(SVC.app, raise_server_exceptions=False)
    yield ns
    SVC.san.lock()            # never leave an unlocked vault behind


# ------------------------------------------------------------ helpers
def _make_vault(sp_, encrypted: bool = True) -> None:
    from core import derive_key, load_or_create_salt
    svc = sp_.svc
    lines = [f"client:default={CLIENT_TOKEN}", SECRET_A, SECRET_B]
    data = ("\n".join(lines) + "\n").encode("utf-8")
    if encrypted:
        salt = load_or_create_salt(svc.KDF_SALT_PATH)
        data = Fernet(derive_key(PW, salt).encode()).encrypt(data)
    with open(svc.VAULT_PATH, "wb") as f:
        f.write(data)
    os.chmod(svc.VAULT_PATH, 0o600)


def _unlock(sp_) -> None:
    from core import derive_key, load_or_create_salt
    svc = sp_.svc
    salt = load_or_create_salt(svc.KDF_SALT_PATH)
    svc.san.load_vault(svc.VAULT_PATH, master_key=derive_key(PW, salt),
                       enforce_perms=True)


_CSV = (
    "R07_CD_CLIENTE,R07_RAGIONE_SOC,R07_CITTA,R07_PROVINCIA,R07_PARTITA_IVA,R07_TOKEN\n"
    "000002,Acme Sud Spa SNC,Milano,MI,"
    f"{SECRET_A},alpha\n"
    "000003,Beta Nord Srl,Torino,TO,"
    f"{SECRET_B},beta\n"
    "000004,Gamma Est Snc,Roma,RM,98765432101,gamma\n"
)

CSV_SEMI = _CSV.replace(",", ";")
AUTH = {"Authorization": f"Bearer {CLIENT_TOKEN}"}


def _post(sp, path, delim=",", csv_text=_CSV, **kw):
    payload = {"csv": csv_text, "header": True, "delimiter": delim}
    payload.update(kw)
    return sp.client().post(path, json=payload, headers=AUTH)


# ------------------------------------------------------------------ tests
def test_01_sanitize_restore_roundtrip_json(sp):
    """Full round-trip: secrets tagged on the way out, restored verbatim."""
    _make_vault(sp, encrypted=True)
    _unlock(sp)
    r = _post(sp, "/csv/sanitize")
    assert r.status_code == 200, r.text
    d = r.json()
    assert d["replaced"] == 2
    assert "Acme Sud Spa SNC" in d["csv"]          # non-secret cells verbatim
    assert SECRET_A not in d["csv"] and SECRET_B not in d["csv"]
    assert d["unresolved"] == []
    r2 = _post(sp, "/csv/restore", csv_text=d["csv"])
    assert r2.status_code == 200
    d2 = r2.json()
    assert d2["restored"] == 2 and d2["unresolved"] == []
    # verbatim: exact same rows as the original input
    assert d2["csv"] == _CSV


def test_02_on_missing_tag_whole_cells(sp):
    """on_missing='tag': long cells without secrets are tagged whole
    (privacy: the LLM only sees opaque tags), short codes stay clear."""
    _make_vault(sp, encrypted=False)
    _unlock(sp)
    r = _post(sp, "/csv/sanitize", on_missing="tag")
    assert r.status_code == 200
    d = r.json()
    assert d["tagged_cells"] >= 2      # company names + cities
    assert "Acme Sud Spa SNC" not in d["csv"]
    assert "Milano" not in d["csv"] and "Torino" not in d["csv"]
    assert "MI" in d["csv"]            # 2-char province (< min) stays clear
    # restore: verbatim round-trip
    r2 = _post(sp, "/csv/restore", csv_text=d["csv"])
    assert r2.json()["csv"] == _CSV


def test_03_auth_enforced(sp):
    """/csv/* require the client token (same as /sanitize)."""
    _make_vault(sp, encrypted=False)
    _unlock(sp)
    c = sp.client()
    assert c.post("/csv/sanitize", json={"csv": _CSV}).status_code == 401
    assert c.post("/csv/restore", json={"csv": _CSV}).status_code == 401


def test_04_failsafe_locked(sp):
    """Locked vault: 503, never process the data (fail-safe)."""
    _make_vault(sp, encrypted=False)
    c = sp.client()
    assert _post(sp, "/csv/sanitize").status_code == 503
    assert _post(sp, "/csv/restore").status_code == 503


def test_05_multipart_upload(sp):
    """multipart/form-data upload: same behavior as the JSON path."""
    _make_vault(sp, encrypted=False)
    _unlock(sp)
    import io
    files = {"file": ("r07_clienti.csv", io.BytesIO(_CSV.encode()), "text/csv")}
    r = sp.client().post("/csv/sanitize", files=files,
                         data={"on_missing": "keep", "header": "true"},
                         headers=AUTH)
    assert r.status_code == 200, r.text
    d = r.json()
    assert d["rows"] == 4 and d["replaced"] == 2
    assert SECRET_A not in d["csv"]


def test_06_size_limits(sp):
    """Oversized CSV -> 413; too many rows -> 413."""
    _make_vault(sp, encrypted=False)
    _unlock(sp)
    c = sp.client()
    big = "h1,h2\n" + "x" * (sp.svc.CSV_MAX_BYTES + 10) + ",y\n"
    assert c.post("/csv/sanitize", json={"csv": big},
                  headers=AUTH).status_code == 413
    many = "h\n" + "row\n" * (sp.svc.CSV_MAX_ROWS + 2)
    assert c.post("/csv/sanitize", json={"csv": many},
                  headers=AUTH).status_code == 413


def test_07_delimiter_semicolon(sp):
    """Delimiter option: sanitize/restore on a ;-separated file."""
    _make_vault(sp, encrypted=False)
    _unlock(sp)
    r = sp.client().post("/csv/sanitize",
                         json={"csv": CSV_SEMI, "delimiter": ";"},
                         headers=AUTH)
    assert r.status_code == 200
    d = r.json()
    assert d["rows"] == 4 and d["replaced"] == 2
    assert SECRET_A not in d["csv"] and SECRET_B not in d["csv"]
    r2 = sp.client().post("/csv/restore",
                          json={"csv": d["csv"], "delimiter": ";"},
                          headers=AUTH)
    assert r2.status_code == 200
    assert r2.json()["csv"] == CSV_SEMI


def test_08_bad_input(sp):
    """Malformed payload -> 400 (never a 500)."""
    _make_vault(sp, encrypted=False)
    _unlock(sp)
    c = sp.client()
    r = c.post("/csv/sanitize", data="not json",
               headers={**AUTH, "Content-Type": "application/json"})
    assert r.status_code == 400
    r = c.post("/csv/sanitize", json={"csv": "a,b\nc,d", "delimiter": ";;"},
               headers=AUTH)
    assert r.status_code == 400
    r = c.post("/csv/sanitize", json={"csv": "   "}, headers=AUTH)
    assert r.status_code == 400


def test_09_core_cache_and_determinism():
    """Same value in many rows -> ONE tag derivation, same tag everywhere
    (deterministic per value)."""
    from core import Sanitizer
    s = Sanitizer()
    s.load_from_lists([])
    rows = [["id", "name"], ["1", "Long Company Name Alpha"],
            ["2", "Long Company Name Alpha"], ["3", "Other Company Beta"]]
    out, replaced, tagged = s.sanitize_rows(rows, on_missing="tag")
    assert tagged == 3 and replaced == 0
    t1 = out[1][1]
    assert t1 == out[2][1] and t1.startswith("PWD_")
    assert out[3][1] != t1
    back, restored, un = s.restore_rows(out)
    assert back == rows and un == []


def test_10_cell_threshold_and_exact_first(sp):
    """Threshold semantics: cells >= SENSITIVE_CELL_MIN without a secret
    are tagged (listone mode); exact secret match ALWAYS wins, shorter
    cells stay clear."""
    from core import Sanitizer
    s = Sanitizer()
    s.load_from_lists(["short-pwd"], salt=b"0123456789abcdef")
    rows = [["ID", "NOTE"], ["1", "short-pwd"], ["2", "IT"], ["3", "81020"]]
    out, replaced, tagged = s.sanitize_rows(rows, on_missing="tag")
    assert replaced == 1 and tagged == 1
    assert out[1][1].startswith("PWD_")     # exact secret wins
    assert out[2][1] == "IT"                # 2 chars < min -> stays clear
    assert out[3][1].startswith("PWD_")     # 5 chars >= min -> tagged
    back, restored, un = s.restore_rows(out)
    assert back == rows and un == []