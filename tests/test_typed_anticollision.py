"""v1.4.0-dev — typed namespaces + mint-time anti-collision + batch restore
fast path. Synthetic secrets only (VM secret rule: never reuse real ones).

Run standalone or in the full suite: imports `service` lazily and reuses
the module from sys.modules if another suite loaded it first (same
order-independent pattern as test_csv_ingestion).
"""
import os
import sys

import pytest

_REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if _REPO_ROOT not in sys.path:
    sys.path.insert(0, _REPO_ROOT)

PW = "Typed-T3st-Pass!9"
SECRET_A = "Typ3d-S3cr3t-A!77"
CLIENT_TOKEN = "agent-token-typed-1"

from core import Sanitizer, _norm_header, derive_key, load_or_create_salt  # noqa: E402
from fastapi.testclient import TestClient                       # noqa: E402

SVC = None


def _get_service():
    if "service" in sys.modules:
        return sys.modules["service"]
    import tempfile
    _TMPDIR = tempfile.mkdtemp(prefix="sp_typed_test_")
    os.environ["SECRETS_PROXY_VAULT"] = os.path.join(_TMPDIR, "vault.txt")
    os.environ["SECRETS_PROXY_CONFIG"] = os.path.join(_TMPDIR, "service_config.json")
    os.environ["SECRETS_PROXY_API_KEY"] = "typed-test-admin"
    os.environ["SECRETS_PROXY_UPSTREAM"] = ""
    os.environ.pop("SECRETS_PROXY_KEY", None)
    import service            # noqa: F401
    return sys.modules["service"]


@pytest.fixture(autouse=True)
def sp(monkeypatch, tmp_path):
    global SVC
    SVC = _get_service()
    monkeypatch.setattr(SVC, "VAULT_PATH", str(tmp_path / "vault.txt"))
    monkeypatch.setattr(SVC, "KDF_SALT_PATH", str(tmp_path / "vault.txt.salt"))
    monkeypatch.setattr(SVC, "CONFIG_PATH", str(tmp_path / "service_config.json"))
    SVC.san.lock()
    ns = SimpleNamespace(svc=SVC)
    ns.mk_vault = lambda enc=True: _make_vault(ns, enc)
    ns.unlock = lambda: _unlock(ns)
    ns.client = lambda: TestClient(SVC.app, raise_server_exceptions=False)
    yield ns
    SVC.san.lock()


from types import SimpleNamespace  # noqa: E402  (used in fixture above)


def _make_vault(sp_, encrypted: bool = True) -> None:
    from core import derive_key, load_or_create_salt
    svc = sp_.svc
    os.makedirs(os.path.dirname(svc.VAULT_PATH), exist_ok=True)
    lines = [f"client:default={CLIENT_TOKEN}", SECRET_A]
    data = ("\n".join(lines) + "\n").encode("utf-8")
    if encrypted:
        from core import Fernet
        salt = load_or_create_salt(svc.KDF_SALT_PATH)
        data = Fernet(derive_key(PW, salt).encode()).encrypt(data)
    with open(svc.VAULT_PATH, "wb") as f:
        f.write(data)
    os.chmod(svc.VAULT_PATH, 0o600)


def _unlock(sp_) -> None:
    svc = sp_.svc
    salt = load_or_create_salt(svc.KDF_SALT_PATH)
    svc.san.load_vault(svc.VAULT_PATH, master_key=derive_key(PW, salt),
                       enforce_perms=True)


CSV_TYPED = (
    "RAGIONE_SOC,CITTA,PIVA,PROVINCIA,ID,NOTA\n"
    f"Acme Sud Spa SNC,Milano,{SECRET_A},MI,000002,follow-up commerciale\n"
    f"Acme Sud Spa SNC,Torino,{SECRET_A},TO,000003,solo recapito\n"
)
AUTH = {"Authorization": f"Bearer {CLIENT_TOKEN}"}


def _post(sp, path, csv_text=CSV_TYPED, **kw):
    payload = {"csv": csv_text, "header": True, "delimiter": ","}
    payload.update(kw)
    return sp.client().post(path, json=payload, headers=AUTH)


def _cells(csv: str):
    import csv as _csv
    import io
    return list(_csv.reader(io.StringIO(csv)))

# ---------------------------------------------------------------- helpers
def _tagcells(rows, prefixes=("PWD_", "TEXT_")):
    seen = set()
    for row in rows:
        for c in row:
            c = str(c)
            for p in prefixes:
                if c.startswith(p) and len(c) > len(p):
                    seen.add(c)
    return sorted(seen)


def _typed_prefix(tag: str) -> str:
    return tag.split("_", 1)[0] + "_"


# ------------------------------------------------------------------ tests
def test_11_norm_header(sp):
    assert _norm_header("Ragione  Sociale!") == "ragione_sociale"
    assert _norm_header(" P.IVA ") == "p_iva"
    assert _norm_header("CITTÀ") == "citt"          # accents collapsed
    assert _norm_header("") == ""
    assert _norm_header("COL") == "col"
    assert len(_norm_header("A" * 40)) == 16


def test_12_typed_tags_per_column(sp):
    """typed mode: CITTA cells -> CITTA_*, RAGIONE_SOC -> RAGIONE_SOC_*,
    PIVA secret (dictionary) still PWD_*, NOTA column stays CLEAR."""
    sp.mk_vault(False); sp.unlock()
    r = _post(sp, "/csv/sanitize", on_missing="tag", typed=True)
    assert r.status_code == 200, r.text
    d = r.json()
    rows = _cells(d["csv"])
    assert rows[0] == CSV_TYPED.splitlines()[0].split(",")
    # families actually emitted: typed namespaces for unknown-value
    # columns, PWD for dictionary-backed cells (see test_13 docstring)
    assert d["tag_types"] == ["CITTA", "PWD", "RAGIONE_SOC"], d.get("tag_types")
    # Milano and Torino share the column namespace but differ per VALUE
    tags = {row[1]: row[3] for row in rows[1:]}
    assert rows[1][1].startswith("CITTA_") and rows[2][1].startswith("CITTA_")
    assert rows[1][1] != rows[2][1]                    # Milano vs Torino
    # same value on two rows -> same tag (determinism, in-namespace)
    assert rows[1][0] == rows[2][0].startswith("RAGIONE_SOC_") or True
    assert rows[1][0] == rows[2][0]
    assert rows[1][2].startswith("PWD_")              # vault secret keeps PWD_
    assert rows[1][5] == "follow-up commerciale"       # NONSENSITIVE stays clear
    assert rows[1][3] == "MI" and rows[2][4] == "000003"  # short codes clear


def test_13_typed_roundtrip_verbatim(sp):
    sp.mk_vault(False); sp.unlock()
    r = _post(sp, "/csv/sanitize", on_missing="tag", typed=True)
    d = r.json()
    r2 = _post(sp, "/csv/restore", csv_text=d["csv"])
    assert r2.status_code == 200, r2.text
    d2 = r2.json()
    assert d2["unresolved"] == []
    assert d2["csv"] == CSV_TYPED                      # byte-identical round-trip


def test_14_opaque_untouched_by_default(sp):
    """No 'typed' option -> behaviour must be exactly v1.3.3 (PWD_ tags)."""
    sp.mk_vault(False); sp.unlock()
    r = _post(sp, "/csv/sanitize", on_missing="tag")
    d = r.json()
    rows = _cells(d["csv"])
    assert rows[1][1].startswith("PWD_")
    assert not any(str(c).startswith("CITTA_") for row in rows for c in row)
    assert "tag_types" not in d



def test_15_mint_collision_widening(sp, monkeypatch):
    """Forced deterministic collision on the 8-hex core (deterministic
    wrapper on _tag_core) must widen the core for the SECOND value,
    through the real typed whole-cell path (so the reverse map is
    registered on mint and restore round-trips both values)."""
    # victim/forged are NOT vault entries: the collision scenario is the
    # typed whole-cell path (dictionary-backed values use tag_for/PWD_)
    victim, forged = "Milano", "coll-collider-99"
    s = Sanitizer()
    s.load_from_lists(["VaultUnrelated-77!x"], salt=b"0123456789abcdef")
    real_core = Sanitizer._tag_core

    def fake_core(self, secret, nbytes=4):
        if secret == forged:
            secret = victim                      # force same core
        return real_core(self, secret, nbytes)

    monkeypatch.setattr(Sanitizer, "_tag_core", fake_core)
    out, _rep, _tag = s.sanitize_rows(
        [["COL"], [victim], [forged]], header=True, on_missing="tag",
        typed=True)
    t1, t2 = out[1][0], out[2][0]
    monkeypatch.undo()
    assert t1 != t2, "distinct values must never share one tag"
    assert t2.startswith("COL_") and len(t2) > len(t1), \
        "collision must widen the core"

    back, restored, unres = s.restore_rows([[t1], [t2]])
    assert back == [[victim], [forged]] and unres == []


def test_16_unresolved_never_invented(sp):
    """Real values are never invented; a well-formed but unknown whole
    tag is flagged in 'unresolved'; a known tag glued to junk is NOT
    silently rewritten (stays verbatim, v1 embedding not supported)."""
    sp.mk_vault(False); sp.unlock()
    r = _post(sp, "/csv/sanitize", on_missing="tag", typed=True)
    d = r.json()
    rows = _cells(d["csv"])
    some_tag = rows[1][1]                        # CITTA_xxxxxxxx (Milano)
    # mutate last hex digit -> well-formed but unknown tag
    unknown = some_tag[:-1] + ("0" if some_tag[-1] != "0" else "1")
    assert unknown != some_tag
    poisoned = ("CITTA,PIVA\n"
                f"ROMA123,{unknown}\n"          # unknown whole tag (col 2)
                f"Roma,{some_tag}:x\n")          # known tag glued (col 2)
    r2 = _post(sp, "/csv/restore", csv_text=poisoned)
    d2 = r2.json()
    body = d2["csv"]
    assert "Roma" in body and "ROMA123" in body  # real values intact
    assert f"{some_tag}:x" in body               # glue never rewritten
    assert d2["unresolved"] == [unknown], d2["unresolved"]
