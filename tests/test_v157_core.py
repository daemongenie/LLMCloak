#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""v1.5.7 core unit tests: column-aware minting + multi-family restore."""
import os, sys, tempfile, shutil

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
os.chdir(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import core
from core import Sanitizer

PASS = 0
def ok(name):
    global PASS; PASS += 1
    print(f"  [OK] {name}")

# ------------------------------------------------ T1: value2prefix minting
san = Sanitizer()
san.load_from_lists(["000001-MARIO ROSSI Barbieri SPA",
                     "MARIO BIANCHI SRL"])
san.set_value_prefix({"000001-MARIO ROSSI Barbieri SPA":
                      "R07_RAGIONE_SO_"})
out, n = san.sanitize("Fattura per 000001-MARIO ROSSI Barbieri SPA "
                      "e MARIO BIANCHI SRL")
assert n == 2, (n, out)
r07 = [t for t in out.split() if t.startswith("R07_RAGIONE_SO_")]
pwd = [t for t in out.split() if t.startswith("PWD_") and len(t) > 10]
assert len(r07) == 1, out
assert len(pwd) == 1, out
core_hex = r07[0].replace("R07_RAGIONE_SO_", "")
assert san.tag_core2secret[core_hex] == "000001-MARIO ROSSI Barbieri SPA"
ok("T1 chat-time mint uses the column prefix (value2prefix)")

# ------------------------------------------------ T2: multi-family desanitize
back, n, un = san.desanitize(out)
assert n == 2 and not un, (n, un)
assert back == ("Fattura per 000001-MARIO ROSSI Barbieri SPA "
                "e MARIO BIANCHI SRL"), back
ok("T2 auto-families desanitize restores both tags")

# explicit families param
out2, n2, _ = san._desanitize_one(out, prefix="PWD_")
assert n2 == 1
ok("T3 single-family still works (_desanitize_one)")

# ------------------------------------------- T4: sanitize_rows + colprefixes
san2 = Sanitizer()
san2.load_from_lists(["MARIO ROSSI", "IT60X0542811101000000123456"])
rows = [["id", "ragione_sociale", "iban"],
        ["1", "MARIO ROSSI", "IT60X0542811101000000123456"]]
out_rows, rep, tag = san2.sanitize_rows(
    rows, on_missing="tag", header=True, typed=False,
    column_prefixes={1: "R07_RAGIONE_SO_", 2: "IBAN_"})
# v1.5.7: exact vault hits use the column family and count as replaced
assert rep == 2 and out_rows[1][1].startswith("R07_RAGIONE_SO_"), (rep, out_rows)
assert out_rows[1][2].startswith("IBAN_"), out_rows
# whole-cell tagging of an UNKNOWN value also honours the column prefix
rows2 = [["id", "ragione_sociale"], ["2", "UNKNOWNSRL DI TEST"]]
out_rows2, rep2, tag2 = san2.sanitize_rows(
    rows2, on_missing="tag", header=True, typed=False,
    column_prefixes={1: "R07_RAGIONE_SO_"})
assert tag2 == 1 and out_rows2[1][1].startswith("R07_RAGIONE_SO_"), (rep2, tag2, out_rows2)
back2, nres2, unres2 = san2.desanitize(out_rows2[1][1])
assert nres2 == 1 and back2 == "UNKNOWNSRL DI TEST", (back2, nres2, unres2)
ok("T4 sanitize_rows colprefixes -> custom tags (exact + whole-cell)")

# typed mode: NONSENSITIVE col id stays, sensitive cols tagged
san3 = Sanitizer()
san3.load_from_lists(["MARIO ROSSI", "IT60X0542811101000000123456"])
rows3 = [["id", "ragione_sociale", "iban"],
         ["1", "MARIO ROSSI", "IT60X0542811101000000123456"]]
out3, rep3, tag3 = san3.sanitize_rows(
    rows3, on_missing="tag", header=True, typed=True,
    column_prefixes={1: "R07_RAGIONE_SO_"})
assert out3[1][1].startswith("R07_RAGIONE_SO_"), out3
# v1.5.7 semantics: a known secret in a column WITHOUT an explicit
# prefix override uses the default family (PWD_) in the exact pass;
# the header namespace (IBAN_) applies only to whole-cell mints.
assert out3[1][2].startswith("PWD_"), out3
assert out3[1][0] == "1", out3
ok("T5 typed mode: colprefixes override, other cols keep default family")

# restore_rows with families
back3, nres, unres = san3.restore_rows(out3, prefix="PWD_",
                                       families=["PWD_", "R07_RAGIONE_SO_",
                                                 "IBAN_"])
# 2 tagged cells restored (col0 "id" never tagged)
assert nres == 2 and not unres, (nres, back3, unres)
assert back3 == rows3, back3
ok("T6 restore_rows multi-family full round-trip")

# --------------------------------------------- T7: lock wipes value2prefix
san.set_value_prefix({"TEMP_VALUE_XY": "TEST_"})
assert san.value2prefix.get("TEMP_VALUE_XY") == "TEST_"
san.lock()
assert san.value2prefix == {}, san.value2prefix
ok("T7 lock() wipes the value->prefix index")

# ------------------------------------- T8: load_vault fires the reload hook
d = tempfile.mkdtemp(prefix="v157core_")
import dashboard as dash
salt = core.load_or_create_salt(d + "/s.salt")
key = core.derive_key("pw", salt)
dash.persist_vault(d + "/v.txt", ["SECRET-ALFA-ONE"], key, encrypt=True)
fired = []
san4 = Sanitizer()
san4._on_reload_cb = lambda mk: fired.append(mk)
san4.load_vault(d + "/v.txt", master_key=key, enforce_perms=False, salt=salt)
assert fired == [key], fired
san4.lock()
# locked vault: sanitize fails safe (raise, never leak)
try:
    san4.sanitize("SECRET-ALFA-ONE")
    raise SystemExit("FAIL: sanitize on locked vault did not raise")
except core.VaultNotLoaded:
    pass
# reload after lock fires the hook again (rebuild after unlock)
san4.load_vault(d + "/v.txt", master_key=key, enforce_perms=False, salt=salt)
assert len(fired) == 2, fired
ok("T8 load_vault fires _on_reload_cb(master_key), also after lock")

# ---------------------------- T9: StreamDesanitizer multi-family chunked
san5 = Sanitizer()
san5.load_from_lists(["ROBERTO VERDI SPA"])
san5.set_value_prefix({"ROBERTO VERDI SPA": "R07_RAGIONE_SO_"})
txt = "Spett.le ROBERTO VERDI SPA conferma l'ordine"
tagged, n5 = san5.sanitize(txt)
assert n5 == 1 and "R07_RAGIONE_SO_" in tagged, tagged
sd = core.StreamDesanitizer(san5)
acc = ""
for i in range(0, len(tagged), 3):     # 3-char chunks split the tag
    acc += sd.feed(tagged[i:i + 3])
acc += sd.flush()
assert acc == txt, acc
ok("T9 SSE multi-family restore with 3-char chunks")

# partial split at every offset (robustness)
for off in range(1, min(6, len(tagged))):
    sd2 = core.StreamDesanitizer(san5)
    acc2 = sd2.feed(tagged[:off]) + sd2.feed(tagged[off:]) + sd2.flush()
    assert acc2 == txt, (off, acc2)
ok("T10 SSE split at every offset 1..5 restored")

print(f"\nALL {PASS} CORE TESTS PASSED")
