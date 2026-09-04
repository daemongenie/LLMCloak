# v1.5.9-hotfix regression tests: the no-leak residual scan must NOT
# fail-close on occurrences INSIDE our own minted tags (tag cores /
# family prefixes can contain strings that are themselves vault values
# when a CSV ingest populates the vault with 50k+ real-world cells).
# Any occurrence OUTSIDE tag-shaped spans stays fatal (fail-closed).
import hmac
import json
import re
from hashlib import sha256

import pytest

from core import Sanitizer

SALT = b"\x77" * 16


def _mk(values, prefix_map=None):
    s = Sanitizer(salt=SALT)
    s.load_from_lists(values)
    if prefix_map:
        s.set_value_prefix(prefix_map)
    return s


def test_tag_internal_prefix_collision_not_fatal():
    # Field repro A: value "Mario Rossi" is mapped to family "EMAIL_"
    # (column-derived), while "EMAIL" (5 chars) is itself a vault value:
    # the minted tag "EMAIL_<hex>" CONTAINS the value "EMAIL" -> the old
    # raw scan raised RuntimeError; the hotfix masks tag-shaped spans.
    s = _mk(["Mario Rossi", "EMAIL"], {"Mario Rossi": "EMAIL_"})
    out, n = s.sanitize("contatta Mario Rossi subito")
    assert n == 1 and "Mario Rossi" not in out
    assert re.search(r"EMAIL_[0-9a-f]{8}", out)


def test_tag_internal_core_collision_not_fatal():
    # Field repro B: a CSV cell that is an 8-hex string (numeric ID)
    # collides with the HMAC core of another minted tag: the old scan
    # saw a phantom residual inside the tag and fail-closed every
    # proxied request. Deterministic: we add the exact HMAC core of a
    # known value as a vault value.
    s = Sanitizer(salt=SALT)
    core = hmac.new(SALT, "ValUnica42".encode(), sha256).digest()[:4].hex()
    s.load_from_lists(["ValUnica42", core])
    s.set_value_prefix({"ValUnica42": "FAM_"})
    out, n = s.sanitize("rif ValUnica42 ok")
    assert n == 1 and "ValUnica42" not in out
    # the tag is present and the no-leak scan does not fatal on its core
    assert re.search(r"FAM_[0-9a-f]{8}", out)


def test_roundtrip_after_mask_change():
    s = _mk(["Mario Rossi", "EMAIL"], {"Mario Rossi": "EMAIL_"})
    t = json.dumps({"msg": "contatta Mario Rossi adesso"})
    out, n = s.sanitize(t)
    assert n == 1
    back, r, un = s.desanitize(out)
    assert json.loads(back)["msg"] == "contatta Mario Rossi adesso"
    assert r == 1 and un == []


def test_mask_rx_does_not_eat_occurrences_outside_tags():
    # scan-only semantics: a raw value sitting NEXT TO a tag (separated
    # by a space) must survive masking and stay fatal; a non-hex tail
    # after a tag must not be eaten either.
    s = _mk(["abcd1234"])
    fams = {s.TAG_PREFIX_TEST} if hasattr(s, "TAG_PREFIX_TEST") else {"FAM_"}
    from core import TAG_PREFIX
    fams.add(TAG_PREFIX)
    mrx = re.compile(
        "(?:" + "|".join(re.escape(f) for f in sorted(fams))
        + r")[0-9a-f]{8,24}")
    scan = mrx.sub(" ", "FAM_ab12cd34 abcd1234 FAM_ab12cd34zzz")
    assert "abcd1234" in scan          # outside a tag -> still scanned
    assert "zzz" in scan               # non-hex tail untouched
    assert "FAM_ab12cd34" not in scan  # tag-shaped spans are masked