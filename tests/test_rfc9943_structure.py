"""RFC 9943 Figure 3 structural conformance for statements this emulator creates.

These assert the SHAPE the spec fixes, not byte-equality with any other
implementation. Two conformant implementations legitimately differ on `alg`
(any registered COSE algorithm) and on `kid` (RFC 9943 types it `bstr` with no
constraint on content), so a byte-diff across implementations reports noise.
What must NOT differ is the field set and where each field lives.

Written after diffing this emulator's create_claim against the EMILIA
scitt-statement-identity-v0.1 fixture (issue #13). Both matched on every
invariant below; the only differences were the two free choices named above.
"""
import pathlib
import tempfile

import cbor2
import pytest

from scitt_emulator.create_statement import create_claim

ISSUER = "https://issuer.example/scitt"
SUBJECT = "urn:example:scitt-identity-p256:1"
CONTENT_TYPE = "application/example+json"
PAYLOAD = b'{"claim":"one signing input, two valid envelopes","sequence":1}'

ALG, CONTENT_TYPE_LABEL, KID, CWT_CLAIMS, RECEIPTS = 1, 3, 4, 15, 394


@pytest.fixture(scope="module")
def statement():
    with tempfile.TemporaryDirectory() as d:
        path = pathlib.Path(d) / "statement.cose"
        create_claim(
            path,
            issuer=ISSUER,
            subject=SUBJECT,
            content_type=CONTENT_TYPE,
            payload=PAYLOAD,
        )
        raw = path.read_bytes()
    obj = cbor2.loads(raw)
    return obj


def _parts(statement):
    arr = statement.value if hasattr(statement, "value") else statement
    return cbor2.loads(arr[0]), arr[1], arr[2], arr[3]


def test_is_a_tagged_cose_sign1(statement):
    # RFC 9052: COSE_Sign1 carries tag 18.
    assert getattr(statement, "tag", None) == 18


def test_protected_header_field_set_is_exactly_the_four(statement):
    protected, _, _, _ = _parts(statement)
    assert set(protected) == {ALG, CONTENT_TYPE_LABEL, KID, CWT_CLAIMS}


def test_cwt_claims_are_in_the_protected_header(statement):
    # RFC 9597 registers label 15; RFC 9943 Figure 3 requires it PROTECTED.
    protected, unprotected, _, _ = _parts(statement)
    assert CWT_CLAIMS in protected
    assert CWT_CLAIMS not in (unprotected or {})


def test_cwt_claims_are_a_plain_map_not_a_nested_cwt(statement):
    # Figure 5 of RFC 9943 shows a CWT Claims Set — a plain map of claim key to
    # value, protected by the OUTER COSE_Sign1. Not a separately signed CWT.
    protected, _, _, _ = _parts(statement)
    claims = protected[CWT_CLAIMS]
    assert isinstance(claims, dict)
    assert claims[1] == ISSUER   # iss
    assert claims[2] == SUBJECT  # sub


def test_receipts_label_is_omitted_not_nil_when_absent(statement):
    # Figure 3 types 394 as [+ bstr .cbor Receipt]. With no Receipts the label
    # must be ABSENT. A nil there is a different structure and would make a
    # Signed Statement look like a malformed Transparent Statement.
    protected, unprotected, _, _ = _parts(statement)
    assert RECEIPTS not in protected
    assert RECEIPTS not in (unprotected or {})


def test_payload_is_carried_verbatim(statement):
    _, _, payload, _ = _parts(statement)
    assert payload == PAYLOAD


def test_alg_is_a_registered_cose_algorithm(statement):
    # Deliberately does NOT pin a curve. create_claim generates its own key when
    # no PEM is supplied and currently defaults to ES384 (-35), while the EMILIA
    # fixture is ES256 (-7). Both conform. A test that pinned one would fail on
    # a default change rather than on a conformance break.
    protected, _, _, _ = _parts(statement)
    assert isinstance(protected[ALG], int)
    assert protected[ALG] < 0  # ECDSA/EdDSA identifiers are negative


def test_kid_is_a_bytestring(statement):
    # RFC 9943 types kid as bstr and constrains nothing else. This emulator uses
    # a JWK thumbprint; the EMILIA fixture uses an ASCII label. Both conform.
    protected, _, _, _ = _parts(statement)
    assert isinstance(protected[KID], bytes)
    assert len(protected[KID]) > 0
