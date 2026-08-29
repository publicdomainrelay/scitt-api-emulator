# Copyright (c) SCITT Authors
# Licensed under the MIT License.
"""
Signed Statement structure, against the CDDL of Figure 3 of RFC 9943.
"""
import cbor2
import pytest

from scitt_emulator import create_statement
from scitt_emulator.rfc9162_sha256 import (
    COSE_HEADER_ALG,
    COSE_HEADER_CWT_CLAIMS,
    COSE_HEADER_KID,
    COSE_SIGN1_TAG,
    CWT_CLAIM_ISS,
    CWT_CLAIM_SUB,
)

COSE_HEADER_CONTENT_TYPE = 3
COSE_HEADER_RECEIPTS = 394
COSE_HEADER_REG_INFO = 393


@pytest.fixture
def statement(tmp_path):
    claim_path = tmp_path / "claim.cose"
    create_statement.create_claim(
        claim_path,
        "did:web:example.org",
        "vendor.product.example",
        "application/json",
        b'{"foo": "bar"}',
    )
    return cbor2.loads(claim_path.read_bytes())


def test_statement_is_a_tagged_cose_sign1(statement):
    assert statement.tag == COSE_SIGN1_TAG
    assert len(statement.value) == 4


def test_protected_header_matches_figure_3(statement):
    """
    Figure 3 of RFC 9943:

        Protected_Header = {
          &(CWT_Claims: 15) => CWT_Claims
          ? &(alg: 1) => int
          ? &(content_type: 3) => tstr / uint
          ? &(kid: 4) => bstr
          ...
        }
    """
    phdr = cbor2.loads(statement.value[0])

    assert isinstance(phdr[COSE_HEADER_CWT_CLAIMS], dict)
    assert isinstance(phdr[COSE_HEADER_ALG], int)
    assert isinstance(phdr[COSE_HEADER_CONTENT_TYPE], str)
    assert isinstance(phdr[COSE_HEADER_KID], bytes)


def test_cwt_claims_carries_issuer_and_subject(statement):
    """
    Section 6 of RFC 9943: "The CWT Claims value MUST include the Issuer Claim
    (Claim label 1) and the Subject Claim (Claim label 2)."
    """
    cwt_claims = cbor2.loads(statement.value[0])[COSE_HEADER_CWT_CLAIMS]

    assert cwt_claims[CWT_CLAIM_ISS] == "did:web:example.org"
    assert cwt_claims[CWT_CLAIM_SUB] == "vendor.product.example"


def test_receipts_label_is_absent_when_there_are_none(statement):
    """
    Figure 3 of RFC 9943 types label 394 as [+ bstr .cbor Receipt]. `nil` is
    not that, so the label is omitted rather than set to nil when the
    statement carries no Receipts. A Signed Statement with Receipts is a
    Transparent Statement (Figure 7).
    """
    unprotected = statement.value[1]

    assert COSE_HEADER_RECEIPTS not in unprotected
    assert unprotected == {}


def test_registration_policy_info_label_is_not_emitted(statement):
    """
    Label 393 (Reg_Info) came from an earlier architecture draft and appears
    nowhere in RFC 9943 or draft-ietf-scitt-scrapi-11.
    """
    assert COSE_HEADER_REG_INFO not in cbor2.loads(statement.value[0])


def test_statement_urn_is_unpadded_base64url(tmp_path):
    """
    Section 2 of RFC 7515 base64url omits all trailing "=".
    """
    urn = create_statement.create_claim(
        tmp_path / "claim.cose",
        "did:web:example.org",
        "subject",
        "application/json",
        b'{"foo": "bar"}',
    )

    assert urn.startswith("urn:ietf:params:scitt:signed-statement:sha256:base64url:")
    assert "=" not in urn
