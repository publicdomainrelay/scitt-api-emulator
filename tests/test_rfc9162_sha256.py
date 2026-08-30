# Copyright (c) SCITT Authors
# Licensed under the MIT License.
"""
Tests for the RFC9162_SHA256 Transparency Service, whose Receipts are COSE
Sign1 messages as described in Section 7 of RFC 9943.
"""
import pathlib

import cbor2
import httpx
import pytest

from scitt_emulator import create_statement
from scitt_emulator.cose_keys import COSE_KEY_KID
from scitt_emulator.rfc9162_sha256 import (
    COSE_ALG_ES256,
    COSE_HEADER_ALG,
    COSE_HEADER_CWT_CLAIMS,
    COSE_HEADER_KID,
    COSE_HEADER_PROOFS,
    COSE_HEADER_VDS,
    COSE_SIGN1_TAG,
    CWT_CLAIM_ISS,
    CWT_CLAIM_SUB,
    PROOF_TYPE_INCLUSION,
    VDS_RFC9162_SHA256,
    ReceiptInvalidError,
    RFC9162SHA256SCITTServiceEmulator,
    decode_inclusion_proof,
    inclusion_proof_path,
    leaf_hash,
    merkle_tree_hash,
    root_from_inclusion_proof,
)

from tests.test_cli import Service


# The sub used in test Signed Statements.
SUBJECT = "vendor.product.example"


@pytest.fixture
def service(tmp_path):
    with Service(
        {
            "workspace": tmp_path / "workspace",
            "error_rate": 0,
            "use_lro": False,
        }
    ) as service:
        yield service


def make_statement(tmp_path, name="claim.cose", subject=SUBJECT):
    claim_path = tmp_path / name
    create_statement.create_claim(
        claim_path,
        "did:web:example.org",
        subject,
        "application/json",
        b'{"foo": "bar"}',
    )
    return claim_path


def register(service, claim: bytes):
    response = httpx.post(
        f"{service.url}/entries",
        content=claim,
        headers={"Content-Type": "application/cose", "Accept": "application/cose"},
    )
    assert response.status_code == 201, response.content
    return response


# Merkle tree, RFC 9162 Section 2.1


@pytest.mark.parametrize("size", range(1, 17))
def test_every_leaf_proves_inclusion(size):
    """
    RFC 9162 Section 2.1.3.2: an inclusion proof reconstructs the Merkle tree
    root from the leaf alone, for every leaf of every tree size.
    """
    leaves = [leaf_hash(f"leaf-{i}".encode()) for i in range(size)]
    root = merkle_tree_hash(leaves)

    for index in range(size):
        path = inclusion_proof_path(leaves, index)
        assert root_from_inclusion_proof(size, index, leaves[index], path) == root


def test_inclusion_proof_rejects_the_wrong_leaf():
    leaves = [leaf_hash(f"leaf-{i}".encode()) for i in range(8)]
    path = inclusion_proof_path(leaves, 3)

    assert root_from_inclusion_proof(8, 3, leaves[4], path) != merkle_tree_hash(leaves)


def test_inclusion_proof_rejects_a_truncated_path():
    leaves = [leaf_hash(f"leaf-{i}".encode()) for i in range(8)]
    path = inclusion_proof_path(leaves, 3)

    with pytest.raises(ReceiptInvalidError):
        root_from_inclusion_proof(8, 3, leaves[3], path[:-1])


def test_inclusion_proof_rejects_an_out_of_range_index():
    with pytest.raises(ReceiptInvalidError):
        root_from_inclusion_proof(4, 4, leaf_hash(b"x"), [])


# Receipt structure, RFC 9943 Figures 9 to 11


def test_receipt_is_a_cose_sign1_with_detached_payload(service, tmp_path):
    """
    Figure 9 of RFC 9943: a Receipt is a tagged COSE_Sign1 whose payload is
    detached; RFC 9942 makes that payload the Verifiable Data Structure root.
    """
    receipt = register(service, make_statement(tmp_path).read_bytes()).content

    outer = cbor2.loads(receipt)
    assert isinstance(outer, cbor2.CBORTag)
    assert outer.tag == COSE_SIGN1_TAG
    protected, unprotected, payload, signature = outer.value
    assert payload is None
    assert isinstance(signature, bytes)
    # Section 8.1 of RFC 9053: ES256 signatures are r || s.
    assert len(signature) == 64


def test_receipt_protected_header(service, tmp_path):
    """
    Figure 10 of RFC 9943: the Receipt's protected header carries the
    algorithm, the key identifier, the Verifiable Data Structure, and the CWT
    Claims.
    """
    receipt = register(service, make_statement(tmp_path).read_bytes()).content

    protected = cbor2.loads(cbor2.loads(receipt).value[0])

    assert protected[COSE_HEADER_ALG] == COSE_ALG_ES256
    # Per the "COSE Verifiable Data Structure Algorithms" registry of RFC 9942,
    # RFC9162_SHA256 is value 1.
    assert protected[COSE_HEADER_VDS] == VDS_RFC9162_SHA256

    cwt_claims = protected[COSE_HEADER_CWT_CLAIMS]
    assert isinstance(cwt_claims, dict)
    assert isinstance(cwt_claims[CWT_CLAIM_ISS], str)
    # The Receipt repeats the Signed Statement's subject.
    assert cwt_claims[CWT_CLAIM_SUB] == SUBJECT


def test_receipt_kid_resolves_from_the_key_discovery_resource(service, tmp_path):
    """
    Section 2.2 of draft-ietf-scitt-scrapi-11: the kid in a Receipt resolves a
    single public key from /.well-known/scitt-keys/{kid_value}.
    """
    receipt = register(service, make_statement(tmp_path).read_bytes()).content
    kid = cbor2.loads(cbor2.loads(receipt).value[0])[COSE_HEADER_KID]

    from scitt_emulator.cose_keys import base64url_encode

    response = httpx.get(f"{service.url}/.well-known/scitt-keys/{base64url_encode(kid)}")

    assert response.status_code == 200
    assert cbor2.loads(response.content)[COSE_KEY_KID] == kid


def test_receipt_unprotected_header_carries_an_inclusion_proof(service, tmp_path):
    """
    Figure 9 of RFC 9943: the Receipt's unprotected header contains Proofs
    (396), with inclusion proofs at label -1, each a bstr .cbor.

    Figure 11: an RFC9162_SHA256 inclusion proof is
    [tree size, leaf index, [intermediate hashes]].
    """
    claim = make_statement(tmp_path).read_bytes()
    receipt = register(service, claim).content

    unprotected = cbor2.loads(receipt).value[1]
    proofs = unprotected[COSE_HEADER_PROOFS]
    inclusion_proofs = proofs[PROOF_TYPE_INCLUSION]
    assert len(inclusion_proofs) == 1
    assert isinstance(inclusion_proofs[0], bytes)

    tree_size, leaf_index, path = decode_inclusion_proof(inclusion_proofs[0])
    assert tree_size == 1
    assert leaf_index == 0
    assert path == []

    # The proof is over the Signed Statement as registered.
    assert root_from_inclusion_proof(
        tree_size, leaf_index, leaf_hash(claim), path
    ) == merkle_tree_hash([leaf_hash(claim)])


def test_receipts_prove_inclusion_as_the_tree_grows(service, tmp_path):
    """
    Each Receipt proves inclusion in the tree as it stood at registration, so
    the tree size and leaf index advance with each registration.
    """
    claims = [
        make_statement(tmp_path, name=f"claim-{i}.cose", subject=f"subject-{i}").read_bytes()
        for i in range(5)
    ]

    for expected_index, claim in enumerate(claims):
        receipt = register(service, claim).content
        inclusion_proofs = cbor2.loads(receipt).value[1][COSE_HEADER_PROOFS][
            PROOF_TYPE_INCLUSION
        ]
        tree_size, leaf_index, path = decode_inclusion_proof(inclusion_proofs[0])

        assert leaf_index == expected_index
        assert tree_size == expected_index + 1
        # The root the proof reconstructs is the root over everything so far.
        assert root_from_inclusion_proof(
            tree_size, leaf_index, leaf_hash(claim), path
        ) == merkle_tree_hash([leaf_hash(c) for c in claims[: expected_index + 1]])


# Verification, RFC 9943 Section 7.1


def verifying_service(service):
    return RFC9162SHA256SCITTServiceEmulator(
        service_parameters_path=service.service_parameters_path
    )


def test_verify_receipt(service, tmp_path):
    claim_path = make_statement(tmp_path)
    receipt = register(service, claim_path.read_bytes()).content
    receipt_path = tmp_path / "claim.receipt.cbor"
    receipt_path.write_bytes(receipt)

    verifying_service(service).verify_receipt(claim_path, receipt_path)


def test_verify_receipt_rejects_a_different_statement(service, tmp_path):
    """
    A Receipt proves inclusion of the Signed Statement it was issued for, so
    verifying it against a different one must fail.
    """
    claim_path = make_statement(tmp_path)
    receipt_path = tmp_path / "claim.receipt.cbor"
    receipt_path.write_bytes(register(service, claim_path.read_bytes()).content)

    other_path = make_statement(tmp_path, name="other.cose", subject="other")

    with pytest.raises(ReceiptInvalidError):
        verifying_service(service).verify_receipt(other_path, receipt_path)


def test_verify_receipt_rejects_a_tampered_signature(service, tmp_path):
    claim_path = make_statement(tmp_path)
    receipt = cbor2.loads(register(service, claim_path.read_bytes()).content)
    signature = bytearray(receipt.value[3])
    signature[-1] ^= 0xFF
    receipt.value[3] = bytes(signature)

    receipt_path = tmp_path / "claim.receipt.cbor"
    receipt_path.write_bytes(cbor2.dumps(receipt))

    with pytest.raises(ReceiptInvalidError):
        verifying_service(service).verify_receipt(claim_path, receipt_path)


def test_verify_receipt_rejects_an_unknown_verifiable_data_structure(service, tmp_path):
    claim_path = make_statement(tmp_path)
    receipt = cbor2.loads(register(service, claim_path.read_bytes()).content)
    protected = cbor2.loads(receipt.value[0])
    protected[COSE_HEADER_VDS] = 2
    receipt.value[0] = cbor2.dumps(protected, canonical=True)

    receipt_path = tmp_path / "claim.receipt.cbor"
    receipt_path.write_bytes(cbor2.dumps(receipt))

    with pytest.raises(ReceiptInvalidError, match="verifiable data structure"):
        verifying_service(service).verify_receipt(claim_path, receipt_path)


def test_receipt_cwt_claims_always_carries_issuer_and_subject(service, tmp_path):
    """
    Section 6 of RFC 9943: "The CWT Claims value MUST include the Issuer Claim
    (Claim label 1) and the Subject Claim (Claim label 2)." This holds for a
    Receipt's protected header as much as a Signed Statement's.
    """
    receipt = register(service, make_statement(tmp_path).read_bytes()).content

    cwt_claims = cbor2.loads(cbor2.loads(receipt).value[0])[COSE_HEADER_CWT_CLAIMS]

    assert isinstance(cwt_claims[CWT_CLAIM_ISS], str)
    assert isinstance(cwt_claims[CWT_CLAIM_SUB], str)


def test_statement_without_subject_is_rejected(service, tmp_path):
    """
    A Signed Statement whose CWT Claims lack iss or sub cannot yield a
    conformant Receipt, so it is not registered.
    """
    for cwt_claims in ({}, {CWT_CLAIM_ISS: "iss"}, {CWT_CLAIM_SUB: "sub"}):
        protected = cbor2.dumps(
            {COSE_HEADER_ALG: COSE_ALG_ES256, COSE_HEADER_CWT_CLAIMS: cwt_claims}
        )
        claim = cbor2.dumps(
            cbor2.CBORTag(COSE_SIGN1_TAG, [protected, {}, b"payload", b"signature"])
        )

        response = httpx.post(
            f"{service.url}/entries",
            content=claim,
            headers={"Content-Type": "application/cose"},
        )

        assert response.status_code == 400, cwt_claims
